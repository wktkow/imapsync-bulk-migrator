from __future__ import annotations

import argparse
import json
import logging
import math
import socket
import os
import signal
import threading
from pathlib import Path
from typing import List, Optional, Tuple, Dict

from .audit import audit_export
from .da_client import DirectAdminClient
from .da_ensure import ensure_accounts_exist_directadmin
from .executor import parallel_process_accounts
from .imap_ops import export_account, import_account
from .imapsync_cli import run_imapsync_justconnect
from .models import Account, Config, ProviderMigrationConfig, load_config_file
from .provider_ops import (
    provider_audit_all,
    provider_export_all,
    provider_import_all,
    provider_preflight,
    provider_test_accounts,
    provider_validate_all,
)
from .utils import check_environment, sanitize_for_path
from .utils import check_free_space_for_path


def _read_required_secret_file(path: str, *, label: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{label} is empty: {path}")
    return value


def _resolve_da_password(args: argparse.Namespace) -> str:
    sources = [
        name
        for name, value in (
            ("--da-password", getattr(args, "da_password", None)),
            ("--da-password-file", getattr(args, "da_password_file", None)),
            ("--da-password-env", getattr(args, "da_password_env", None)),
        )
        if value
    ]
    if not sources:
        raise ValueError("DirectAdmin auto-provisioning requires one of: --da-password-file, --da-password-env, --da-password")
    if len(sources) > 1:
        raise ValueError("DirectAdmin password must be provided by only one source: --da-password-file, --da-password-env, or --da-password")
    if getattr(args, "da_password_file", None):
        return _read_required_secret_file(str(args.da_password_file), label="DirectAdmin password file")
    if getattr(args, "da_password_env", None):
        env_name = str(args.da_password_env)
        value = os.environ.get(env_name, "").strip()
        if not value:
            raise ValueError(f"DirectAdmin password environment variable is unset or empty: {env_name}")
        return value
    logging.warning("--da-password exposes the DirectAdmin secret via shell history/process arguments; prefer --da-password-file or --da-password-env")
    return str(args.da_password)


def _write_secure_json_file(path: Path, payload: Dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except Exception:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise


def setup_logging(log_directory: Path) -> Path:
    """Initialize root logger with file + stdout handlers and return log path."""
    log_directory.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    import logging
    import sys

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    log_file = log_directory / f"run-{timestamp}.log"

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.info("Logging initialized. File: %s", str(log_file))
    return log_file


def test_accounts(config: Config, max_workers: int) -> None:
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    import concurrent.futures
    import queue
    errors: queue.Queue[str] = queue.Queue()
    from .imap_ops import imap_connection

    def worker(acc: Account) -> None:
        try:
            # Properly open and logout via the context manager
            with imap_connection(config.server, acc):
                pass
            ok, out = run_imapsync_justconnect(
                host=config.server.host,
                port=config.server.port,
                ssl_enabled=config.server.ssl,
                starttls=config.server.starttls,
                user=acc.email,
                password=acc.password,
                timeout_sec=30,
            )
            if not ok:
                raise RuntimeError(f"imapsync justconnect failed for {acc.email}:\n{out}")
            logging.info("[test] %s: OK", acc.email)
        except Exception as exc:
            logging.error("[test] %s: FAILED: %s", acc.email, exc)
            errors.put(f"{acc.email}: {exc}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="test") as ex:
        list(ex.map(worker, config.accounts))

    if not errors.empty():
        reason_lines: List[str] = []
        while not errors.empty():
            try:
                reason_lines.append(errors.get_nowait())
            except Exception:
                break
        raise RuntimeError(f"Connectivity test failed for some accounts:\n" + "\n".join(reason_lines))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk export/import/validate IMAP mailboxes with legacy and provider-aware workflows.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", required=True, choices=["export", "import", "test", "validate", "audit", "preflight"], help="Operation mode")
    parser.add_argument("--config", required=False, help="Path to JSON config file with server and accounts")
    parser.add_argument("--output-dir", default=str(Path.cwd() / "exported"), help="Directory to write exported data")
    parser.add_argument("--input-dir", default=str(Path.cwd() / "exported"), help="Directory to read exported data for import/validate")
    parser.add_argument("--max-workers", type=int, default=max(4, (os.cpu_count() or 4)), help="Parallel worker threads for accounts")
    parser.add_argument("--ignore-errors", action="store_true", help="Continue other accounts on errors")
    parser.add_argument("--log-dir", default=str(Path.cwd() / "logs"), help="Directory to store log files")
    parser.add_argument("--min-free-gb", type=float, default=1.0, help="Fail-fast if free disk space is lower")
    parser.add_argument("--resync-missing", action="store_true", help="Deprecated; validation reports missing messages without automatic APPEND replay")
    parser.add_argument("--no-audit-after-export", action="store_true", help="Do not run audit automatically after export")
    parser.add_argument("--no-connectivity-test", action="store_true", help="Skip preflight connectivity tests")
    parser.add_argument("--audit-offline", action="store_true", help="Do not contact IMAP server during audit; perform local-only checks")
    parser.add_argument("--imap-timeout", type=float, default=60.0, help="Default IMAP socket timeout in seconds")

    parser.add_argument("--auto-provision-da", action="store_true", help="In import mode, if accounts don't exist on the panel, auto-create them via DirectAdmin API before tests and import")
    parser.add_argument("--reset", action="store_true", help="Import mode only: delete and recreate each mailbox on the panel before importing")
    parser.add_argument("--da-url", required=False, help="DirectAdmin base URL, e.g. https://panel.example.com:2222")
    parser.add_argument("--da-username", required=False, help="DirectAdmin API username")
    parser.add_argument("--da-password", required=False, help="DirectAdmin API password or login key; insecure because process args can expose it")
    parser.add_argument("--da-password-file", required=False, help="Path to a file containing the DirectAdmin API password or login key")
    parser.add_argument("--da-password-env", required=False, help="Environment variable containing the DirectAdmin API password or login key")
    parser.add_argument("--da-no-verify-ssl", action="store_true", help="Disable TLS certificate verification for DirectAdmin API")
    parser.add_argument("--da-dry-run", action="store_true", help="Show what would be created without making changes")
    parser.add_argument("--da-quota-mb", type=int, default=0, help="New mailbox quota in MiB (0 = unlimited)")

    args = parser.parse_args(argv)

    log_file = setup_logging(Path(args.log_dir))
    logging.info("Starting imapsync-bulk-migrator | mode=%s", args.mode)

    if int(args.max_workers) < 1:
        logging.error("--max-workers must be >= 1")
        return 2
    imap_timeout = float(args.imap_timeout)
    if not math.isfinite(imap_timeout) or imap_timeout <= 0:
        logging.error("--imap-timeout must be a positive finite number of seconds")
        return 2
    min_free_gb = float(args.min_free_gb)
    if not math.isfinite(min_free_gb) or min_free_gb < 0:
        logging.error("--min-free-gb must be a non-negative finite number")
        return 2
    if args.mode == "test" and bool(getattr(args, "no_connectivity_test", False)):
        logging.error("--no-connectivity-test cannot be used with --mode test")
        return 2

    # Apply default IMAP socket timeout early so all imaplib ops inherit it
    try:
        socket.setdefaulttimeout(imap_timeout)
        logging.info("IMAP default socket timeout set to %.1f sec", imap_timeout)
    except Exception as _exc:
        logging.warning("Failed to set default socket timeout: %s", _exc)

    try:
        check_environment(min_free_gb=min_free_gb)
    except Exception as exc:
        logging.error("Environment/dependency check failed: %s", exc)
        return 2

    default_config = {
        "export": "export.pass.config.json",
        "import": "import.pass.config.json",
        "test": "export.pass.config.json",
        "validate": "import.pass.config.json",
        "audit": "export.pass.config.json",
        "preflight": "migration.config.json",
    }[args.mode]
    config_path = Path(args.config or default_config)
    if not config_path.exists():
        logging.error("Config not found: %s", str(config_path))
        return 2
    try:
        config = load_config_file(config_path)
    except Exception as exc:
        logging.error("Invalid config: %s", exc)
        return 2
    is_provider_config = isinstance(config, ProviderMigrationConfig)

    try:
        if (
            not is_provider_config
            and args.mode in {"export", "import", "test", "validate"}
            and not bool(getattr(args, "no_connectivity_test", False))
        ):
            from .utils import ensure_imapsync_available
            ensure_imapsync_available()
    except Exception as exc:
        logging.error("Environment/dependency check failed: %s", exc)
        return 2

    da_client: Optional[DirectAdminClient] = None
    da_password: Optional[str] = None
    if is_provider_config and (bool(getattr(args, "auto_provision_da", False)) or bool(getattr(args, "reset", False))):
        logging.error("DirectAdmin auto-provisioning is not supported for provider source/target configs")
        return 2
    if (not is_provider_config) and args.mode == "import" and (bool(getattr(args, "auto_provision_da", False)) or bool(getattr(args, "reset", False))):
        missing = [n for n in ("da_url", "da_username") if not getattr(args, n)]
        if missing:
            logging.error("DirectAdmin auto-provisioning requires: --da-url, --da-username, and a password source (missing: %s)", ", ".join(missing))
            return 2
        try:
            da_password = _resolve_da_password(args)
            logging.info("[da] Auto-provisioning missing mailboxes before import...")
            da_client = DirectAdminClient(
                base_url=str(args.da_url),
                username=str(args.da_username),
                password=da_password,
                verify_ssl=not bool(args.da_no_verify_ssl),
            )
            if bool(getattr(args, "reset", False)):
                from .da_ensure import reset_accounts_directadmin
                logging.info("[da] Reset requested: deleting and recreating mailboxes before import...")
                reset_accounts_directadmin(
                    config,
                    da_client,
                    dry_run=bool(args.da_dry_run),
                    ignore_errors=bool(args.ignore_errors),
                    quota_mb=int(args.da_quota_mb),
                )
            else:
                ensure_accounts_exist_directadmin(
                    config,
                    da_client,
                    dry_run=bool(args.da_dry_run),
                    ignore_errors=bool(args.ignore_errors),
                    quota_mb=int(args.da_quota_mb),
                )
            logging.info("[da] Auto-provisioning step completed")
        except Exception as exc:
            logging.error("[da] Auto-provisioning failed: %s", exc)
            if not args.ignore_errors:
                return 3

    if args.mode in {"export", "import", "test", "validate"} and not bool(getattr(args, "no_connectivity_test", False)):
        try:
            if is_provider_config:
                if args.mode == "export":
                    roles = ("source",)
                elif args.mode in {"import", "validate"}:
                    roles = ("target",)
                else:
                    roles = ("source", "target")
                logging.info("Running provider connectivity tests (roles=%s) ...", ",".join(roles))
                provider_test_accounts(config, max_workers=int(args.max_workers), roles=roles)
            else:
                logging.info("Running connectivity tests (imaplib + imapsync --justconnect) ...")
                assert isinstance(config, Config)
                test_accounts(config, max_workers=int(args.max_workers))
            logging.info("Connectivity tests passed for all accounts")
        except Exception as exc:
            logging.error("Connectivity tests failed: %s", exc)
            return 3
    elif args.mode in {"export", "import", "test", "validate"}:
        logging.info("Skipping connectivity tests due to --no-connectivity-test")

    stop_event = threading.Event()

    def handle_sig(signum, _frame):
        logging.warning("Received signal %s, requesting stop...", signum)
        stop_event.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, handle_sig)
        signal.signal(signal.SIGTERM, handle_sig)

    try:
        if is_provider_config:
            assert isinstance(config, ProviderMigrationConfig)
            if args.mode == "preflight":
                ok, issues = provider_preflight(config, max_workers=int(args.max_workers))
                if ok:
                    logging.info("Provider preflight passed")
                    return 0
                logging.error("Provider preflight found %d issue(s):", len(issues))
                for issue in issues:
                    logging.error("[provider-preflight] %s", issue)
                return 4
            if args.mode == "export":
                out_root = Path(args.output_dir)
                out_root.mkdir(parents=True, exist_ok=True)
                check_free_space_for_path(out_root, min_free_gb)
                provider_export_all(
                    config,
                    out_root,
                    max_workers=int(args.max_workers),
                    ignore_errors=bool(args.ignore_errors),
                    stop_event=stop_event,
                )
                logging.info("Provider export finished. Data stored under: %s", out_root)
                if not bool(getattr(args, "no_audit_after_export", False)):
                    ok, issues = provider_audit_all(config, out_root, max_workers=int(args.max_workers))
                    if ok:
                        logging.info("Provider audit passed")
                    else:
                        logging.error("Provider audit found %d issue(s):", len(issues))
                        for issue in issues:
                            logging.error("[provider-audit] %s", issue)
                        return 4
            elif args.mode == "import":
                in_root = Path(args.input_dir)
                if not in_root.exists():
                    logging.error("Input directory does not exist: %s", in_root)
                    return 2
                check_free_space_for_path(in_root, min_free_gb)
                provider_import_all(
                    config,
                    in_root,
                    max_workers=int(args.max_workers),
                    ignore_errors=bool(args.ignore_errors),
                    stop_event=stop_event,
                )
                logging.info("Provider import finished into server %s", config.target.host)
            elif args.mode == "test":
                logging.info("Provider test completed successfully.")
            elif args.mode == "validate":
                if bool(getattr(args, "resync_missing", False)):
                    logging.warning("--resync-missing is disabled for provider configs; exact validation reports missing identities instead")
                in_root = Path(args.input_dir)
                if not in_root.exists():
                    logging.error("Input directory does not exist: %s", in_root)
                    return 2
                check_free_space_for_path(in_root, min_free_gb)
                ok, issues = provider_validate_all(config, in_root, max_workers=int(args.max_workers))
                if ok:
                    logging.info("Provider validation successful.")
                else:
                    logging.warning("Provider validation found %d issue(s):", len(issues))
                    for issue in issues:
                        logging.warning("[provider-validate] %s", issue)
                    return 4
            elif args.mode == "audit":
                in_root = Path(args.input_dir)
                if not in_root.exists():
                    logging.error("Input directory does not exist: %s", in_root)
                    return 2
                check_free_space_for_path(in_root, min_free_gb)
                ok, issues = provider_audit_all(config, in_root, max_workers=int(args.max_workers))
                if ok:
                    logging.info("Provider audit passed")
                    return 0
                logging.error("Provider audit found %d issue(s):", len(issues))
                for issue in issues:
                    logging.error("[provider-audit] %s", issue)
                return 4
            else:
                logging.error("Unknown provider mode: %s", args.mode)
                return 2
        elif args.mode == "preflight":
            logging.error("--mode preflight requires a provider source/target config")
            return 2
        elif args.mode == "export":
            assert isinstance(config, Config)
            out_root = Path(args.output_dir)
            out_root.mkdir(parents=True, exist_ok=True)
            # Ensure destination filesystem has enough free space
            check_free_space_for_path(out_root, min_free_gb)
            try:
                payload_path = config_path.parent / "import.pass.config.json"
                if not payload_path.exists():
                    _write_secure_json_file(payload_path, {
                        "server": {
                            "host": "CHANGE_ME.example.com",
                            "port": 993,
                            "ssl": True,
                            "starttls": False,
                        },
                        "accounts": [{"email": a.email, "password": a.password} for a in config.accounts],
                    })
                    logging.warning("Generated import config TEMPLATE at: %s — you MUST edit server.host before importing!", payload_path)
            except Exception as exc:
                logging.warning("Failed to generate import config template: %s", exc)

            def do_export(acc: Account) -> None:
                if stop_event.is_set():
                    return
                export_account(acc, config.server, out_root, ignore_errors=bool(args.ignore_errors), stop_event=stop_event)

            parallel_process_accounts("export", do_export, config.accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            logging.info("Export finished. Data stored under: %s", out_root)

            if not bool(getattr(args, "no_audit_after_export", False)):
                try:
                    logging.info("Running export audit (%s)...", "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                    ok, audit_issues = audit_export(out_root, config, int(args.max_workers), check_remote=not bool(getattr(args, "audit_offline", False)))
                    if ok:
                        logging.info("Audit passed: exported data looks consistent for all accounts")
                    else:
                        logging.error("Audit found %d issue(s):", len(audit_issues))
                        for line in audit_issues:
                            logging.error("[audit] %s", line)
                        return 4
                except Exception as exc:
                    logging.error("Audit failed to complete: %s", exc)
                    return 4
        elif args.mode == "import":
            assert isinstance(config, Config)
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            check_free_space_for_path(in_root, min_free_gb)

            def do_import(acc: Account) -> None:
                if stop_event.is_set():
                    return
                da_ctx = None
                if bool(getattr(args, "auto_provision_da", False)) and da_client is not None and not bool(getattr(args, "da_dry_run", False)):
                    da_ctx = (da_client, int(args.da_quota_mb))
                elif bool(getattr(args, "auto_provision_da", False)) and bool(getattr(args, "da_dry_run", False)):
                    logging.info("[da][dry-run] Lazy create-and-retry disabled for %s", acc.email)
                import_account(
                    acc,
                    config.server,
                    in_root,
                    ignore_errors=bool(args.ignore_errors),
                    stop_event=stop_event,
                    da_context=da_ctx,
                )

            parallel_process_accounts("import", do_import, config.accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            logging.info("Import finished into server %s", config.server.host)
        elif args.mode == "test":
            logging.info("Test completed successfully.")
        elif args.mode == "validate":
            assert isinstance(config, Config)
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            check_free_space_for_path(in_root, min_free_gb)
            mismatches: List[Tuple[str, str, int, int]] = []
            validation_errors: List[Tuple[str, str]] = []
            mismatches_lock = threading.Lock()
            def do_validate(acc: Account) -> None:
                email = acc.email
                try:
                    from .imap_ops import imap_connection, list_all_mailboxes, quote_mailbox_name
                    account_dir = in_root / sanitize_for_path(acc.email)
                    local_counts: Dict[str, int] = {}
                    if account_dir.exists():
                        for folder_dir in [p for p in account_dir.iterdir() if p.is_dir()]:
                            count = len(list(folder_dir.glob("*.eml")))
                            local_counts[folder_dir.name] = count
                    remote_counts: Dict[str, int] = {}
                    with imap_connection(config.server, acc) as imap:
                        mailboxes = list_all_mailboxes(imap)
                        for mailbox in mailboxes:
                            try:
                                status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
                                if status != "OK":
                                    raise RuntimeError(f"select failed: {mailbox}")
                                status, data = imap.search(None, "ALL")
                                if status != "OK":
                                    raise RuntimeError(f"search failed: {mailbox}")
                                num = len((data[0] or b"").split()) if data else 0
                                remote_counts[sanitize_for_path(mailbox)] = num
                            except Exception:
                                remote_counts[sanitize_for_path(mailbox)] = -1
                    for folder, local_count in local_counts.items():
                        remote = remote_counts.get(folder, -1)
                        if local_count != remote:
                            with mismatches_lock:
                                mismatches.append((email, folder, local_count, remote))
                    for folder, remote_count in remote_counts.items():
                        if folder not in local_counts and remote_count > 0:
                            with mismatches_lock:
                                mismatches.append((email, folder, 0, remote_count))
                except Exception as exc:
                    with mismatches_lock:
                        validation_errors.append((email, str(exc)))
            parallel_process_accounts("validate", do_validate, config.accounts, int(args.max_workers), stop_on_error=False)
            if validation_errors:
                logging.warning("Validation account failures found:")
                for email, reason in validation_errors:
                    logging.warning("%s | %s", email, reason)
                return 4
            if mismatches:
                logging.warning("Validation mismatches found:")
                for email, folder, local_count, remote_count in mismatches:
                    logging.warning("%s | %s | local=%d remote=%d", email, folder, local_count, remote_count)
                if args.resync_missing:
                    logging.warning("--resync-missing is disabled for legacy configs; blind APPEND replay can create duplicates")
                return 4
            else:
                logging.info("Validation successful: local export matches remote counts for all accounts.")
        elif args.mode == "audit":
            assert isinstance(config, Config)
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            check_free_space_for_path(in_root, min_free_gb)
            try:
                logging.info("Running audit on %s (%s) ...", in_root, "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                ok, audit_issues = audit_export(in_root, config, int(args.max_workers), check_remote=not bool(getattr(args, "audit_offline", False)))
                if ok:
                    logging.info("Audit passed: exported data looks consistent for all accounts")
                    return 0
                logging.error("Audit found %d issue(s):", len(audit_issues))
                for line in audit_issues:
                    logging.error("[audit] %s", line)
                return 4
            except Exception as exc:
                logging.exception("Fatal audit error: %s", exc)
                return 4
        else:
            logging.error("Unknown mode: %s", args.mode)
            return 2
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        return 1

    logging.info("Done. Log file: %s", log_file)
    return 0
