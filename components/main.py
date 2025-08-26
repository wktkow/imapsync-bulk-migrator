from __future__ import annotations

import argparse
import logging
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
from .models import Account, Config
from .utils import check_environment, sanitize_for_path


def setup_logging(log_directory: Path) -> Path:
    log_directory.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    import logging
    import sys

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
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
        reasons = "\n".join(list(errors.queue))
        raise RuntimeError(f"Connectivity test failed for some accounts:\n{reasons}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk export/import/validate IMAP mailboxes with prechecks via imapsync.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", required=True, choices=["export", "import", "test", "validate", "audit"], help="Operation mode")
    parser.add_argument("--config", required=False, help="Path to JSON config file with server and accounts")
    parser.add_argument("--output-dir", default=str(Path.cwd() / "exported"), help="Directory to write exported data")
    parser.add_argument("--input-dir", default=str(Path.cwd() / "exported"), help="Directory to read exported data for import/validate")
    parser.add_argument("--max-workers", type=int, default=max(4, (os.cpu_count() or 4)), help="Parallel worker threads for accounts")
    parser.add_argument("--ignore-errors", action="store_true", help="Continue other accounts on errors")
    parser.add_argument("--log-dir", default=str(Path.cwd() / "logs"), help="Directory to store log files")
    parser.add_argument("--min-free-gb", type=float, default=1.0, help="Fail-fast if free disk space is lower")
    parser.add_argument("--resync-missing", action="store_true", help="In validate mode, attempt to re-import missing messages")
    parser.add_argument("--no-audit-after-export", action="store_true", help="Do not run audit automatically after export")
    parser.add_argument("--no-connectivity-test", action="store_true", help="Skip preflight connectivity tests (imaplib + imapsync --justconnect)")
    parser.add_argument("--audit-offline", action="store_true", help="Do not contact IMAP server during audit; perform local-only checks")

    parser.add_argument("--auto-provision-da", action="store_true", help="In import mode, if accounts don't exist on the panel, auto-create them via DirectAdmin API before tests and import")
    parser.add_argument("--da-url", required=False, help="DirectAdmin base URL, e.g. https://panel.example.com:2222")
    parser.add_argument("--da-username", required=False, help="DirectAdmin API username")
    parser.add_argument("--da-password", required=False, help="DirectAdmin API password or login key")
    parser.add_argument("--da-no-verify-ssl", action="store_true", help="Disable TLS certificate verification for DirectAdmin API")
    parser.add_argument("--da-dry-run", action="store_true", help="Show what would be created without making changes")
    parser.add_argument("--da-quota-mb", type=int, default=0, help="New mailbox quota in MiB (0 = unlimited)")

    args = parser.parse_args(argv)

    log_file = setup_logging(Path(args.log_dir))
    logging.info("Starting imapsync-bulk-migrator | mode=%s", args.mode)

    try:
        check_environment(min_free_gb=float(args.min_free_gb))
        if args.mode in {"export", "import", "test", "validate"} and not bool(getattr(args, "no_connectivity_test", False)):
            from .utils import ensure_imapsync_available
            ensure_imapsync_available()
    except Exception as exc:
        logging.error("Environment/dependency check failed: %s", exc)
        return 2

    default_config = {
        "export": "export.pass.config.json",
        "import": "import.pass.config.json",
        "test": "export.pass.config.json",
        "validate": "import.pass.config.json",
        "audit": "export.pass.config.json",
    }[args.mode]
    config_path = Path(args.config or default_config)
    if not config_path.exists():
        logging.error("Config not found: %s", str(config_path))
        return 2
    try:
        config = Config.from_json_file(config_path)
    except Exception as exc:
        logging.error("Invalid config: %s", exc)
        return 2

    da_client: Optional[DirectAdminClient] = None
    if args.mode == "import" and bool(getattr(args, "auto_provision_da", False)):
        missing = [n for n in ("da_url", "da_username", "da_password") if not getattr(args, n)]
        if missing:
            logging.error("DirectAdmin auto-provisioning requires: --da-url, --da-username, --da-password (missing: %s)", ", ".join(missing))
            return 2
        try:
            logging.info("[da] Auto-provisioning missing mailboxes before import...")
            da_client = DirectAdminClient(
                base_url=str(args.da_url),
                username=str(args.da_username),
                password=str(args.da_password),
                verify_ssl=not bool(args.da_no_verify_ssl),
            )
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
            logging.info("Running connectivity tests (imaplib + imapsync --justconnect) ...")
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

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    try:
        if args.mode == "export":
            out_root = Path(args.output_dir)
            out_root.mkdir(parents=True, exist_ok=True)
            try:
                from .models import Config as _Cfg
                payload_path = Path("import.pass.config.json")
                if not payload_path.exists():
                    with payload_path.open("w", encoding="utf-8") as f:
                        import json
                        json.dump({
                            "server": {
                                "host": config.server.host,
                                "port": config.server.port,
                                "ssl": config.server.ssl,
                                "starttls": config.server.starttls,
                            },
                            "accounts": [ {"email": a.email, "password": a.password} for a in config.accounts ],
                        }, f, ensure_ascii=False, indent=2)
                    logging.info("Generated import config template at: %s", payload_path)
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
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2

            def do_import(acc: Account) -> None:
                if stop_event.is_set():
                    return
                da_ctx = None
                if bool(getattr(args, "auto_provision_da", False)) and da_client is not None:
                    da_ctx = (da_client, int(args.da_quota_mb))
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
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            mismatches: List[Tuple[str, str, int, int]] = []
            mismatches_lock = threading.Lock()
            def do_validate(acc: Account) -> None:
                from .imap_ops import imap_connection, list_all_mailboxes
                from .imap_ops import fetch_all_uids
                email = acc.email
                account_dir = in_root / sanitize_for_path(acc.email)
                if not account_dir.exists():
                    return
                local_counts: Dict[str, int] = {}
                for folder_dir in [p for p in account_dir.iterdir() if p.is_dir()]:
                    count = len(list(folder_dir.glob("*.eml")))
                    local_counts[folder_dir.name] = count
                remote_counts: Dict[str, int] = {}
                import imaplib
                with imap_connection(config.server, acc) as imap:
                    mailboxes = list_all_mailboxes(imap)
                    for mailbox in mailboxes:
                        try:
                            status, _ = imap.select(mailbox, readonly=True)
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
            parallel_process_accounts("validate", do_validate, config.accounts, int(args.max_workers), stop_on_error=False)
            if mismatches:
                logging.warning("Validation mismatches found:")
                for email, folder, local_count, remote_count in mismatches:
                    logging.warning("%s | %s | local=%d remote=%d", email, folder, local_count, remote_count)
                if args.resync_missing:
                    logging.info("Attempting resync for mismatched folders by re-running import for affected accounts ...")
                    affected = {e for e, _, _, _ in mismatches}
                    def do_resync(acc: Account) -> None:
                        if acc.email in affected:
                            from .imap_ops import import_account as _import
                            _import(acc, config.server, in_root, ignore_errors=True)
                    parallel_process_accounts("resync", do_resync, [a for a in config.accounts if a.email in affected], int(args.max_workers), stop_on_error=False)
            else:
                logging.info("Validation successful: local export matches remote counts for all accounts.")
        elif args.mode == "audit":
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
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


