from __future__ import annotations

import argparse
import errno
import hashlib
import json
import logging
import math
import socket
import os
import signal
import sys
import threading
from pathlib import Path
from email.parser import BytesParser
from email.policy import default as default_policy
from typing import List, Optional, Tuple, Dict, Set

from .audit import audit_export
from .cpanel_client import CPanelClient
from .cpanel_ensure import ensure_accounts_exist_cpanel
from .da_client import DirectAdminClient
from .da_ensure import ensure_accounts_exist_directadmin
from .executor import parallel_process_accounts
from .imap_ops import (
    _legacy_symlink_component,
    archive_legacy_import_journal_for_reset,
    export_account,
    import_account,
    legacy_export_output_symlink_issues,
)
from .imapsync_cli import run_imapsync_justconnect
from .models import Account, Config, ProviderMigrationConfig, load_config_file
from .provider_ops import (
    provider_audit_all,
    provider_export_all,
    provider_import_all,
    provider_preflight,
    provider_test_accounts,
    provider_validate_account,
    provider_validate_all,
    _raise_if_provider_path_symlink,
)
from .utils import check_environment, quote_imap_search_value, sanitize_for_path, sanitized_path_key
from .utils import check_free_space_for_path


def _utc_log_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _read_required_secret_file(path: str, *, label: str) -> str:
    value = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
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
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ValueError(f"DirectAdmin password environment variable is unset or empty: {env_name}")
        return value
    logging.warning("--da-password exposes the DirectAdmin secret via shell history/process arguments; prefer --da-password-file or --da-password-env")
    return str(args.da_password)


def _resolve_cpanel_auth(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    password_sources = [
        name
        for name, value in (
            ("--cpanel-password", getattr(args, "cpanel_password", None)),
            ("--cpanel-password-file", getattr(args, "cpanel_password_file", None)),
            ("--cpanel-password-env", getattr(args, "cpanel_password_env", None)),
        )
        if value
    ]
    token_sources = [
        name
        for name, value in (
            ("--cpanel-token", getattr(args, "cpanel_token", None)),
            ("--cpanel-token-file", getattr(args, "cpanel_token_file", None)),
            ("--cpanel-token-env", getattr(args, "cpanel_token_env", None)),
        )
        if value
    ]
    if len(password_sources) > 1:
        raise ValueError("cPanel password must be provided by only one source")
    if len(token_sources) > 1:
        raise ValueError("cPanel API token must be provided by only one source")
    if password_sources and token_sources:
        raise ValueError("cPanel authentication must use either password or API token, not both")
    if getattr(args, "cpanel_password_file", None):
        return _read_required_secret_file(str(args.cpanel_password_file), label="cPanel password file"), None
    if getattr(args, "cpanel_password_env", None):
        env_name = str(args.cpanel_password_env)
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ValueError(f"cPanel password environment variable is unset or empty: {env_name}")
        return value, None
    if getattr(args, "cpanel_password", None):
        logging.warning("--cpanel-password exposes the cPanel secret via shell history/process arguments; prefer --cpanel-password-file or --cpanel-password-env")
        return str(args.cpanel_password), None
    if getattr(args, "cpanel_token_file", None):
        return None, _read_required_secret_file(str(args.cpanel_token_file), label="cPanel API token file")
    if getattr(args, "cpanel_token_env", None):
        env_name = str(args.cpanel_token_env)
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ValueError(f"cPanel API token environment variable is unset or empty: {env_name}")
        return None, value
    if getattr(args, "cpanel_token", None):
        logging.warning("--cpanel-token exposes the cPanel token via shell history/process arguments; prefer --cpanel-token-file or --cpanel-token-env")
        return None, str(args.cpanel_token)
    raise ValueError("cPanel provisioning requires one of: --cpanel-token-file, --cpanel-token-env, --cpanel-token, --cpanel-password-file, --cpanel-password-env, --cpanel-password")


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


def _message_id_header(data: bytes) -> str:
    try:
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    except Exception:
        return ""


def _legacy_remote_has_message(imap, mailbox: str, data: bytes, used_nums: Optional[Set[bytes]] = None) -> bool:
    from .imap_ops import _imap_append_wire_bytes, quote_mailbox_name

    data = _imap_append_wire_bytes(data)
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    message_id = _message_id_header(data)
    expected_hash = hashlib.sha256(data).hexdigest()
    expected_size = len(data)
    if message_id:
        status, search_data = imap.search(None, "HEADER", "Message-ID", quote_imap_search_value(message_id))
    else:
        status, search_data = imap.search(None, "ALL")
    if status != "OK" or not search_data or not search_data[0]:
        return False
    for num in search_data[0].split():
        if used_nums is not None and num in used_nums:
            continue
        status, fetched = imap.fetch(num, "(RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            continue
        for part in fetched or []:
            if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
                continue
            body = bytes(part[1])
            if len(body) == expected_size and hashlib.sha256(body).hexdigest() == expected_hash:
                if used_nums is not None:
                    used_nums.add(num)
                return True
    return False


def setup_logging(log_directory: Path) -> Path:
    """Initialize root logger with file + stdout handlers and return log path."""
    if _legacy_symlink_component(log_directory) is not None:
        raise RuntimeError(f"refusing to use symlinked log directory: {log_directory}")
    log_directory.mkdir(parents=True, exist_ok=True)
    if _legacy_symlink_component(log_directory) is not None:
        raise RuntimeError(f"refusing to use symlinked log directory: {log_directory}")
    import logging
    import sys
    import time

    timestamp = _utc_log_timestamp()

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = time.gmtime

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    log_file: Optional[Path] = None
    log_fd: Optional[int] = None
    for attempt in range(100):
        suffix = "" if attempt == 0 else f"-{attempt}"
        candidate = log_directory / f"run-{timestamp}{suffix}.log"
        try:
            log_fd = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK} or candidate.is_symlink():
                raise RuntimeError(f"refusing to use symlinked log file: {candidate}") from exc
            raise
        log_file = candidate
        break
    if log_file is None or log_fd is None:
        raise RuntimeError(f"could not create a unique log file in {log_directory}")
    os.fchmod(log_fd, 0o600)
    fh = logging.StreamHandler(os.fdopen(log_fd, "a", encoding="utf-8"))
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


def _invalid_panel_account_emails(config: Config) -> List[str]:
    invalid: List[str] = []
    for acc in config.accounts:
        email = acc.email.strip()
        if (
            email != acc.email
            or email.count("@") != 1
            or not email.split("@", 1)[0]
            or not email.split("@", 1)[1]
            or any(ch.isspace() for ch in email)
        ):
            invalid.append(acc.email)
    return invalid


def _legacy_staged_symlink_issues(in_root: Path, config: Config) -> List[str]:
    issues: List[str] = []
    for acc in config.accounts:
        account_dir = in_root / sanitize_for_path(acc.email)
        if account_dir.is_symlink():
            issues.append(f"{acc.email}: account directory is a symlink: {account_dir}")
            continue
        if not account_dir.exists():
            continue
        if not account_dir.is_dir():
            issues.append(f"{acc.email}: account path is not a directory: {account_dir}")
            continue
        for path in sorted(account_dir.rglob("*")):
            if path.is_symlink():
                rel_path = path.relative_to(account_dir).as_posix()
                issues.append(f"{acc.email}: staged path is a symlink: {rel_path}")
    return issues


def _provider_staged_symlink_issues(account_dir: Path, account_label: str) -> List[str]:
    issues: List[str] = []
    stack = [account_dir]
    while stack:
        current = stack.pop()
        try:
            children = sorted(current.iterdir())
        except OSError as exc:
            rel = current.relative_to(account_dir).as_posix() if current != account_dir else "."
            issues.append(f"{account_label}: failed to read staged provider path {rel}: {exc}")
            continue
        for child in children:
            rel = child.relative_to(account_dir).as_posix()
            if child.is_symlink():
                issues.append(f"{account_label}: staged provider path is a symlink: {rel}")
                continue
            if child.is_dir():
                stack.append(child)
    return issues


def _provider_cli_local_root_issues(
    root: Path,
    config: ProviderMigrationConfig,
    *,
    label: str,
    require_exists: bool,
) -> List[str]:
    issues: List[str] = []
    try:
        _raise_if_provider_path_symlink(root, f"{label} root")
    except RuntimeError as exc:
        return [str(exc)]
    if not root.exists():
        if require_exists:
            issues.append(f"{label.capitalize()} directory does not exist: {root}")
        return issues
    if not root.is_dir():
        return [f"{label.capitalize()} directory is not a directory: {root}"]
    for account in config.accounts:
        account_dir = root / sanitize_for_path(account.source_email)
        try:
            _raise_if_provider_path_symlink(account_dir, "account directory")
        except RuntimeError as exc:
            issues.append(f"{account.source_email}: {exc}")
            continue
        if account_dir.exists() and not account_dir.is_dir():
            issues.append(f"{account.source_email}: provider account path is not a directory: {account_dir}")
            continue
        if account_dir.exists():
            issues.extend(_provider_staged_symlink_issues(account_dir, account.source_email))
    return issues


def _provider_cli_staged_validation_issues(
    root: Path,
    config: ProviderMigrationConfig,
    *,
    mode: str,
) -> List[str]:
    issues: List[str] = []
    for account in config.accounts:
        _name, report = provider_validate_account(
            config,
            account,
            root,
            check_target=False,
            write_report=False,
            allow_unresolved_pending=(mode == "import"),
        )
        keys = ("duplicates", "failed", "missing") if mode == "validate" else ("duplicates", "failed")
        for key in keys:
            for item in report.get(key, []):
                issues.append(f"{account.source_email}: {key}: {item}")
    return issues


def _legacy_pending_import_journal_issues(root: Path, config: Config) -> List[str]:
    from .imap_ops import _legacy_import_target_id, _load_legacy_import_journal, _unresolved_legacy_pending_keys

    issues: List[str] = []
    for account in config.accounts:
        account_dir = root / sanitize_for_path(account.email)
        if not account_dir.exists():
            continue
        try:
            pending_keys = _unresolved_legacy_pending_keys(
                _load_legacy_import_journal(account_dir, repair_trailing=False),
                _legacy_import_target_id(config.server, account),
            )
        except Exception as exc:
            issues.append(f"{account.email}: import journal load failed: {exc}")
            continue
        if pending_keys:
            issues.append(
                f"{account.email}: import journal has {len(pending_keys)} pending append(s); "
                "target state is uncertain"
            )
    return issues


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
    parser.add_argument("--reset-confirm", required=False, help="Required for non-dry-run --reset; must match the target IMAP host or be YES")
    parser.add_argument("--da-url", required=False, help="DirectAdmin base URL, e.g. https://panel.example.com:2222")
    parser.add_argument("--da-username", required=False, help="DirectAdmin API username")
    parser.add_argument("--da-password", required=False, help="DirectAdmin API password or login key; insecure because process args can expose it")
    parser.add_argument("--da-password-file", required=False, help="Path to a file containing the DirectAdmin API password or login key")
    parser.add_argument("--da-password-env", required=False, help="Environment variable containing the DirectAdmin API password or login key")
    parser.add_argument("--da-no-verify-ssl", action="store_true", help="Disable TLS certificate verification for DirectAdmin API")
    parser.add_argument("--da-dry-run", action="store_true", help="Show what would be created without making changes")
    parser.add_argument("--da-quota-mb", type=int, default=0, help="New mailbox quota in MiB (0 = unlimited)")

    parser.add_argument("--auto-provision-cpanel", action="store_true", help="In import mode, auto-create/reset missing target mailboxes via cPanel UAPI")
    parser.add_argument("--cpanel-url", required=False, help="cPanel base URL, e.g. https://panel.example.com:2083")
    parser.add_argument("--cpanel-username", required=False, help="cPanel account username for UAPI")
    parser.add_argument("--cpanel-password", required=False, help="cPanel password; insecure because process args can expose it")
    parser.add_argument("--cpanel-password-file", required=False, help="Path to a file containing the cPanel password")
    parser.add_argument("--cpanel-password-env", required=False, help="Environment variable containing the cPanel password")
    parser.add_argument("--cpanel-token", required=False, help="cPanel API token; insecure because process args can expose it")
    parser.add_argument("--cpanel-token-file", required=False, help="Path to a file containing the cPanel API token")
    parser.add_argument("--cpanel-token-env", required=False, help="Environment variable containing the cPanel API token")
    parser.add_argument("--cpanel-no-verify-ssl", action="store_true", help="Disable TLS certificate verification for cPanel UAPI")
    parser.add_argument("--cpanel-dry-run", action="store_true", help="Show cPanel provisioning/reset operations without making changes")
    parser.add_argument("--cpanel-quota-mb", type=int, default=0, help="New cPanel mailbox quota in MiB (0 = unlimited)")

    args = parser.parse_args(argv)

    try:
        log_file = setup_logging(Path(args.log_dir))
    except Exception as exc:
        print(f"Failed to initialize logging: {exc}", file=sys.stderr)
        return 2
    logging.info("Starting imapsync-bulk-migrator | mode=%s", args.mode)

    if int(args.max_workers) < 1:
        logging.error("--max-workers must be >= 1")
        return 2
    if int(args.da_quota_mb) < 0:
        logging.error("--da-quota-mb must be >= 0")
        return 2
    if int(args.cpanel_quota_mb) < 0:
        logging.error("--cpanel-quota-mb must be >= 0")
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
    use_da_panel = bool(getattr(args, "auto_provision_da", False))
    use_cpanel = bool(getattr(args, "auto_provision_cpanel", False))
    legacy_staged_audit_completed = False
    free_space_checked_paths: Set[Path] = set()
    if (
        not is_provider_config
        and args.mode != "import"
        and (use_da_panel or use_cpanel or bool(getattr(args, "reset", False)))
    ):
        logging.error("--auto-provision-da, --auto-provision-cpanel, and --reset are only valid with --mode import")
        return 2
    if use_da_panel and use_cpanel:
        logging.error("Choose only one control panel integration: --auto-provision-da or --auto-provision-cpanel")
        return 2
    if is_provider_config and (use_da_panel or use_cpanel or bool(getattr(args, "reset", False))):
        logging.error("Control-panel auto-provisioning is not supported for provider source/target configs; use provider IMAP configs without panel reset")
        return 2
    if bool(getattr(args, "reset", False)) and not (use_da_panel or use_cpanel):
        logging.error("--reset requires --auto-provision-da or --auto-provision-cpanel")
        return 2
    if bool(getattr(args, "da_dry_run", False)) and not use_da_panel:
        logging.error("--da-dry-run requires --auto-provision-da")
        return 2
    if bool(getattr(args, "cpanel_dry_run", False)) and not use_cpanel:
        logging.error("--cpanel-dry-run requires --auto-provision-cpanel")
        return 2
    panel_dry_run_requested = (
        args.mode == "import"
        and not is_provider_config
        and (
            (use_da_panel and bool(getattr(args, "da_dry_run", False)))
            or (use_cpanel and bool(getattr(args, "cpanel_dry_run", False)))
        )
    )
    if (
        args.mode == "import"
        and bool(getattr(args, "reset", False))
        and not (bool(getattr(args, "auto_provision_da", False)) and bool(getattr(args, "da_dry_run", False)))
        and not (bool(getattr(args, "auto_provision_cpanel", False)) and bool(getattr(args, "cpanel_dry_run", False)))
    ):
        target_host = config.target.host if isinstance(config, ProviderMigrationConfig) else config.server.host
        reset_confirm = str(getattr(args, "reset_confirm", "") or "")
        if reset_confirm not in {target_host, "YES"}:
            logging.error("--reset-confirm must match target IMAP host %r or be YES for non-dry-run --reset", target_host)
            return 2
    if args.mode in {"import", "validate", "audit"} and not panel_dry_run_requested:
        input_root = Path(args.input_dir)
        if is_provider_config:
            assert isinstance(config, ProviderMigrationConfig)
            provider_local_issues = _provider_cli_local_root_issues(
                input_root,
                config,
                label=args.mode,
                require_exists=True,
            )
            if provider_local_issues:
                logging.error("Provider %s input failed local preflight:", args.mode)
                for issue in provider_local_issues:
                    logging.error("[provider-local] %s", issue)
                return 2
            if args.mode in {"import", "validate"}:
                provider_staged_issues = _provider_cli_staged_validation_issues(input_root, config, mode=args.mode)
                if provider_staged_issues:
                    logging.error("Provider %s staged data failed local validation:", args.mode)
                    for issue in provider_staged_issues:
                        logging.error("[provider-staged] %s", issue)
                    return 4
        elif _legacy_symlink_component(input_root) is not None:
            logging.error("Input directory is a symlink: %s", input_root)
            return 2
        if not input_root.exists():
            logging.error("Input directory does not exist: %s", input_root)
            return 2
        if not input_root.is_dir():
            logging.error("Input directory is not a directory: %s", input_root)
            return 2
        if not is_provider_config and args.mode in {"import", "validate"}:
            assert isinstance(config, Config)
            symlink_issues = _legacy_staged_symlink_issues(input_root, config)
            if symlink_issues:
                logging.error("Input directory failed local staged preflight:")
                for issue in symlink_issues:
                    logging.error("[staged-local] %s", issue)
                return 2
            if not use_da_panel and not use_cpanel:
                try:
                    logging.info("Running strict local staged export audit before connectivity...")
                    ok, staged_audit_issues = audit_export(
                        input_root,
                        config,
                        int(args.max_workers),
                        check_remote=False,
                        require_integrity_metadata=True,
                    )
                except Exception as exc:
                    logging.error("Staged export audit failed before connectivity: %s", exc)
                    return 4
                if not ok:
                    logging.error(
                        "Refusing %s because staged export audit found %d issue(s)",
                        args.mode,
                        len(staged_audit_issues),
                    )
                    for issue in staged_audit_issues:
                        logging.error("[staged-audit] %s", issue)
                    return 4
                legacy_staged_audit_completed = True
            if not (args.mode == "import" and bool(getattr(args, "reset", False))):
                pending_journal_issues = _legacy_pending_import_journal_issues(input_root, config)
                if pending_journal_issues:
                    logging.error("Input directory has unresolved legacy import journal entries:")
                    for issue in pending_journal_issues:
                        logging.error("[staged-journal] %s", issue)
                    return 4
    if args.mode == "export":
        output_root = Path(args.output_dir)
        if is_provider_config:
            assert isinstance(config, ProviderMigrationConfig)
            provider_local_issues = _provider_cli_local_root_issues(
                output_root,
                config,
                label="export",
                require_exists=False,
            )
            if provider_local_issues:
                logging.error("Provider export output failed local preflight:")
                for issue in provider_local_issues:
                    logging.error("[provider-local] %s", issue)
                return 2
        elif _legacy_symlink_component(output_root) is not None:
            logging.error("Output directory is a symlink: %s", output_root)
            return 2
        elif output_root.exists() and not output_root.is_dir():
            logging.error("Output directory is not a directory: %s", output_root)
            return 2
        elif not is_provider_config:
            assert isinstance(config, Config)
            output_symlink_issues = legacy_export_output_symlink_issues(output_root, config.accounts)
            if output_symlink_issues:
                logging.error("Legacy export output failed local preflight:")
                for issue in output_symlink_issues:
                    logging.error("[export-local] %s", issue)
                return 2

    free_space_preflight_path: Optional[Path] = None
    if args.mode == "export":
        free_space_preflight_path = Path(args.output_dir)
    elif args.mode in {"import", "validate"} and not panel_dry_run_requested:
        panel_import_will_preflight = (
            not is_provider_config
            and args.mode == "import"
            and (use_da_panel or use_cpanel)
        )
        if not panel_import_will_preflight:
            free_space_preflight_path = Path(args.input_dir)
    if free_space_preflight_path is not None:
        try:
            check_free_space_for_path(free_space_preflight_path, min_free_gb)
        except Exception as exc:
            logging.error("Free-space check failed before connectivity: %s", exc)
            return 2
        free_space_checked_paths.add(free_space_preflight_path)

    try:
        if (
            not is_provider_config
            and args.mode in {"export", "import", "test", "validate"}
            and not bool(getattr(args, "no_connectivity_test", False))
            and not panel_dry_run_requested
        ):
            from .utils import ensure_imapsync_available
            ensure_imapsync_available()
    except Exception as exc:
        logging.error("Environment/dependency check failed: %s", exc)
        return 2

    da_client: Optional[DirectAdminClient] = None
    da_password: Optional[str] = None
    cpanel_client: Optional[CPanelClient] = None
    panel_reset_failed_accounts: set[str] = set()
    if (not is_provider_config) and args.mode == "import" and (use_da_panel or use_cpanel):
        assert isinstance(config, Config)
        invalid_panel_accounts = _invalid_panel_account_emails(config)
        if invalid_panel_accounts:
            logging.error(
                "Control-panel provisioning requires mailbox accounts in local@domain form; invalid account(s): %s",
                ", ".join(invalid_panel_accounts),
            )
            return 2
    if (not is_provider_config) and args.mode == "import" and (use_da_panel or use_cpanel):
        if not panel_dry_run_requested:
            staged_root = Path(args.input_dir)
            if not staged_root.exists():
                logging.error("Input directory does not exist: %s", staged_root)
                return 2
            assert isinstance(config, Config)
            missing_account_dirs = [
                acc.email
                for acc in config.accounts
                if not (staged_root / sanitize_for_path(acc.email)).exists()
            ]
            if missing_account_dirs:
                logging.error(
                    "Input directory is missing staged data for %d account(s): %s",
                    len(missing_account_dirs),
                    ", ".join(missing_account_dirs),
                )
                return 2
            try:
                check_free_space_for_path(staged_root, min_free_gb)
            except Exception as exc:
                logging.error("[panel] Free-space check failed before panel changes: %s", exc)
                return 2
            audit_for_reset = bool(getattr(args, "reset", False))
            try:
                logging.info(
                    "[panel] Running strict local staged export audit before %s...",
                    "destructive reset" if audit_for_reset else "panel provisioning",
                )
                ok, staged_audit_issues = audit_export(
                    staged_root,
                    config,
                    int(args.max_workers),
                    check_remote=False,
                    require_integrity_metadata=True,
                )
            except Exception as exc:
                logging.error("[panel] Staged export audit failed before panel changes: %s", exc)
                return 4
            if not ok:
                logging.error(
                    "[panel] Refusing %s because staged export audit found %d issue(s)",
                    "destructive reset" if audit_for_reset else "panel provisioning",
                    len(staged_audit_issues),
                )
                for issue in staged_audit_issues:
                    logging.error("[panel-staged-audit] %s", issue)
                return 4
    if (not is_provider_config) and args.mode == "import" and use_da_panel:
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
                panel_reset_failed_accounts = reset_accounts_directadmin(
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
            if bool(getattr(args, "reset", False)):
                panel_reset_failed_accounts = {acc.email for acc in config.accounts}
            if da_client is None or bool(getattr(args, "da_dry_run", False)) or not args.ignore_errors:
                return 3
    if (not is_provider_config) and args.mode == "import" and use_cpanel:
        missing = [n for n in ("cpanel_url", "cpanel_username") if not getattr(args, n)]
        if missing:
            logging.error("cPanel auto-provisioning requires: --cpanel-url, --cpanel-username, and a password/token source (missing: %s)", ", ".join(missing))
            return 2
        try:
            cpanel_password, cpanel_token = _resolve_cpanel_auth(args)
            logging.info("[cpanel] Auto-provisioning missing mailboxes before import...")
            cpanel_client = CPanelClient(
                base_url=str(args.cpanel_url),
                username=str(args.cpanel_username),
                password=cpanel_password,
                token=cpanel_token,
                verify_ssl=not bool(args.cpanel_no_verify_ssl),
            )
            if bool(getattr(args, "reset", False)):
                from .cpanel_ensure import reset_accounts_cpanel
                logging.info("[cpanel] Reset requested: deleting and recreating mailboxes before import...")
                panel_reset_failed_accounts = reset_accounts_cpanel(
                    config,
                    cpanel_client,
                    dry_run=bool(args.cpanel_dry_run),
                    ignore_errors=bool(args.ignore_errors),
                    quota_mb=int(args.cpanel_quota_mb),
                )
            else:
                ensure_accounts_exist_cpanel(
                    config,
                    cpanel_client,
                    dry_run=bool(args.cpanel_dry_run),
                    ignore_errors=bool(args.ignore_errors),
                    quota_mb=int(args.cpanel_quota_mb),
                )
            logging.info("[cpanel] Auto-provisioning step completed")
        except Exception as exc:
            logging.error("[cpanel] Auto-provisioning failed: %s", exc)
            if bool(getattr(args, "reset", False)):
                panel_reset_failed_accounts = {acc.email for acc in config.accounts}
            if cpanel_client is None or bool(getattr(args, "cpanel_dry_run", False)) or not args.ignore_errors:
                return 3
    if args.mode == "import" and (
        (use_da_panel and bool(getattr(args, "da_dry_run", False)))
        or (use_cpanel and bool(getattr(args, "cpanel_dry_run", False)))
    ):
        logging.info("[panel][dry-run] Skipping connectivity tests and IMAP import because panel dry-run was requested")
        return 0

    if (not is_provider_config) and args.mode == "import" and bool(getattr(args, "reset", False)):
        assert isinstance(config, Config)
        reset_input_root = Path(args.input_dir)
        try:
            for acc in config.accounts:
                if acc.email in panel_reset_failed_accounts:
                    continue
                archive_path = archive_legacy_import_journal_for_reset(reset_input_root / sanitize_for_path(acc.email))
                if archive_path is not None:
                    logging.info("[panel] Archived stale import journal after reset for %s: %s", acc.email, archive_path)
        except Exception as exc:
            logging.error("[panel] Failed to archive stale import journal after reset: %s", exc)
            return 4

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
                connectivity_config = config
                if args.mode == "import" and bool(getattr(args, "reset", False)) and panel_reset_failed_accounts:
                    active_accounts = [acc for acc in config.accounts if acc.email not in panel_reset_failed_accounts]
                    skipped = len(config.accounts) - len(active_accounts)
                    logging.info(
                        "[panel] Skipping connectivity tests for %d account(s) whose control-panel reset failed",
                        skipped,
                    )
                    connectivity_config = Config(server=config.server, accounts=active_accounts, source_server=config.source_server)
                test_accounts(connectivity_config, max_workers=int(args.max_workers))
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
                if out_root not in free_space_checked_paths:
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
                if in_root not in free_space_checked_paths:
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
                if in_root not in free_space_checked_paths:
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
            if out_root.is_symlink():
                logging.error("Output directory is a symlink: %s", out_root)
                return 2
            out_root.mkdir(parents=True, exist_ok=True)
            # Ensure destination filesystem has enough free space
            if out_root not in free_space_checked_paths:
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
                        "source_server": {
                            "host": config.server.host,
                            "port": config.server.port,
                            "ssl": config.server.ssl,
                            "starttls": config.server.starttls,
                        },
                        "accounts": [{"email": a.email, "password": a.password} for a in config.accounts],
                    })
                    logging.warning("Generated import config TEMPLATE at: %s — you MUST edit server.host before importing!", payload_path)
            except Exception as exc:
                logging.warning("Failed to generate import config template: %s", exc)

            def do_export(acc: Account) -> None:
                if stop_event.is_set():
                    raise RuntimeError(f"legacy export {acc.email}: stop requested before completion")
                export_account(acc, config.server, out_root, ignore_errors=bool(args.ignore_errors), stop_event=stop_event)

            parallel_process_accounts("export", do_export, config.accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            logging.info("Export finished. Data stored under: %s", out_root)

            if not bool(getattr(args, "no_audit_after_export", False)):
                try:
                    logging.info("Running export audit (%s)...", "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                    ok, audit_issues = audit_export(
                        out_root,
                        config,
                        int(args.max_workers),
                        check_remote=not bool(getattr(args, "audit_offline", False)),
                        require_integrity_metadata=True,
                    )
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
            if in_root.is_symlink():
                logging.error("Input directory is a symlink: %s", in_root)
                return 2
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            if in_root not in free_space_checked_paths:
                check_free_space_for_path(in_root, min_free_gb)
            panel_dry_run = (use_da_panel and bool(getattr(args, "da_dry_run", False))) or (use_cpanel and bool(getattr(args, "cpanel_dry_run", False)))
            if not panel_dry_run and not legacy_staged_audit_completed:
                try:
                    logging.info("Running strict local staged export audit before import...")
                    ok, staged_audit_issues = audit_export(
                        in_root,
                        config,
                        int(args.max_workers),
                        check_remote=False,
                        require_integrity_metadata=True,
                    )
                except Exception as exc:
                    logging.error("Staged export audit failed before import: %s", exc)
                    return 4
                if not ok:
                    logging.error(
                        "Refusing import because staged export audit found %d issue(s)",
                        len(staged_audit_issues),
                    )
                    for issue in staged_audit_issues:
                        logging.error("[staged-audit] %s", issue)
                    return 4

            def do_import(acc: Account) -> None:
                if stop_event.is_set():
                    raise RuntimeError(f"legacy import {acc.email}: stop requested before completion")
                if acc.email in panel_reset_failed_accounts:
                    logging.error("[panel] Skipping import for %s because control-panel reset failed", acc.email)
                    return
                da_ctx = None
                provision_ctx = None
                if use_da_panel and da_client is not None and not bool(getattr(args, "da_dry_run", False)):
                    da_ctx = (da_client, int(args.da_quota_mb))
                    provision_ctx = (da_client, int(args.da_quota_mb), "da")
                elif use_da_panel and bool(getattr(args, "da_dry_run", False)):
                    logging.info("[da][dry-run] Lazy create-and-retry disabled for %s", acc.email)
                if use_cpanel and cpanel_client is not None and not bool(getattr(args, "cpanel_dry_run", False)):
                    provision_ctx = (cpanel_client, int(args.cpanel_quota_mb), "cpanel")
                elif use_cpanel and bool(getattr(args, "cpanel_dry_run", False)):
                    logging.info("[cpanel][dry-run] Lazy create-and-retry disabled for %s", acc.email)
                import_account(
                    acc,
                    config.server,
                    in_root,
                    ignore_errors=bool(args.ignore_errors),
                    stop_event=stop_event,
                    da_context=da_ctx,
                    provision_context=provision_ctx,
                    source_server=config.source_server,
                )

            import_accounts = [acc for acc in config.accounts if acc.email not in panel_reset_failed_accounts]
            parallel_process_accounts("import", do_import, import_accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            if panel_reset_failed_accounts:
                logging.error(
                    "[panel] Import skipped %d account(s) because control-panel reset failed: %s",
                    len(panel_reset_failed_accounts),
                    ", ".join(sorted(panel_reset_failed_accounts)),
                )
                return 3
            logging.info("Import finished into server %s", config.server.host)
        elif args.mode == "test":
            logging.info("Test completed successfully.")
        elif args.mode == "validate":
            assert isinstance(config, Config)
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            if in_root not in free_space_checked_paths:
                check_free_space_for_path(in_root, min_free_gb)
            mismatches: List[Tuple[str, str, int, int]] = []
            validation_errors: List[Tuple[str, str]] = []
            mismatches_lock = threading.Lock()
            def do_validate(acc: Account) -> None:
                email = acc.email
                try:
                    from .imap_ops import _legacy_import_target_id, _load_legacy_import_journal, _unresolved_legacy_pending_keys, imap_connection, list_all_mailboxes, quote_mailbox_name
                    account_dir = in_root / sanitize_for_path(acc.email)
                    local_counts: Dict[str, int] = {}
                    local_messages: Dict[str, List[Tuple[str, bytes]]] = {}
                    if not account_dir.exists():
                        with mismatches_lock:
                            validation_errors.append((email, f"account directory missing: {account_dir}"))
                        return
                    ok, audit_issues = audit_export(
                        in_root,
                        Config(server=config.server, accounts=[acc], source_server=config.source_server),
                        1,
                        check_remote=False,
                        require_integrity_metadata=True,
                    )
                    if not ok:
                        with mismatches_lock:
                            validation_errors.extend((email, issue) for issue in audit_issues)
                        return
                    current_target = _legacy_import_target_id(config.server, acc)
                    unresolved_pending_keys = _unresolved_legacy_pending_keys(
                        _load_legacy_import_journal(account_dir, repair_trailing=False),
                        current_target,
                    )
                    if unresolved_pending_keys:
                        with mismatches_lock:
                            validation_errors.append((email, f"import journal has {len(unresolved_pending_keys)} pending append(s); target state is uncertain"))
                        return

                    def marker_mailbox(folder_dir: Path) -> str:
                        marker_path = folder_dir / ".mailbox.json"
                        if not marker_path.exists():
                            return folder_dir.name
                        try:
                            raw = json.loads(marker_path.read_text(encoding="utf-8"))
                        except Exception as exc:
                            raise RuntimeError(f"{marker_path}: failed to parse mailbox marker: {exc}") from exc
                        mailbox = raw.get("mailbox") if isinstance(raw, dict) else None
                        return mailbox if isinstance(mailbox, str) and mailbox else folder_dir.name

                    folder_dirs = [p for p in account_dir.iterdir() if p.is_dir()]
                    if not folder_dirs:
                        with mismatches_lock:
                            validation_errors.append((email, "no mailbox folders found"))
                        return
                    local_mailboxes_by_key: Dict[str, str] = {}
                    for folder_dir in folder_dirs:
                        default_mailbox = marker_mailbox(folder_dir)
                        eml_paths = sorted(folder_dir.glob("*.eml"))
                        if not eml_paths:
                            key = sanitize_for_path(default_mailbox)
                            local_mailboxes_by_key.setdefault(key, default_mailbox)
                            local_counts.setdefault(key, 0)
                            local_messages.setdefault(default_mailbox, [])
                            continue
                        for eml_path in eml_paths:
                            mailbox = default_mailbox
                            metadata_path = eml_path.with_suffix(".json")
                            if metadata_path.exists():
                                try:
                                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                                except Exception as exc:
                                    raise RuntimeError(f"{metadata_path}: failed to parse message metadata: {exc}") from exc
                                metadata_mailbox = metadata.get("mailbox") if isinstance(metadata, dict) else None
                                if isinstance(metadata_mailbox, str) and metadata_mailbox:
                                    mailbox = metadata_mailbox
                            key = sanitize_for_path(mailbox)
                            local_mailboxes_by_key.setdefault(key, mailbox)
                            local_counts[key] = local_counts.get(key, 0) + 1
                            local_messages.setdefault(mailbox, []).append((eml_path.relative_to(account_dir).as_posix(), eml_path.read_bytes()))
                    remote_counts: Dict[str, int] = {}
                    remote_mailboxes: Dict[str, str] = {}
                    remote_mailboxes_by_alias_key: Dict[str, Tuple[str, str]] = {}
                    remote_name_mismatch_keys: Set[str] = set()
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
                                key = sanitize_for_path(mailbox)
                                alias_key = sanitized_path_key(mailbox)
                                expected_mailbox = local_mailboxes_by_key.get(key)
                                if expected_mailbox is not None and mailbox != expected_mailbox:
                                    remote_counts[key] = num
                                    remote_mailboxes[key] = mailbox
                                    remote_name_mismatch_keys.add(key)
                                    with mismatches_lock:
                                        validation_errors.append((
                                            email,
                                            f"{expected_mailbox}: remote mailbox name mismatch for staged path {key}: "
                                            f"expected {expected_mailbox!r} got {mailbox!r}",
                                        ))
                                    continue
                                previous = remote_mailboxes_by_alias_key.get(alias_key)
                                if previous is not None and previous[0] != mailbox:
                                    previous_mailbox, previous_path = previous
                                    remote_counts[previous_path] = -1
                                    remote_counts[key] = -1
                                    remote_mailboxes.setdefault(previous_path, previous_mailbox)
                                    remote_mailboxes[key] = mailbox
                                    with mismatches_lock:
                                        validation_errors.append((
                                            email,
                                            f"{alias_key}: remote mailbox name collision after sanitizing: "
                                            f"{previous_mailbox!r} and {mailbox!r}",
                                        ))
                                    continue
                                remote_counts[key] = num
                                remote_mailboxes[key] = mailbox
                                remote_mailboxes_by_alias_key[alias_key] = (mailbox, key)
                            except Exception:
                                key = sanitize_for_path(mailbox)
                                remote_counts[key] = -1
                                remote_mailboxes.setdefault(key, mailbox)
                        mismatched_folders = set()
                        for folder, local_count in local_counts.items():
                            if folder in remote_name_mismatch_keys:
                                mismatched_folders.add(folder)
                                continue
                            remote = remote_counts.get(folder, -1)
                            if local_count != remote:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    mismatches.append((email, folder, local_count, remote))
                        for folder, remote_count in remote_counts.items():
                            if folder not in local_counts and remote_count < 0:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    validation_errors.append((email, f"{remote_mailboxes.get(folder, folder)}: remote mailbox could not be counted"))
                            elif folder not in local_counts and remote_count > 0:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    mismatches.append((email, folder, 0, remote_count))
                        for mailbox, messages in local_messages.items():
                            key = sanitize_for_path(mailbox)
                            if key in mismatched_folders or remote_counts.get(key, -1) < 0:
                                continue
                            remote_mailbox = remote_mailboxes.get(key, mailbox)
                            used_remote_nums: Set[bytes] = set()
                            for rel_path, data in messages:
                                try:
                                    found = _legacy_remote_has_message(imap, remote_mailbox, data, used_remote_nums)
                                except Exception as exc:
                                    with mismatches_lock:
                                        validation_errors.append((email, f"{mailbox}: identity check failed for {rel_path}: {exc}"))
                                    continue
                                if not found:
                                    with mismatches_lock:
                                        validation_errors.append((email, f"{mailbox}: remote message identity missing for {rel_path}"))
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
                logging.info("Validation successful: local export matches remote counts and message identities for all accounts.")
        elif args.mode == "audit":
            assert isinstance(config, Config)
            in_root = Path(args.input_dir)
            if in_root.is_symlink():
                logging.error("Input directory is a symlink: %s", in_root)
                return 2
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2
            check_free_space_for_path(in_root, min_free_gb)
            try:
                logging.info("Running audit on %s (%s) ...", in_root, "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                ok, audit_issues = audit_export(
                    in_root,
                    config,
                    int(args.max_workers),
                    check_remote=not bool(getattr(args, "audit_offline", False)),
                    require_integrity_metadata=True,
                )
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
