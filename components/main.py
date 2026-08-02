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
import stat
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
    LEGACY_RESET_STATE_FILENAME,
    LegacyResetGateError,
    _is_legacy_flagged_source_view,
    _legacy_fetch_body_part_matches_sequence,
    _legacy_metadata_for_fetch_body_part,
    _legacy_internaldates_equal,
    _legacy_missing_target_flags,
    _legacy_search_target_uids,
    _legacy_used_uid_key,
    _legacy_used_uid_namespace,
    _maximum_bipartite_matching,
    _normalized_legacy_internaldate,
    _parse_fetch_response_for_uid,
    ensure_private_dir as ensure_legacy_private_dir,
    _fsync_legacy_directory_fd,
    _open_legacy_dir,
    _open_legacy_parent_dir,
    _raise_if_legacy_parent_replaced,
    _legacy_symlink_component,
    _legacy_trusted_covered_by_regular_content,
    _unlink_legacy_entry_and_fsync,
    archive_legacy_import_journal_for_reset as _archive_legacy_import_journal_for_reset,
    export_account,
    import_account,
    legacy_export_output_symlink_issues,
    legacy_global_reset_state_issues,
    legacy_reset_state_issues,
    run_legacy_global_target_action_under_lock,
    run_legacy_target_action_under_import_lock,
)
from .imapsync_cli import run_imapsync_justconnect
from .models import Account, Config, ProviderMigrationConfig, load_config_file
from .gmail_provisioning import (
    gmail_api_client_if_required,
    plan_live_gmail_configuration,
    provision_gmail_filters,
    provision_gmail_labels,
    require_gmail_configuration_plan,
    require_live_gmail_plan_ok,
    verify_gmail_configuration,
)
from .provider_workflow import (
    migration_report_path,
    provider_workflow_terminal_success_committed,
    redact_workflow_diagnostic_secrets,
    run_provider_migration_workflow,
    stop_aware_remote_client,
)
from .secret_files import read_secret_file_no_links
from .provider_ops import (
    ProviderImportIntegrityGateError,
    load_provider_routing_plan,
    provider_audit_all,
    provider_export_all,
    provider_import_all,
    provider_merge_group_identity_collision_issues,
    provider_preflight,
    provider_test_accounts,
    provider_validate_account,
    provider_validate_all,
    provider_workflow_lock,
    _raise_if_provider_path_symlink,
)
from .utils import (
    canonical_imap_mailbox_name,
    canonical_mailbox_path_key,
    check_environment,
    sanitize_for_path,
    sanitized_path_key,
    validate_panel_base_url,
)
from .utils import check_free_space_for_path

# Retain the historical patch seam while reset archiving is now performed by
# `imap_ops.import_account` under the per-target lock.
archive_legacy_import_journal_for_reset = _archive_legacy_import_journal_for_reset


def _utc_log_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _read_required_secret_file(path: str, *, label: str) -> str:
    value = read_secret_file_no_links(path, label=label)
    if not value:
        raise ValueError(f"{label} is empty: {path}")
    return value


def _canonical_reset_confirm_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


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


def _ensure_directadmin_client_dependency() -> None:
    from . import da_client as da_client_module

    if da_client_module.requests is None:  # type: ignore[attr-defined]
        raise RuntimeError("DirectAdmin auto-provisioning requires the 'requests' package. Install it via: pip install -r requirements.txt")


def _ensure_cpanel_client_dependency() -> None:
    from . import cpanel_client as cpanel_client_module

    if cpanel_client_module.requests is None:  # type: ignore[attr-defined]
        raise RuntimeError("cPanel provisioning requires the 'requests' package. Install it via: pip install -r requirements.txt")


def _write_secure_json_file(path: Path, payload: Dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, "secure config file")
    fd = -1
    created = False
    try:
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "secure config file")
        try:
            fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            try:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "secure config file")
            except RuntimeError as replaced_exc:
                raise replaced_exc from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked secure config file: {path}") from exc
            raise
        created = True
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "secure config file")
            _fsync_legacy_directory_fd(parent_fd, parent_path, "secure config file")
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "secure config file")
        except Exception:
            if created:
                _unlink_legacy_entry_and_fsync(parent_fd, name, parent_path, "secure config file")
            raise
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def _message_id_header(data: bytes) -> str:
    try:
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    except Exception:
        return ""


def _legacy_remote_has_message(
    imap,
    mailbox: str,
    data: bytes,
    used_nums: Optional[Set[bytes]] = None,
    expected_flags: str = "",
    expected_internaldate: str = "",
) -> bool:
    from .imap_ops import _imap_append_wire_bytes, quote_mailbox_name

    data = _imap_append_wire_bytes(data)
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    uidvalidity = _legacy_used_uid_namespace(imap)
    message_id = _message_id_header(data)
    expected_hash = hashlib.sha256(data).hexdigest()
    expected_size = len(data)
    search_uids = _legacy_search_target_uids(imap, message_id, mailbox=mailbox)
    if not search_uids:
        return False
    flag_mismatches: List[List[str]] = []
    date_mismatches: List[str] = []
    expected_date = _normalized_legacy_internaldate(expected_internaldate)
    for uid in search_uids:
        uid_token = str(uid).encode("ascii")
        used_key = _legacy_used_uid_key(uidvalidity, uid)
        if used_nums is not None and (used_key in used_nums or uid_token in used_nums):
            continue
        status, fetched = imap.uid("fetch", str(uid), "(UID RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[])")
        if status != "OK":
            continue
        body, actual_flags, actual_date = _parse_fetch_response_for_uid(list(fetched or []), uid)
        if body is None:
            continue
        if len(body) != expected_size or hashlib.sha256(body).hexdigest() != expected_hash:
            continue
        missing_flags = _legacy_missing_target_flags(expected_flags, actual_flags)
        if missing_flags:
            flag_mismatches.append(missing_flags)
            continue
        if expected_date and not _legacy_internaldates_equal(actual_date, expected_date):
            date_mismatches.append(actual_date or "<missing>")
            continue
        if used_nums is not None:
            used_nums.add(used_key)
        return True
    if flag_mismatches:
        missing = sorted({flag for flags in flag_mismatches for flag in flags}, key=str.upper)
        raise RuntimeError("remote flags missing: " + ", ".join(missing))
    if date_mismatches:
        got = ", ".join(sorted(set(date_mismatches)))
        raise RuntimeError(f"remote INTERNALDATE mismatch: expected {expected_date!r} got {got!r}")
    return False


def _legacy_content_identity_variants(data: bytes) -> Set[Tuple[int, str]]:
    from .imap_ops import _imap_append_wire_bytes

    variants = {data, _imap_append_wire_bytes(data)}
    return {(len(candidate), hashlib.sha256(candidate).hexdigest()) for candidate in variants}


def _legacy_virtual_source_attrs(attributes: Tuple[str, ...]) -> bool:
    from .imap_ops import _is_legacy_all_source_view, _is_legacy_flagged_source_view

    return _is_legacy_all_source_view(attributes) or _is_legacy_flagged_source_view(attributes)


_LegacyCoverageSlot = Tuple[Set[Tuple[int, str]], str, str]


def _legacy_identity_variant_slots_cover(
    remote_slots: List[_LegacyCoverageSlot],
    local_slots: List[_LegacyCoverageSlot],
    *,
    required_flags: str = "",
    require_all_local: bool = False,
) -> bool:
    required_local_indexes = {
        idx
        for idx, (_local_identities, local_flags, _local_internaldate) in enumerate(local_slots)
        if not required_flags or not _legacy_missing_target_flags(required_flags, local_flags)
    }
    if not remote_slots and (required_local_indexes if required_flags else local_slots):
        return False
    if require_all_local and len(remote_slots) < len(required_local_indexes):
        return False
    if len(remote_slots) > len(local_slots):
        return False
    edges: List[List[int]] = []
    for remote_identities, remote_flags, remote_internaldate in remote_slots:
        if required_flags and _legacy_missing_target_flags(required_flags, remote_flags):
            return False
        matches = [
            idx
            for idx, (local_identities, local_flags, local_internaldate) in enumerate(local_slots)
            if remote_identities & local_identities
            and not (required_flags and _legacy_missing_target_flags(required_flags, local_flags))
            and not (
                required_flags
                and _normalized_legacy_internaldate(remote_internaldate)
                and _normalized_legacy_internaldate(local_internaldate)
                and not _legacy_internaldates_equal(remote_internaldate, local_internaldate)
            )
        ]
        if not matches:
            return False
        edges.append(matches)
    matched_count, matched_local_indexes = _maximum_bipartite_matching(edges, len(local_slots))
    if matched_count != len(remote_slots):
        return False
    if require_all_local and not required_local_indexes.issubset(matched_local_indexes):
        return False
    return True


def _legacy_remote_mailbox_content_covered(
    imap,
    mailbox: str,
    local_identity_slots: List[_LegacyCoverageSlot],
    *,
    required_flags: str = "",
    require_all_local: bool = False,
) -> bool:
    from .imap_ops import quote_mailbox_name

    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    status, search_data = imap.search(None, "ALL")
    if status != "OK":
        return False
    nums = search_data[0].split() if search_data and search_data[0] else []
    remote_slots: List[_LegacyCoverageSlot] = []
    fetch_query = "(RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[])" if required_flags else "(RFC822.SIZE BODY.PEEK[])"
    for num in nums:
        status, fetched = imap.fetch(num, fetch_query)
        if status != "OK":
            return False
        fetched_parts = list(fetched or [])
        remote_identities: Set[Tuple[int, str]] = set()
        body_part_index: Optional[int] = None
        for index, part in enumerate(fetched_parts):
            if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
                continue
            if not _legacy_fetch_body_part_matches_sequence(part, num):
                continue
            if body_part_index is None:
                body_part_index = index
            remote_identities.update(_legacy_content_identity_variants(bytes(part[1])))
        if not remote_identities:
            return False
        actual_flags, actual_date = _legacy_metadata_for_fetch_body_part(fetched_parts, body_part_index)
        remote_slots.append((
            remote_identities,
            actual_flags or "",
            actual_date or "",
        ))
    return _legacy_identity_variant_slots_cover(
        remote_slots,
        local_identity_slots,
        required_flags=required_flags,
        require_all_local=require_all_local,
    )


def setup_logging(log_directory: Path) -> Path:
    """Initialize root logger with file + stderr handlers and return log path."""
    ensure_legacy_private_dir(log_directory, label="log directory")
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
    log_dir_fd: Optional[int] = None
    try:
        log_dir_fd, log_dir_path = _open_legacy_dir(log_directory, "log directory")
        for attempt in range(100):
            suffix = "" if attempt == 0 else f"-{attempt}"
            name = f"run-{timestamp}{suffix}.log"
            candidate = log_directory / name
            try:
                _raise_if_legacy_parent_replaced(log_dir_path, log_dir_fd, "log directory")
                opened_fd = os.open(name, flags, 0o600, dir_fd=log_dir_fd)
                try:
                    _raise_if_legacy_parent_replaced(log_dir_path, log_dir_fd, "log directory")
                except Exception:
                    os.close(opened_fd)
                    raise
                log_fd = opened_fd
            except FileExistsError:
                continue
            except OSError as exc:
                try:
                    _raise_if_legacy_parent_replaced(log_dir_path, log_dir_fd, "log directory")
                except RuntimeError as replaced_exc:
                    raise replaced_exc from exc
                if exc.errno in {errno.ELOOP, errno.EMLINK} or candidate.is_symlink():
                    raise RuntimeError(f"refusing to use symlinked log file: {candidate}") from exc
                raise
            log_file = candidate
            break
        if log_file is None or log_fd is None:
            raise RuntimeError(f"could not create a unique log file in {log_directory}")
    finally:
        if log_dir_fd is not None:
            os.close(log_dir_fd)
    os.fchmod(log_fd, 0o600)
    fh = logging.StreamHandler(os.fdopen(log_fd, "a", encoding="utf-8"))
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.info("Logging initialized. File: %s", str(log_file))
    return log_file


def _log_provider_workflow_result(context: str, report: Dict[str, object]) -> None:
    issues = report.get("issues")
    issue_count = len(issues) if isinstance(issues, list) else 0
    logging.info(
        "%s summary | status=%s | ok=%s | dry_run=%s | issues=%d",
        context,
        report.get("status", "unknown"),
        bool(report.get("ok")),
        bool(report.get("dry_run")),
        issue_count,
    )
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, str) and issue:
                logging.error("%s issue | %s", context, _safe_workflow_log_text(issue))
    for key, label in (
        ("report_write_error", "report write error"),
        ("report_removal_error", "report removal error"),
    ):
        error = report.get(key)
        if isinstance(error, str) and error:
            logging.error(
                "%s %s | %s",
                context,
                label,
                _safe_workflow_log_text(error),
            )
    durability_warning = report.get("report_durability_uncertain")
    if isinstance(durability_warning, str) and durability_warning:
        logging.warning(
            "%s report durability uncertain | %s",
            context,
            _safe_workflow_log_text(durability_warning),
        )
    quarantine = report.get("report_quarantine")
    if isinstance(quarantine, str) and quarantine:
        logging.warning(
            "%s non-authoritative cancelled-report quarantine | %s",
            context,
            _safe_workflow_log_text(quarantine),
        )
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict):
        return
    for key, filename in (
        ("routing_plan", "routing-plan.json"),
        ("gmail_configuration_plan", "gmail-configuration-plan.json"),
        ("workspace_alias_plan", "workspace-alias-plan.json"),
        ("report", "migration report"),
    ):
        path = artifacts.get(key)
        if key == "report" and (
            report.get("report_persisted") is False
            or bool(report.get("report_write_error"))
        ):
            continue
        if path:
            logging.info(
                "%s artifact | %s=%s",
                context,
                filename,
                _safe_workflow_log_text(str(path)),
            )


def _redact_workflow_log_secrets(value: str) -> str:
    """Redact common credential forms without depending on exact casing."""

    return redact_workflow_diagnostic_secrets(value)


def _safe_workflow_log_text(value: str, *, limit: int = 2000) -> str:
    """Redact secrets and keep workflow diagnostics on one bounded log line."""

    value = _redact_workflow_log_secrets(value)
    escaped = "".join(
        character
        if character >= " " and character != "\x7f"
        else f"\\x{ord(character):02x}"
        for character in value
    )
    if len(escaped) <= limit:
        return escaped
    return escaped[:limit] + "...[truncated]"


def test_accounts(
    config: Config,
    max_workers: int,
    *,
    imap_timeout: float = 30.0,
    stop_event: Optional[object] = None,
) -> None:
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    import concurrent.futures
    import queue
    errors: queue.Queue[str] = queue.Queue()
    from .imap_ops import imap_connection

    def stop_requested() -> bool:
        return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())

    def raise_if_stopped(label: str) -> None:
        if stop_requested():
            raise RuntimeError(f"{label}: stop requested before completion")

    def worker(acc: Account) -> None:
        try:
            raise_if_stopped(f"connectivity test {acc.email}")
            # Properly open and logout via the context manager
            with imap_connection(config.server, acc):
                pass
            raise_if_stopped(f"connectivity test {acc.email}")
            ok, out = run_imapsync_justconnect(
                host=config.server.host,
                port=config.server.port,
                ssl_enabled=config.server.ssl,
                starttls=config.server.starttls,
                user=acc.email,
                password=acc.password,
                timeout_sec=imap_timeout,
                stop_event=stop_event,
            )
            raise_if_stopped(f"connectivity test {acc.email}")
            if not ok:
                raise RuntimeError(f"imapsync justconnect failed for {acc.email}:\n{out}")
            logging.info("[test] %s: OK", acc.email)
        except Exception as exc:
            logging.error("[test] %s: FAILED: %s", acc.email, exc)
            errors.put(f"{acc.email}: {exc}")
            if stop_requested():
                raise

    account_iter = iter(config.accounts)
    futures: Dict[concurrent.futures.Future[None], Account] = {}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="test")
    wait_timeout = 0.2 if stop_event is not None else None

    def submit_next() -> bool:
        if stop_requested():
            return False
        try:
            acc = next(account_iter)
        except StopIteration:
            return False
        futures[executor.submit(worker, acc)] = acc
        return True

    try:
        for _ in range(min(max_workers, len(config.accounts))):
            if not submit_next():
                break
        while futures:
            raise_if_stopped("connectivity tests")
            done, _pending = concurrent.futures.wait(
                futures,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            completed_successfully = 0
            for fut in done:
                futures.pop(fut, None)
                fut.result()
                completed_successfully += 1
                raise_if_stopped("connectivity tests")
            for _ in range(completed_successfully):
                submit_next()
        raise_if_stopped("connectivity tests")
    finally:
        if stop_requested():
            for fut in futures:
                fut.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        else:
            executor.shutdown(wait=True)

    if not errors.empty():
        reason_lines: List[str] = []
        while not errors.empty():
            try:
                reason_lines.append(errors.get_nowait())
            except Exception:
                break
        raise RuntimeError("Connectivity test failed for some accounts:\n" + "\n".join(reason_lines))


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


def _empty_panel_account_passwords(config: Config) -> List[str]:
    return [acc.email for acc in config.accounts if not acc.password]


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
                if (
                    path.parent == account_dir
                    and path.name == LEGACY_RESET_STATE_FILENAME
                ):
                    # The reset gate owns this reserved artifact and maps its
                    # fail-closed security diagnostics to the integrity-gate
                    # exit class rather than generic staged-path setup.
                    continue
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
    routing_plan = None
    if config.migration.routing.enabled:
        try:
            routing_plan = load_provider_routing_plan(root, config)
            require_gmail_configuration_plan(root, config, routing_plan)
        except Exception as exc:
            return [f"routing plan validation failed: {exc}"]
    for account in config.accounts:
        _name, report = provider_validate_account(
            config,
            account,
            root,
            check_target=False,
            write_report=False,
            allow_unresolved_pending=(mode == "import"),
            # Direct import invokes this gate while holding the root workflow
            # lock. Repairing an interrupted final append here is therefore
            # serialized and lets the immutable journal rows be validated
            # before any Gmail mutation.
            repair_trailing_journal=(mode == "import"),
            allow_missing_gmail_target_msgid=(mode == "import"),
            routing_plan=routing_plan,
            include_journal=True,
        )
        keys = ("duplicates", "failed", "missing") if mode == "validate" else ("duplicates", "failed")
        for key in keys:
            for item in report.get(key, []):
                issues.append(f"{account.source_email}: {key}: {item}")
    if mode == "import":
        issues.extend(provider_merge_group_identity_collision_issues(config, root))
    return issues


def _legacy_pending_import_journal_issues(root: Path, config: Config, *, repair_trailing: bool = False) -> List[str]:
    from .imap_ops import _legacy_import_target_id, _load_legacy_import_journal, _unresolved_legacy_pending_keys

    issues: List[str] = []
    for account in config.accounts:
        account_dir = root / sanitize_for_path(account.email)
        if not account_dir.exists():
            continue
        try:
            pending_keys = _unresolved_legacy_pending_keys(
                _load_legacy_import_journal(account_dir, repair_trailing=repair_trailing),
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


def _legacy_audit_export_with_target_locks(
    in_root: Path,
    config: Config,
    max_workers: int,
    *,
    check_remote: bool,
    require_integrity_metadata: bool,
    stop_event: Optional[object],
) -> Tuple[bool, List[str]]:
    """Run remote legacy audit work per account behind the global target gate."""

    if not check_remote:
        return audit_export(
            in_root,
            config,
            max_workers,
            check_remote=False,
            require_integrity_metadata=require_integrity_metadata,
            stop_event=stop_event,
        )

    remote_server = config.source_server or config.server
    collected: List[str] = []
    collected_lock = threading.Lock()

    def audit_one(acc: Account) -> None:
        single_config = Config(
            server=config.server,
            accounts=[acc],
            source_server=config.source_server,
        )
        result: List[Tuple[bool, List[str]]] = []

        def remote_audit_action() -> None:
            result.append(
                audit_export(
                    in_root,
                    single_config,
                    1,
                    check_remote=True,
                    require_integrity_metadata=require_integrity_metadata,
                    stop_event=stop_event,
                )
            )

        try:
            run_legacy_target_action_under_import_lock(
                acc,
                remote_server,
                in_root,
                remote_audit_action,
                stop_event=stop_event,
                allow_unrelated_local_target=True,
            )
            if not result:
                raise RuntimeError("locked remote audit produced no result")
            ok, account_issues = result[0]
            if ok:
                return
            with collected_lock:
                collected.extend(account_issues)
        except Exception as exc:
            if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                raise
            with collected_lock:
                collected.append(f"{acc.email}: locked remote audit failed: {exc}")

    parallel_process_accounts(
        "audit",
        audit_one,
        config.accounts,
        max_workers,
        stop_on_error=False,
        stop_event=stop_event,
    )
    return not collected, collected


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk export/import/validate IMAP mailboxes with legacy and provider-aware workflows.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", required=True, choices=["export", "import", "test", "validate", "audit", "preflight", "migrate"], help="Operation mode")
    parser.add_argument("--config", required=False, help="Path to JSON config file with server and accounts")
    parser.add_argument("--output-dir", default=str(Path.cwd() / "exported"), help="Directory to write exported data")
    parser.add_argument("--input-dir", default=str(Path.cwd() / "exported"), help="Directory to read exported data for import/validate")
    parser.add_argument("--max-workers", type=int, default=max(4, (os.cpu_count() or 4)), help="Parallel worker threads for accounts")
    parser.add_argument("--ignore-errors", action="store_true", help="Continue other accounts on errors")
    parser.add_argument("--log-dir", default=str(Path.cwd() / "logs"), help="Directory to store log files")
    parser.add_argument("--min-free-gb", type=float, default=1.0, help="Fail-fast if free disk space is lower")
    parser.add_argument("--resync-missing", action="store_true", help="Deprecated; validation reports missing messages without automatic APPEND replay")
    parser.add_argument("--no-audit-after-export", action="store_true", help="Do not run audit automatically after export")
    parser.add_argument(
        "--no-connectivity-test",
        action="store_true",
        help="Skip connectivity tests (not valid with test or preflight modes)",
    )
    parser.add_argument("--audit-offline", action="store_true", help="Do not contact IMAP server during audit; perform local-only checks")
    parser.add_argument("--imap-timeout", type=float, default=60.0, help="Default IMAP socket timeout in seconds")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Provider preflight/migrate only: discover and persist plans without remote mutations",
    )
    parser.add_argument(
        "--report-file",
        required=False,
        help="Provider preflight/migrate report path inside --output-dir (defaults to migration-report.json)",
    )

    parser.add_argument("--auto-provision-da", action="store_true", help="In import mode, if accounts don't exist on the panel, auto-create them via DirectAdmin API before tests and import")
    parser.add_argument("--reset", action="store_true", help="Import mode only: delete and recreate each mailbox on the panel before importing")
    parser.add_argument("--reset-confirm", required=False, help="Required for non-dry-run --reset; must match the target IMAP host or be YES")
    parser.add_argument("--da-url", required=False, help="DirectAdmin HTTPS base URL (literal loopback HTTP is also allowed)")
    parser.add_argument("--da-username", required=False, help="DirectAdmin API username")
    parser.add_argument("--da-password", required=False, help="DirectAdmin API password or login key; insecure because process args can expose it")
    parser.add_argument("--da-password-file", required=False, help="Path to a file containing the DirectAdmin API password or login key")
    parser.add_argument("--da-password-env", required=False, help="Environment variable containing the DirectAdmin API password or login key")
    parser.add_argument("--da-no-verify-ssl", action="store_true", help="Disable TLS certificate verification for DirectAdmin API")
    parser.add_argument("--da-dry-run", action="store_true", help="Show what would be created without making changes")
    parser.add_argument("--da-quota-mb", type=int, default=0, help="New mailbox quota in MiB (0 = unlimited)")

    parser.add_argument("--auto-provision-cpanel", action="store_true", help="In import mode, auto-create/reset missing target mailboxes via cPanel UAPI")
    parser.add_argument("--cpanel-url", required=False, help="cPanel HTTPS base URL (literal loopback HTTP is also allowed)")
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
    if args.mode in {"test", "preflight", "migrate"} and bool(getattr(args, "no_connectivity_test", False)):
        logging.error("--no-connectivity-test cannot be used with --mode %s", args.mode)
        return 2
    if bool(getattr(args, "dry_run", False)) and args.mode not in {"preflight", "migrate"}:
        logging.error("--dry-run is valid only with --mode preflight or --mode migrate")
        return 2
    if getattr(args, "report_file", None) and args.mode not in {"preflight", "migrate"}:
        logging.error("--report-file is valid only with --mode preflight or --mode migrate")
        return 2
    if getattr(args, "report_file", None):
        try:
            migration_report_path(Path(args.output_dir), Path(args.report_file))
        except ValueError as exc:
            logging.error("Invalid --report-file: %s", exc)
            return 2
    if args.mode == "migrate" and bool(getattr(args, "no_audit_after_export", False)):
        logging.error("--no-audit-after-export is not valid with --mode migrate; the audited workflow cannot skip audit")
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
        "migrate": "migration.config.json",
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
    if args.mode == "migrate" and not is_provider_config:
        logging.error("--mode migrate requires a provider source/target config")
        return 2
    if is_provider_config:
        assert isinstance(config, ProviderMigrationConfig)
        if getattr(args, "report_file", None):
            try:
                migration_report_path(
                    Path(args.output_dir),
                    Path(args.report_file),
                    config=config,
                )
            except ValueError as exc:
                logging.error("Invalid --report-file: %s", exc)
                return 2
        if config.target.workspace_aliases.enabled and args.mode in {
            "export",
            "import",
            "validate",
        }:
            logging.error(
                "Alias-enabled provider %s is migrate-only: use --mode migrate with the same "
                "staging directory so Gmail filters are verified before alias provisioning and "
                "Workspace alias ownership is included in final validation",
                args.mode,
            )
            return 2
    use_da_panel = bool(getattr(args, "auto_provision_da", False))
    use_cpanel = bool(getattr(args, "auto_provision_cpanel", False))
    legacy_staged_audit_completed = False
    free_space_checked_paths: Set[Path] = set()
    stop_event = threading.Event()

    def handle_sig(signum, _frame):
        stop_event.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, handle_sig)
        signal.signal(signal.SIGTERM, handle_sig)

    def stop_requested_result(label: str) -> Optional[int]:
        if not stop_event.is_set():
            return None
        logging.warning("%s: stop requested before completion", label)
        return 130

    def provider_workflow_stop_result(
        label: str,
        report: Dict[str, object],
    ) -> Optional[int]:
        if (
            stop_event.is_set()
            and provider_workflow_terminal_success_committed(report)
        ):
            logging.info(
                "%s: stop requested after terminal success commit; preserving success",
                label,
            )
            return None
        return stop_requested_result(label)

    def provider_target_connectivity_result() -> Optional[int]:
        assert isinstance(config, ProviderMigrationConfig)
        if bool(getattr(args, "no_connectivity_test", False)):
            logging.info("Skipping connectivity tests due to --no-connectivity-test")
            return stop_requested_result("provider connectivity tests")
        try:
            logging.info("Running provider connectivity tests (roles=target) ...")
            provider_test_accounts(
                config,
                max_workers=int(args.max_workers),
                roles=("target",),
                stop_event=stop_event,
            )
            logging.info("Connectivity tests passed for all accounts")
        except Exception as exc:
            if stop_event.is_set():
                logging.warning("Connectivity tests stopped: %s", exc)
                return 130
            logging.error("Connectivity tests failed: %s", exc)
            return 3
        return stop_requested_result("provider connectivity tests")

    def provider_locked_input_preflight_result(root: Path, mode: str) -> Optional[int]:
        assert isinstance(config, ProviderMigrationConfig)
        provider_local_issues = _provider_cli_local_root_issues(
            root,
            config,
            label=mode,
            require_exists=True,
        )
        if not provider_local_issues:
            return None
        logging.error("Provider %s input failed local preflight:", mode)
        for issue in provider_local_issues:
            logging.error("[provider-local] %s", issue)
        return 2

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
        and not is_provider_config
        and (use_da_panel or use_cpanel)
        and not panel_dry_run_requested
    ):
        assert isinstance(config, Config)
        empty_panel_passwords = _empty_panel_account_passwords(config)
        if empty_panel_passwords:
            logging.error(
                "Control-panel provisioning requires a non-empty accounts[].password before making changes; "
                "populate the password for: %s",
                ", ".join(empty_panel_passwords),
            )
            return 2
    if (
        args.mode == "import"
        and bool(getattr(args, "reset", False))
        and not (bool(getattr(args, "auto_provision_da", False)) and bool(getattr(args, "da_dry_run", False)))
        and not (bool(getattr(args, "auto_provision_cpanel", False)) and bool(getattr(args, "cpanel_dry_run", False)))
    ):
        target_host = config.target.host if isinstance(config, ProviderMigrationConfig) else config.server.host
        reset_confirm = str(getattr(args, "reset_confirm", "") or "")
        if reset_confirm != "YES" and _canonical_reset_confirm_host(reset_confirm) != _canonical_reset_confirm_host(target_host):
            logging.error("--reset-confirm must match target IMAP host %r or be YES for non-dry-run --reset", target_host)
            return 2
    if args.mode in {"import", "validate", "audit"}:
        input_root = Path(args.input_dir)
        if is_provider_config:
            try:
                _raise_if_provider_path_symlink(input_root, f"{args.mode} root")
            except RuntimeError as exc:
                logging.error("Provider %s input failed local preflight: %s", args.mode, exc)
                return 2
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
    provider_plan_output_mode = bool(
        is_provider_config
        and isinstance(config, ProviderMigrationConfig)
        and (
            config.migration.routing.enabled
            or config.target.workspace_aliases.enabled
            or bool(getattr(args, "report_file", None))
        )
        and args.mode == "preflight"
    )
    if args.mode in {"export", "migrate"} or provider_plan_output_mode:
        output_root = Path(args.output_dir)
        if is_provider_config:
            assert isinstance(config, ProviderMigrationConfig)
            provider_local_issues = _provider_cli_local_root_issues(
                output_root,
                config,
                label=args.mode,
                require_exists=False,
            )
            if provider_local_issues:
                logging.error("Provider %s output failed local preflight:", args.mode)
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
    if args.mode in {"export", "migrate"} or provider_plan_output_mode:
        free_space_preflight_path = Path(args.output_dir)
    elif args.mode in {"import", "validate", "audit"}:
        free_space_preflight_path = Path(args.input_dir)
    if free_space_preflight_path is not None:
        try:
            check_free_space_for_path(free_space_preflight_path, min_free_gb)
        except Exception as exc:
            logging.error("Free-space check failed before connectivity: %s", exc)
            return 2
        free_space_checked_paths.add(free_space_preflight_path)

    da_client: Optional[DirectAdminClient] = None
    da_password: Optional[str] = None
    cpanel_client: Optional[CPanelClient] = None
    cpanel_password: Optional[str] = None
    cpanel_token: Optional[str] = None
    panel_reset_failed_accounts: set[str] = set()
    legacy_reset_gate_failed_accounts: set[str] = set()
    legacy_connectivity_failed_accounts: set[str] = set()
    panel_reset_failed_accounts_lock = threading.Lock()

    if (not is_provider_config) and args.mode == "import" and (use_da_panel or use_cpanel):
        assert isinstance(config, Config)
        invalid_panel_accounts = _invalid_panel_account_emails(config)
        if invalid_panel_accounts:
            logging.error(
                "Control-panel provisioning requires mailbox accounts in local@domain form; invalid account(s): %s",
                ", ".join(invalid_panel_accounts),
            )
            return 2
        staged_root = Path(args.input_dir)
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
        if use_da_panel:
            missing = [name for name in ("da_url", "da_username") if not getattr(args, name)]
            if missing:
                logging.error(
                    "DirectAdmin auto-provisioning requires: --da-url, --da-username, and a password source "
                    "(missing: %s)",
                    ", ".join(missing),
                )
                return 2
            try:
                validate_panel_base_url(str(args.da_url), label="DirectAdmin")
                da_password = _resolve_da_password(args)
                _ensure_directadmin_client_dependency()
            except Exception as exc:
                logging.error("[da] Auto-provisioning setup failed: %s", exc)
                return 2
        if use_cpanel:
            missing = [name for name in ("cpanel_url", "cpanel_username") if not getattr(args, name)]
            if missing:
                logging.error(
                    "cPanel auto-provisioning requires: --cpanel-url, --cpanel-username, and a password/token "
                    "source (missing: %s)",
                    ", ".join(missing),
                )
                return 2
            try:
                validate_panel_base_url(str(args.cpanel_url), label="cPanel")
                cpanel_password, cpanel_token = _resolve_cpanel_auth(args)
                _ensure_cpanel_client_dependency()
            except Exception as exc:
                logging.error("[cpanel] Auto-provisioning setup failed: %s", exc)
                return 2

    legacy_remote_audit = bool(
        args.mode == "audit"
        and not is_provider_config
        and not bool(getattr(args, "audit_offline", False))
    )
    if not is_provider_config and (
        args.mode in {"import", "validate"} or legacy_remote_audit
    ):
        assert isinstance(config, Config)
        gate_server = config.server
        if legacy_remote_audit and config.source_server is not None:
            gate_server = config.source_server
        reset_state_gate_issues = legacy_reset_state_issues(
            Path(args.input_dir),
            config.accounts,
            gate_server,
            allow_resume=(args.mode == "import" and bool(getattr(args, "reset", False))),
            allow_unrelated_local_target=legacy_remote_audit,
        )
        if reset_state_gate_issues:
            logging.error("Input directory has unresolved legacy reset state:")
            for issue in reset_state_gate_issues:
                logging.error("[reset-state] %s", issue)
            if not (args.mode == "import" and bool(args.ignore_errors)):
                return 4
            logging.warning(
                "--ignore-errors is set; independent accounts will continue, "
                "and each account will recheck reset state under its target lock"
            )

    legacy_global_only_target_work = bool(
        not is_provider_config
        and (
            args.mode == "export"
            or (
                args.mode == "test"
                and not bool(getattr(args, "no_connectivity_test", False))
            )
        )
    )
    if legacy_global_only_target_work:
        assert isinstance(config, Config)
        global_gate_issues = legacy_global_reset_state_issues(
            config.accounts,
            config.server,
        )
        if global_gate_issues:
            logging.error("Legacy %s has unresolved global reset state:", args.mode)
            for issue in global_gate_issues:
                logging.error("[reset-state] %s", issue)
            if not bool(args.ignore_errors):
                return 4
            logging.warning(
                "--ignore-errors is set; independent accounts will continue, "
                "and each account will recheck global reset state under its target lock"
            )

    # Provider staged validation is intentionally deferred to the command's
    # root workflow lock below. Legacy validation remains an unlocked,
    # fail-fast pre-connectivity check because it does not share provider
    # generation state.
    if args.mode in {"import", "validate"} and not is_provider_config:
        input_root = Path(args.input_dir)
        assert isinstance(config, Config)
        if not use_da_panel and not use_cpanel:
            try:
                logging.info("Running strict local staged export audit before connectivity...")
                ok, staged_audit_issues = audit_export(
                    input_root,
                    config,
                    int(args.max_workers),
                    check_remote=False,
                    require_integrity_metadata=True,
                    stop_event=stop_event,
                )
            except Exception as exc:
                if stop_event.is_set():
                    logging.warning("Staged export audit stopped: %s", exc)
                    return 130
                logging.error("Staged export audit failed before connectivity: %s", exc)
                return 4
            stop_rc = stop_requested_result("staged export audit")
            if stop_rc is not None:
                return stop_rc
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
        if args.mode == "validate":
            pending_journal_issues = _legacy_pending_import_journal_issues(
                input_root,
                config,
                repair_trailing=False,
            )
            if pending_journal_issues:
                logging.error("Input directory has unresolved legacy import journal entries:")
                for issue in pending_journal_issues:
                    logging.error("[staged-journal] %s", issue)
                return 4

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

    if (not is_provider_config) and args.mode == "import" and (use_da_panel or use_cpanel):
        staged_root = Path(args.input_dir)
        assert isinstance(config, Config)
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
                stop_event=stop_event,
            )
        except Exception as exc:
            if stop_event.is_set():
                logging.warning("[panel] Staged export audit stopped: %s", exc)
                return 130
            logging.error("[panel] Staged export audit failed before panel changes: %s", exc)
            return 4
        stop_rc = stop_requested_result("panel staged audit")
        if stop_rc is not None:
            return stop_rc
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
        try:
            assert da_password is not None
            logging.info("[da] Initializing control-panel client...")
            da_client = DirectAdminClient(
                base_url=str(args.da_url),
                username=str(args.da_username),
                password=da_password,
                verify_ssl=not bool(args.da_no_verify_ssl),
            )
            if bool(getattr(args, "reset", False)):
                if not bool(args.da_dry_run):
                    logging.info(
                        "[da] Reset requested: each mailbox will be deleted and recreated "
                        "under its import lock"
                    )
            else:
                logging.info(
                    "[da] Each mailbox will be checked/provisioned under its import lock%s",
                    " (dry-run)" if bool(args.da_dry_run) else "",
                )
        except Exception as exc:
            logging.error("[da] Auto-provisioning failed: %s", exc)
            if stop_event.is_set():
                return 130
            return 3
    if (not is_provider_config) and args.mode == "import" and use_cpanel:
        try:
            assert cpanel_password is not None or cpanel_token is not None
            logging.info("[cpanel] Initializing control-panel client...")
            cpanel_client = CPanelClient(
                base_url=str(args.cpanel_url),
                username=str(args.cpanel_username),
                password=cpanel_password,
                token=cpanel_token,
                verify_ssl=not bool(args.cpanel_no_verify_ssl),
            )
            if bool(getattr(args, "reset", False)):
                if not bool(args.cpanel_dry_run):
                    logging.info(
                        "[cpanel] Reset requested: each mailbox will be deleted and recreated "
                        "under its import lock"
                    )
            else:
                logging.info(
                    "[cpanel] Each mailbox will be checked/provisioned under its import lock%s",
                    " (dry-run)" if bool(args.cpanel_dry_run) else "",
                )
        except Exception as exc:
            logging.error("[cpanel] Auto-provisioning failed: %s", exc)
            if stop_event.is_set():
                return 130
            return 3
    stop_rc = stop_requested_result("panel setup")
    if stop_rc is not None:
        return stop_rc
    if args.mode == "import" and (
        (use_da_panel and bool(getattr(args, "da_dry_run", False)))
        or (use_cpanel and bool(getattr(args, "cpanel_dry_run", False)))
    ):
        assert isinstance(config, Config)
        staged_root = Path(args.input_dir)

        def do_locked_panel_dry_run(acc: Account) -> None:
            single_account_config = Config(
                server=config.server,
                accounts=[acc],
                source_server=config.source_server,
            )

            def panel_dry_run_action() -> None:
                if use_da_panel:
                    assert da_client is not None
                    if bool(getattr(args, "reset", False)):
                        from .da_ensure import reset_accounts_directadmin

                        failed = reset_accounts_directadmin(
                            single_account_config,
                            da_client,
                            dry_run=True,
                            ignore_errors=bool(args.ignore_errors),
                            quota_mb=int(args.da_quota_mb),
                            stop_event=stop_event,
                        )
                    else:
                        failed = ensure_accounts_exist_directadmin(
                            single_account_config,
                            da_client,
                            dry_run=True,
                            ignore_errors=bool(args.ignore_errors),
                            quota_mb=int(args.da_quota_mb),
                            stop_event=stop_event,
                        )
                else:
                    assert cpanel_client is not None
                    if bool(getattr(args, "reset", False)):
                        from .cpanel_ensure import reset_accounts_cpanel

                        failed = reset_accounts_cpanel(
                            single_account_config,
                            cpanel_client,
                            dry_run=True,
                            ignore_errors=bool(args.ignore_errors),
                            quota_mb=int(args.cpanel_quota_mb),
                            stop_event=stop_event,
                        )
                    else:
                        failed = ensure_accounts_exist_cpanel(
                            single_account_config,
                            cpanel_client,
                            dry_run=True,
                            ignore_errors=bool(args.ignore_errors),
                            quota_mb=int(args.cpanel_quota_mb),
                            stop_event=stop_event,
                        )
                if acc.email in set(failed or ()):
                    raise RuntimeError(f"panel dry-run failed for {acc.email}")

            try:
                run_legacy_target_action_under_import_lock(
                    acc,
                    config.server,
                    staged_root,
                    panel_dry_run_action,
                    stop_event=stop_event,
                    allow_reset_resume=bool(getattr(args, "reset", False)),
                )
            except LegacyResetGateError:
                with panel_reset_failed_accounts_lock:
                    legacy_reset_gate_failed_accounts.add(acc.email)
                if not bool(args.ignore_errors):
                    raise
            except Exception:
                if stop_event.is_set():
                    raise
                with panel_reset_failed_accounts_lock:
                    panel_reset_failed_accounts.add(acc.email)
                if not bool(args.ignore_errors):
                    raise

        try:
            parallel_process_accounts(
                "panel-dry-run",
                do_locked_panel_dry_run,
                config.accounts,
                int(args.max_workers),
                stop_on_error=not bool(args.ignore_errors),
                stop_event=stop_event,
            )
        except LegacyResetGateError as exc:
            logging.error("[reset-state] Panel dry-run blocked: %s", exc)
            return 4
        except Exception as exc:
            if stop_event.is_set():
                logging.warning("[panel][dry-run] Stopped: %s", exc)
                return 130
            logging.error("[panel][dry-run] Failed: %s", exc)
            return 3
        if legacy_reset_gate_failed_accounts:
            logging.error(
                "[reset-state] Panel dry-run blocked for: %s",
                ", ".join(sorted(legacy_reset_gate_failed_accounts)),
            )
            return 4
        if panel_reset_failed_accounts:
            logging.error(
                "[panel][dry-run] Failed for: %s",
                ", ".join(sorted(panel_reset_failed_accounts)),
            )
            return 3
        logging.info("[panel][dry-run] Skipping connectivity tests and IMAP import because panel dry-run was requested")
        return 0

    reset_under_import_lock = bool(
        args.mode == "import"
        and not is_provider_config
        and bool(getattr(args, "reset", False))
    )
    legacy_target_connectivity_under_account_lock = bool(
        args.mode in {"export", "import", "test", "validate"}
        and not is_provider_config
    )
    provider_connectivity_under_root_lock = bool(
        is_provider_config and args.mode in {"import", "validate"}
    )
    if (
        args.mode in {"export", "import", "test", "validate"}
        and not bool(getattr(args, "no_connectivity_test", False))
        and not legacy_target_connectivity_under_account_lock
        and not provider_connectivity_under_root_lock
    ):
        try:
            if is_provider_config:
                if args.mode == "export":
                    roles = ("source",)
                elif args.mode in {"import", "validate"}:
                    roles = ("target",)
                else:
                    roles = ("source", "target")
                logging.info("Running provider connectivity tests (roles=%s) ...", ",".join(roles))
                provider_test_accounts(config, max_workers=int(args.max_workers), roles=roles, stop_event=stop_event)
            else:
                logging.info("Running connectivity tests (imaplib + imapsync --justconnect) ...")
                assert isinstance(config, Config)
                connectivity_config = config
                if args.mode == "import" and panel_reset_failed_accounts:
                    active_accounts = [acc for acc in config.accounts if acc.email not in panel_reset_failed_accounts]
                    skipped = len(config.accounts) - len(active_accounts)
                    logging.info(
                        "[panel] Skipping connectivity tests for %d account(s) whose control-panel setup failed",
                        skipped,
                    )
                    connectivity_config = Config(server=config.server, accounts=active_accounts, source_server=config.source_server)
                test_accounts(connectivity_config, max_workers=int(args.max_workers), imap_timeout=imap_timeout, stop_event=stop_event)
            logging.info("Connectivity tests passed for all accounts")
        except Exception as exc:
            if stop_event.is_set():
                logging.warning("Connectivity tests stopped: %s", exc)
                return 130
            logging.error("Connectivity tests failed: %s", exc)
            return 3
    elif (
        args.mode in {"export", "import", "test", "validate"}
        and not provider_connectivity_under_root_lock
    ):
        if reset_under_import_lock:
            logging.info(
                "Skipping pre-reset target connectivity tests; each recreated mailbox "
                "is authenticated by its locked import"
            )
        elif legacy_target_connectivity_under_account_lock and not bool(
            getattr(args, "no_connectivity_test", False)
        ):
            logging.info(
                "Legacy %s connectivity tests will run per account under each target lock",
                args.mode,
            )
        else:
            logging.info("Skipping connectivity tests due to --no-connectivity-test")

    if not provider_connectivity_under_root_lock:
        stop_rc = stop_requested_result("connectivity tests")
        if stop_rc is not None:
            return stop_rc

    try:
        stop_rc = stop_requested_result(args.mode)
        if stop_rc is not None:
            return stop_rc
        if is_provider_config:
            assert isinstance(config, ProviderMigrationConfig)
            if args.mode == "migrate":
                workflow_root = Path(args.output_dir)
                workflow_report = run_provider_migration_workflow(
                    config,
                    workflow_root,
                    max_workers=int(args.max_workers),
                    ignore_errors=bool(args.ignore_errors),
                    dry_run=bool(getattr(args, "dry_run", False)),
                    stop_event=stop_event,
                    report_path=(
                        Path(args.report_file)
                        if getattr(args, "report_file", None)
                        else None
                    ),
                )
                _log_provider_workflow_result("Provider migrate", workflow_report)
                stop_rc = provider_workflow_stop_result(
                    "provider migrate",
                    workflow_report,
                )
                if stop_rc is not None:
                    return stop_rc
                return 0 if workflow_report.get("ok") else 4
            if args.mode == "preflight":
                if (
                    config.migration.routing.enabled
                    or config.target.workspace_aliases.enabled
                    or bool(getattr(args, "report_file", None))
                ):
                    workflow_report = run_provider_migration_workflow(
                        config,
                        Path(args.output_dir),
                        max_workers=int(args.max_workers),
                        ignore_errors=False,
                        dry_run=True,
                        stop_event=stop_event,
                        report_path=(
                            Path(args.report_file)
                            if getattr(args, "report_file", None)
                            else None
                        ),
                    )
                    _log_provider_workflow_result(
                        "Provider planned preflight",
                        workflow_report,
                    )
                    stop_rc = provider_workflow_stop_result(
                        "provider planned preflight",
                        workflow_report,
                    )
                    if stop_rc is not None:
                        return stop_rc
                    return 0 if workflow_report.get("ok") else 4
                ok, issues = provider_preflight(config, max_workers=int(args.max_workers), stop_event=stop_event)
                stop_rc = stop_requested_result("provider preflight")
                if stop_rc is not None:
                    return stop_rc
                if ok:
                    logging.info("Provider preflight passed")
                    return 0
                logging.error("Provider preflight found %d issue(s):", len(issues))
                for issue in issues:
                    logging.error("[provider-preflight] %s", issue)
                return 4
            if args.mode == "export":
                out_root = Path(args.output_dir)
                # Standalone export shares the root-wide workflow lock used by
                # migrate and direct import.  Acquire it before loading frozen
                # plans and hold it through the optional audit so no process
                # can mutate or consume the same staged state concurrently.
                with provider_workflow_lock(out_root, stop_event=stop_event):
                    stop_rc = stop_requested_result("provider export lock")
                    if stop_rc is not None:
                        return stop_rc
                    if out_root not in free_space_checked_paths:
                        check_free_space_for_path(out_root, min_free_gb)
                    routing_plan = None
                    if config.migration.routing.enabled:
                        routing_plan = load_provider_routing_plan(out_root, config)
                        require_gmail_configuration_plan(out_root, config, routing_plan)
                    stop_rc = stop_requested_result("provider export")
                    if stop_rc is not None:
                        return stop_rc
                    provider_export_all(
                        config,
                        out_root,
                        max_workers=int(args.max_workers),
                        ignore_errors=bool(args.ignore_errors),
                        stop_event=stop_event,
                        routing_plan=routing_plan,
                    )
                    stop_rc = stop_requested_result("provider export")
                    if stop_rc is not None:
                        return stop_rc
                    logging.info("Provider export finished. Data stored under: %s", out_root)
                    if not bool(getattr(args, "no_audit_after_export", False)):
                        ok, issues = provider_audit_all(
                            config,
                            out_root,
                            max_workers=int(args.max_workers),
                            stop_event=stop_event,
                            routing_plan=routing_plan,
                        )
                        stop_rc = stop_requested_result("provider audit")
                        if stop_rc is not None:
                            return stop_rc
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
                with provider_workflow_lock(in_root, stop_event=stop_event):
                    stop_rc = stop_requested_result("provider import lock")
                    if stop_rc is not None:
                        return stop_rc
                    local_rc = provider_locked_input_preflight_result(in_root, "import")
                    if local_rc is not None:
                        return local_rc
                    provider_staged_issues = _provider_cli_staged_validation_issues(
                        in_root,
                        config,
                        mode="import",
                    )
                    if provider_staged_issues:
                        logging.error("Provider import staged data failed local validation:")
                        for issue in provider_staged_issues:
                            logging.error("[provider-staged] %s", issue)
                        return 4
                    routing_plan = None
                    gmail_client = None
                    if config.migration.routing.enabled:
                        routing_plan = load_provider_routing_plan(in_root, config)
                        require_gmail_configuration_plan(in_root, config, routing_plan)
                    connectivity_rc = provider_target_connectivity_result()
                    if connectivity_rc is not None:
                        return connectivity_rc
                    if routing_plan is not None:
                        gmail_client = stop_aware_remote_client(
                            gmail_api_client_if_required(config, stop_event=stop_event),
                            stop_event,
                            label="Gmail API",
                        )
                        stop_rc = stop_requested_result("provider Gmail live-plan check")
                        if stop_rc is not None:
                            return stop_rc
                        live_plan = plan_live_gmail_configuration(routing_plan, gmail_client)
                        require_live_gmail_plan_ok(live_plan)
                        stop_rc = stop_requested_result("provider Gmail label provisioning")
                        if stop_rc is not None:
                            return stop_rc
                        label_result = provision_gmail_labels(routing_plan, gmail_client)
                        if not label_result.ok:
                            logging.error(
                                "Gmail label reconciliation did not verify before provider import"
                            )
                            for issue in label_result.issues or label_result.conflicts:
                                logging.error("[provider-gmail] %s", issue)
                            return 4
                        logging.info(
                            "Gmail label provisioning verified %d required label(s)",
                            len(label_result.labels),
                        )
                        stop_rc = stop_requested_result("provider Gmail filter provisioning")
                        if stop_rc is not None:
                            return stop_rc
                        filter_result = provision_gmail_filters(routing_plan, gmail_client)
                        if not filter_result.ok:
                            logging.error(
                                "Gmail filter reconciliation did not verify before provider import"
                            )
                            for issue in filter_result.issues or filter_result.conflicts:
                                logging.error("[provider-gmail] %s", issue)
                            return 4
                        logging.info(
                            "Gmail filter provisioning verified %d required filter(s)",
                            len(filter_result.filters),
                        )
                        stop_rc = stop_requested_result("provider Gmail verification")
                        if stop_rc is not None:
                            return stop_rc
                        gmail_verification = verify_gmail_configuration(
                            routing_plan,
                            gmail_client,
                        )
                        if not gmail_verification.ok:
                            logging.error(
                                "Gmail configuration verification failed before provider import:"
                            )
                            for issue in gmail_verification.issues:
                                logging.error("[provider-gmail] %s", issue)
                            return 4
                    stop_rc = stop_requested_result("provider import")
                    if stop_rc is not None:
                        return stop_rc
                    try:
                        provider_import_all(
                            config,
                            in_root,
                            max_workers=int(args.max_workers),
                            ignore_errors=bool(args.ignore_errors),
                            stop_event=stop_event,
                            routing_plan=routing_plan,
                        )
                    except ProviderImportIntegrityGateError as exc:
                        if stop_event.is_set():
                            logging.warning("Provider import integrity gate stopped: %s", exc)
                            return 130
                        logging.error("Provider import integrity gate blocked progression: %s", exc)
                        return 4
                    stop_rc = stop_requested_result("provider import")
                    if stop_rc is not None:
                        return stop_rc
                    logging.info("Provider import finished into server %s", config.target.host)
            elif args.mode == "test":
                stop_rc = stop_requested_result("provider test")
                if stop_rc is not None:
                    return stop_rc
                logging.info("Provider test completed successfully.")
            elif args.mode == "validate":
                if bool(getattr(args, "resync_missing", False)):
                    logging.warning("--resync-missing is disabled for provider configs; exact validation reports missing identities instead")
                in_root = Path(args.input_dir)
                if not in_root.exists():
                    logging.error("Input directory does not exist: %s", in_root)
                    return 2
                with provider_workflow_lock(in_root, stop_event=stop_event):
                    stop_rc = stop_requested_result("provider validate lock")
                    if stop_rc is not None:
                        return stop_rc
                    local_rc = provider_locked_input_preflight_result(in_root, "validate")
                    if local_rc is not None:
                        return local_rc
                    provider_staged_issues = _provider_cli_staged_validation_issues(
                        in_root,
                        config,
                        mode="validate",
                    )
                    if provider_staged_issues:
                        logging.error("Provider validate staged data failed local validation:")
                        for issue in provider_staged_issues:
                            logging.error("[provider-staged] %s", issue)
                        return 4
                    routing_plan = None
                    gmail_client = None
                    if config.migration.routing.enabled:
                        routing_plan = load_provider_routing_plan(in_root, config)
                        require_gmail_configuration_plan(in_root, config, routing_plan)
                    connectivity_rc = provider_target_connectivity_result()
                    if connectivity_rc is not None:
                        return connectivity_rc
                    if routing_plan is not None:
                        gmail_client = stop_aware_remote_client(
                            gmail_api_client_if_required(config, stop_event=stop_event),
                            stop_event,
                            label="Gmail API",
                        )
                    stop_rc = stop_requested_result("provider validation")
                    if stop_rc is not None:
                        return stop_rc
                    ok, issues = provider_validate_all(
                        config,
                        in_root,
                        max_workers=int(args.max_workers),
                        stop_event=stop_event,
                        routing_plan=routing_plan,
                    )
                    if routing_plan is not None:
                        stop_rc = stop_requested_result("provider Gmail verification")
                        if stop_rc is not None:
                            return stop_rc
                        gmail_verification = verify_gmail_configuration(routing_plan, gmail_client)
                        if not gmail_verification.ok:
                            ok = False
                            issues.extend(gmail_verification.issues)
                    stop_rc = stop_requested_result("provider validate")
                    if stop_rc is not None:
                        return stop_rc
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
                with provider_workflow_lock(in_root, stop_event=stop_event):
                    stop_rc = stop_requested_result("provider audit lock")
                    if stop_rc is not None:
                        return stop_rc
                    local_rc = provider_locked_input_preflight_result(in_root, "audit")
                    if local_rc is not None:
                        return local_rc
                    routing_plan = (
                        load_provider_routing_plan(in_root, config)
                        if config.migration.routing.enabled
                        else None
                    )
                    ok, issues = provider_audit_all(
                        config,
                        in_root,
                        max_workers=int(args.max_workers),
                        stop_event=stop_event,
                        routing_plan=routing_plan,
                    )
                    stop_rc = stop_requested_result("provider audit")
                    if stop_rc is not None:
                        return stop_rc
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
        elif args.mode in {"preflight", "migrate"}:
            logging.error("--mode %s requires a provider source/target config", args.mode)
            return 2
        elif args.mode == "export":
            assert isinstance(config, Config)
            out_root = Path(args.output_dir)
            if out_root.is_symlink():
                logging.error("Output directory is a symlink: %s", out_root)
                return 2
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

            class _LockedLegacyExportConnectivityFailed(RuntimeError):
                pass

            def do_export(acc: Account) -> None:
                if stop_event.is_set():
                    raise RuntimeError(f"legacy export {acc.email}: stop requested before completion")

                single_account_config = Config(
                    server=config.server,
                    accounts=[acc],
                    source_server=config.source_server,
                )

                def locked_export_action() -> None:
                    if not bool(getattr(args, "no_connectivity_test", False)):
                        try:
                            test_accounts(
                                single_account_config,
                                max_workers=1,
                                imap_timeout=imap_timeout,
                                stop_event=stop_event,
                            )
                        except Exception:
                            if stop_event.is_set():
                                raise
                            with panel_reset_failed_accounts_lock:
                                legacy_connectivity_failed_accounts.add(acc.email)
                            raise _LockedLegacyExportConnectivityFailed(
                                f"connectivity tests failed for {acc.email}"
                            ) from None
                    export_account(
                        acc,
                        config.server,
                        out_root,
                        ignore_errors=bool(args.ignore_errors),
                        stop_event=stop_event,
                    )

                try:
                    run_legacy_global_target_action_under_lock(
                        acc,
                        config.server,
                        locked_export_action,
                        stop_event=stop_event,
                    )
                except LegacyResetGateError as exc:
                    with panel_reset_failed_accounts_lock:
                        legacy_reset_gate_failed_accounts.add(acc.email)
                    if not bool(args.ignore_errors):
                        raise
                    logging.error("[reset-state] %s", exc)
                except _LockedLegacyExportConnectivityFailed as exc:
                    if not bool(args.ignore_errors):
                        raise
                    logging.error("[pre-export] %s", exc)

            try:
                parallel_process_accounts(
                    "export",
                    do_export,
                    config.accounts,
                    int(args.max_workers),
                    stop_on_error=not args.ignore_errors,
                    stop_event=stop_event,
                )
            except LegacyResetGateError as exc:
                if stop_event.is_set():
                    logging.warning("Locked legacy export stopped before completion")
                    return 130
                logging.error("[reset-state] Export blocked: %s", exc)
                return 4
            except _LockedLegacyExportConnectivityFailed as exc:
                if stop_event.is_set():
                    logging.warning("Locked legacy export stopped before completion")
                    return 130
                logging.error("[pre-export] Export aborted: %s", exc)
                return 3
            stop_rc = stop_requested_result("legacy export")
            if stop_rc is not None:
                return stop_rc
            if legacy_reset_gate_failed_accounts:
                logging.error(
                    "[reset-state] Export blocked for %d account(s): %s",
                    len(legacy_reset_gate_failed_accounts),
                    ", ".join(sorted(legacy_reset_gate_failed_accounts)),
                )
                return 4
            if legacy_connectivity_failed_accounts:
                logging.error(
                    "Connectivity tests failed for %d account(s): %s",
                    len(legacy_connectivity_failed_accounts),
                    ", ".join(sorted(legacy_connectivity_failed_accounts)),
                )
                return 3
            logging.info("Export finished. Data stored under: %s", out_root)

            if not bool(getattr(args, "no_audit_after_export", False)):
                try:
                    logging.info("Running export audit (%s)...", "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                    export_audit_config = Config(
                        server=config.server,
                        accounts=config.accounts,
                        source_server=config.server,
                    )
                    ok, audit_issues = _legacy_audit_export_with_target_locks(
                        out_root,
                        export_audit_config,
                        int(args.max_workers),
                        check_remote=not bool(getattr(args, "audit_offline", False)),
                        require_integrity_metadata=True,
                        stop_event=stop_event,
                    )
                    stop_rc = stop_requested_result("legacy export audit")
                    if stop_rc is not None:
                        return stop_rc
                    if ok:
                        logging.info("Audit passed: exported data looks consistent for all accounts")
                    else:
                        logging.error("Audit found %d issue(s):", len(audit_issues))
                        for line in audit_issues:
                            logging.error("[audit] %s", line)
                        return 4
                except Exception as exc:
                    if stop_event.is_set():
                        logging.warning("Legacy export audit stopped: %s", exc)
                        return 130
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
                        stop_event=stop_event,
                    )
                except Exception as exc:
                    if stop_event.is_set():
                        logging.warning("Staged export audit stopped before import: %s", exc)
                        return 130
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

            class _LockedPanelResetFailed(RuntimeError):
                pass

            class _LockedLegacyTargetSetupFailed(RuntimeError):
                pass

            def do_import(acc: Account) -> None:
                if stop_event.is_set():
                    raise RuntimeError(f"legacy import {acc.email}: stop requested before completion")
                if acc.email in panel_reset_failed_accounts:
                    logging.error("[panel] Skipping import for %s because control-panel setup failed", acc.email)
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
                single_account_config = Config(
                    server=config.server,
                    accounts=[acc],
                    source_server=config.source_server,
                )
                before_import = None
                reset_before_import = None
                if bool(getattr(args, "reset", False)):
                    def reset_before_import() -> None:
                        try:
                            if use_da_panel:
                                from .da_ensure import reset_accounts_directadmin

                                assert da_client is not None
                                failed = reset_accounts_directadmin(
                                    single_account_config,
                                    da_client,
                                    dry_run=False,
                                    ignore_errors=bool(args.ignore_errors),
                                    quota_mb=int(args.da_quota_mb),
                                    stop_event=stop_event,
                                )
                            else:
                                from .cpanel_ensure import reset_accounts_cpanel

                                assert cpanel_client is not None
                                failed = reset_accounts_cpanel(
                                    single_account_config,
                                    cpanel_client,
                                    dry_run=False,
                                    ignore_errors=bool(args.ignore_errors),
                                    quota_mb=int(args.cpanel_quota_mb),
                                    stop_event=stop_event,
                                )
                        except Exception:
                            if stop_event.is_set():
                                raise
                            with panel_reset_failed_accounts_lock:
                                panel_reset_failed_accounts.add(acc.email)
                            raise _LockedPanelResetFailed(
                                f"panel reset failed for {acc.email}"
                            ) from None
                        if acc.email in set(failed or ()):
                            with panel_reset_failed_accounts_lock:
                                panel_reset_failed_accounts.add(acc.email)
                            raise _LockedPanelResetFailed(
                                f"panel reset failed for {acc.email}"
                            )
                else:
                    def before_import() -> None:
                        if use_da_panel or use_cpanel:
                            try:
                                if use_da_panel:
                                    assert da_client is not None
                                    failed = ensure_accounts_exist_directadmin(
                                        single_account_config,
                                        da_client,
                                        dry_run=False,
                                        ignore_errors=bool(args.ignore_errors),
                                        quota_mb=int(args.da_quota_mb),
                                        stop_event=stop_event,
                                    )
                                else:
                                    assert cpanel_client is not None
                                    failed = ensure_accounts_exist_cpanel(
                                        single_account_config,
                                        cpanel_client,
                                        dry_run=False,
                                        ignore_errors=bool(args.ignore_errors),
                                        quota_mb=int(args.cpanel_quota_mb),
                                        stop_event=stop_event,
                                    )
                            except Exception:
                                if stop_event.is_set():
                                    raise
                                with panel_reset_failed_accounts_lock:
                                    panel_reset_failed_accounts.add(acc.email)
                                raise _LockedLegacyTargetSetupFailed(
                                    f"panel provisioning failed for {acc.email}"
                                ) from None
                            if acc.email in set(failed or ()):
                                with panel_reset_failed_accounts_lock:
                                    panel_reset_failed_accounts.add(acc.email)
                                raise _LockedLegacyTargetSetupFailed(
                                    f"panel provisioning failed for {acc.email}"
                                )

                        if not bool(getattr(args, "no_connectivity_test", False)):
                            try:
                                test_accounts(
                                    single_account_config,
                                    max_workers=1,
                                    imap_timeout=imap_timeout,
                                    stop_event=stop_event,
                                )
                            except Exception:
                                if stop_event.is_set():
                                    raise
                                with panel_reset_failed_accounts_lock:
                                    legacy_connectivity_failed_accounts.add(acc.email)
                                raise _LockedLegacyTargetSetupFailed(
                                    f"connectivity tests failed for {acc.email}"
                                ) from None

                try:
                    import_account(
                        acc,
                        config.server,
                        in_root,
                        ignore_errors=bool(args.ignore_errors),
                        stop_event=stop_event,
                        da_context=da_ctx,
                        provision_context=provision_ctx,
                        source_server=config.source_server,
                        before_import=before_import,
                        reset_before_import=reset_before_import,
                    )
                except LegacyResetGateError as exc:
                    with panel_reset_failed_accounts_lock:
                        legacy_reset_gate_failed_accounts.add(acc.email)
                    if not bool(args.ignore_errors):
                        raise
                    logging.error("[reset-state] %s", exc)
                    return
                except _LockedPanelResetFailed as exc:
                    if not bool(args.ignore_errors):
                        raise
                    logging.error("[panel] %s", exc)
                    return
                except _LockedLegacyTargetSetupFailed as exc:
                    if not bool(args.ignore_errors):
                        raise
                    logging.error("[pre-import] %s", exc)
                    return

            import_accounts = [acc for acc in config.accounts if acc.email not in panel_reset_failed_accounts]
            try:
                parallel_process_accounts(
                    "import",
                    do_import,
                    import_accounts,
                    int(args.max_workers),
                    stop_on_error=not args.ignore_errors,
                    stop_event=stop_event,
                )
            except LegacyResetGateError as exc:
                if stop_event.is_set():
                    logging.warning("Locked legacy import stopped before completion")
                    return 130
                logging.error("[reset-state] Import blocked: %s", exc)
                return 4
            except (_LockedPanelResetFailed, _LockedLegacyTargetSetupFailed) as exc:
                if stop_event.is_set():
                    logging.warning("Locked legacy target setup stopped before completion")
                    return 130
                logging.error("[pre-import] Import aborted after locked target setup failure: %s", exc)
                return 3
            stop_rc = stop_requested_result("legacy import")
            if stop_rc is not None:
                return stop_rc
            if legacy_reset_gate_failed_accounts:
                logging.error(
                    "[reset-state] Import blocked for %d account(s): %s",
                    len(legacy_reset_gate_failed_accounts),
                    ", ".join(sorted(legacy_reset_gate_failed_accounts)),
                )
                return 4
            if legacy_connectivity_failed_accounts:
                logging.error(
                    "Connectivity tests failed for %d account(s): %s",
                    len(legacy_connectivity_failed_accounts),
                    ", ".join(sorted(legacy_connectivity_failed_accounts)),
                )
                return 3
            if panel_reset_failed_accounts:
                logging.error(
                    "[panel] Import skipped %d account(s) because control-panel setup failed: %s",
                    len(panel_reset_failed_accounts),
                    ", ".join(sorted(panel_reset_failed_accounts)),
                )
                return 3
            logging.info("Import finished into server %s", config.server.host)
        elif args.mode == "test":
            assert isinstance(config, Config)

            if not bool(getattr(args, "no_connectivity_test", False)):
                def do_locked_test(acc: Account) -> None:
                    single_account_config = Config(
                        server=config.server,
                        accounts=[acc],
                        source_server=config.source_server,
                    )

                    def locked_connectivity_action() -> None:
                        test_accounts(
                            single_account_config,
                            max_workers=1,
                            imap_timeout=imap_timeout,
                            stop_event=stop_event,
                        )

                    try:
                        run_legacy_global_target_action_under_lock(
                            acc,
                            config.server,
                            locked_connectivity_action,
                            stop_event=stop_event,
                        )
                    except LegacyResetGateError:
                        with panel_reset_failed_accounts_lock:
                            legacy_reset_gate_failed_accounts.add(acc.email)
                    except Exception:
                        if stop_event.is_set():
                            raise
                        with panel_reset_failed_accounts_lock:
                            legacy_connectivity_failed_accounts.add(acc.email)

                parallel_process_accounts(
                    "test",
                    do_locked_test,
                    config.accounts,
                    int(args.max_workers),
                    stop_on_error=False,
                    stop_event=stop_event,
                )
            stop_rc = stop_requested_result("legacy test")
            if stop_rc is not None:
                return stop_rc
            if legacy_reset_gate_failed_accounts:
                logging.error(
                    "Connectivity test blocked by reset state for: %s",
                    ", ".join(sorted(legacy_reset_gate_failed_accounts)),
                )
                return 4
            if legacy_connectivity_failed_accounts:
                logging.error(
                    "Connectivity tests failed for: %s",
                    ", ".join(sorted(legacy_connectivity_failed_accounts)),
                )
                return 3
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
            def do_validate_unlocked(acc: Account) -> None:
                email = acc.email
                account_dir_fd: Optional[int] = None
                try:
                    from .imap_ops import (
                        _legacy_import_target_id,
                        _legacy_hierarchy_metadata,
                        _list_selectable_mailbox_entries,
                        _load_legacy_import_journal,
                        _open_legacy_dir,
                        _raise_if_legacy_parent_replaced,
                        _read_file_no_symlink,
                        _require_legacy_payload_integrity,
                        _should_skip_legacy_source_view,
                        _legacy_target_hierarchy_delimiter,
                        _legacy_target_mailbox_name,
                        _unresolved_legacy_pending_keys,
                        _validate_legacy_delivery_metadata,
                        _validate_legacy_sidecar_integrity,
                        imap_connection,
                        quote_mailbox_name,
                    )
                    account_dir = in_root / sanitize_for_path(acc.email)
                    local_counts: Dict[str, int] = {}
                    local_messages: Dict[str, List[Tuple[str, bytes, str, str]]] = {}
                    local_content_identity_slots: List[_LegacyCoverageSlot] = []
                    if not account_dir.exists():
                        with mismatches_lock:
                            validation_errors.append((email, f"account directory missing: {account_dir}"))
                        return
                    account_dir_fd, account_dir_path = _open_legacy_dir(account_dir, "legacy account")

                    def guard_account_dir() -> None:
                        if account_dir_fd is None:
                            raise RuntimeError(f"legacy account directory is not pinned: {account_dir}")
                        _raise_if_legacy_parent_replaced(account_dir_path, account_dir_fd, "legacy account")

                    ok, audit_issues = audit_export(
                        in_root,
                        Config(server=config.server, accounts=[acc], source_server=config.source_server),
                        1,
                        check_remote=False,
                        require_integrity_metadata=True,
                        stop_event=stop_event,
                    )
                    guard_account_dir()
                    if not ok:
                        with mismatches_lock:
                            validation_errors.extend((email, issue) for issue in audit_issues)
                        return
                    current_target = _legacy_import_target_id(config.server, acc)
                    journal_rows = _load_legacy_import_journal(account_dir, repair_trailing=False)
                    guard_account_dir()
                    unresolved_pending_keys = _unresolved_legacy_pending_keys(journal_rows, current_target)
                    if unresolved_pending_keys:
                        with mismatches_lock:
                            validation_errors.append((email, f"import journal has {len(unresolved_pending_keys)} pending append(s); target state is uncertain"))
                        return

                    def marker_info(folder_dir: Path) -> Tuple[str, Tuple[str, Tuple[str, ...]], bool]:
                        marker_path = folder_dir / ".mailbox.json"
                        if not marker_path.exists():
                            return folder_dir.name, ("", ()), False
                        try:
                            marker_bytes = _read_file_no_symlink(
                                marker_path,
                                "legacy mailbox marker",
                                reject_hard_links=True,
                            )
                            raw = json.loads(marker_bytes.decode("utf-8"))
                        except Exception as exc:
                            raise RuntimeError(f"{marker_path}: failed to parse mailbox marker: {exc}") from exc
                        mailbox = raw.get("mailbox") if isinstance(raw, dict) else None
                        if not isinstance(mailbox, str) or not mailbox:
                            return folder_dir.name, ("", ()), False
                        hierarchy = _legacy_hierarchy_metadata(
                            raw if isinstance(raw, dict) else {},
                            mailbox,
                            str(marker_path),
                        )
                        covered = (
                            _legacy_trusted_covered_by_regular_content(raw, str(marker_path))
                            if isinstance(raw, dict)
                            else False
                        )
                        return mailbox, hierarchy, covered

                    folder_dirs: List[Path] = []
                    for child_name in sorted(os.listdir(account_dir_fd)):
                        try:
                            child_stat = os.stat(child_name, dir_fd=account_dir_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        if stat.S_ISLNK(child_stat.st_mode):
                            with mismatches_lock:
                                validation_errors.append((email, f"{child_name}: mailbox path is a symlink"))
                            return
                        if stat.S_ISDIR(child_stat.st_mode):
                            folder_dirs.append(account_dir / child_name)
                    guard_account_dir()
                    if not folder_dirs:
                        with mismatches_lock:
                            validation_errors.append((email, "no mailbox folders found"))
                        return
                    local_mailboxes_by_key: Dict[str, str] = {}
                    local_segments_by_key: Dict[str, Tuple[str, ...]] = {}
                    for folder_dir in folder_dirs:
                        guard_account_dir()
                        default_mailbox, default_hierarchy, covered_by_regular_content = marker_info(folder_dir)
                        guard_account_dir()
                        eml_paths = sorted(folder_dir.glob("*.eml"))
                        guard_account_dir()
                        if covered_by_regular_content and not eml_paths:
                            continue
                        folder_key = canonical_mailbox_path_key(folder_dir.name)
                        local_mailboxes_by_key.setdefault(folder_key, default_mailbox)
                        if default_hierarchy[1]:
                            local_segments_by_key[folder_key] = default_hierarchy[1]
                        if not eml_paths:
                            local_counts.setdefault(folder_key, 0)
                            local_messages.setdefault(folder_key, [])
                            continue
                        for eml_path in eml_paths:
                            mailbox = default_mailbox
                            metadata_path = eml_path.with_suffix(".json")
                            if not metadata_path.exists():
                                raise RuntimeError(f"{metadata_path}: missing message metadata")
                            try:
                                guard_account_dir()
                                metadata_bytes = _read_file_no_symlink(
                                    metadata_path,
                                    "legacy message metadata",
                                    reject_hard_links=True,
                                )
                                guard_account_dir()
                                metadata = json.loads(metadata_bytes.decode("utf-8"))
                            except Exception as exc:
                                raise RuntimeError(f"{metadata_path}: failed to parse message metadata: {exc}") from exc
                            if not isinstance(metadata, dict):
                                raise RuntimeError(f"{metadata_path}: message metadata is not an object")
                            account_meta = str(metadata.get("account") or "")
                            if account_meta != acc.email:
                                raise RuntimeError(
                                    f"{metadata_path}: account metadata mismatch "
                                    f"(account={acc.email} meta={account_meta})"
                                )
                            expected_size, expected_hash = _validate_legacy_sidecar_integrity(metadata_path, metadata)
                            expected_flags, _expected_internaldate = _validate_legacy_delivery_metadata(
                                metadata,
                                str(metadata_path),
                            )
                            metadata_mailbox = metadata.get("mailbox")
                            if isinstance(metadata_mailbox, str) and metadata_mailbox:
                                mailbox = metadata_mailbox
                            message_hierarchy = _legacy_hierarchy_metadata(
                                metadata,
                                mailbox,
                                str(metadata_path),
                            )
                            if message_hierarchy != default_hierarchy:
                                raise RuntimeError(f"{metadata_path}: source_path_segments mismatch")
                            local_mailboxes_by_key.setdefault(folder_key, mailbox)
                            if message_hierarchy[1]:
                                existing_segments = local_segments_by_key.get(folder_key)
                                if existing_segments is not None and existing_segments != message_hierarchy[1]:
                                    raise RuntimeError(f"{metadata_path}: source_path_segments mismatch")
                                local_segments_by_key[folder_key] = message_hierarchy[1]
                            local_counts[folder_key] = local_counts.get(folder_key, 0) + 1
                            guard_account_dir()
                            message_bytes = _read_file_no_symlink(
                                eml_path,
                                "legacy message file",
                                reject_hard_links=True,
                            )
                            guard_account_dir()
                            _require_legacy_payload_integrity(eml_path, message_bytes, expected_size, expected_hash)
                            local_content_identity_slots.append((
                                _legacy_content_identity_variants(message_bytes),
                                expected_flags,
                                _expected_internaldate or "",
                            ))
                            local_messages.setdefault(folder_key, []).append((
                                eml_path.relative_to(account_dir).as_posix(),
                                message_bytes,
                                expected_flags,
                                _expected_internaldate or "",
                            ))
                    remote_counts: Dict[str, int] = {}
                    remote_mailboxes: Dict[str, str] = {}
                    remote_attrs_by_key: Dict[str, Tuple[str, ...]] = {}
                    remote_mailboxes_by_alias_key: Dict[str, Tuple[str, str]] = {}
                    remote_name_mismatch_keys: Set[str] = set()
                    guard_account_dir()
                    with imap_connection(config.server, acc) as imap:
                        target_delimiter = _legacy_target_hierarchy_delimiter(imap)
                        target_mailboxes_by_key = {
                            key: _legacy_target_mailbox_name(
                                mailbox,
                                local_segments_by_key.get(key, ()),
                                target_delimiter,
                            )
                            for key, mailbox in local_mailboxes_by_key.items()
                        }
                        target_key_by_mailbox = {}
                        for key, mailbox in target_mailboxes_by_key.items():
                            target_key_by_mailbox[mailbox] = key
                            target_key_by_mailbox.setdefault(canonical_imap_mailbox_name(mailbox), key)
                        target_collision_keys: Dict[str, Tuple[str, str]] = {}
                        for key, target_mailbox in target_mailboxes_by_key.items():
                            alias = sanitized_path_key(target_mailbox)
                            previous = target_collision_keys.get(alias)
                            if previous is not None and previous[0] != key:
                                raise RuntimeError(
                                    f"legacy validate target mailbox collision: "
                                    f"{previous[1]!r} and {target_mailbox!r}"
                                )
                            target_collision_keys[alias] = (key, target_mailbox)
                        mailbox_entries = _list_selectable_mailbox_entries(imap)
                        mailboxes = [
                            name
                            for name, attrs in mailbox_entries
                            if not _should_skip_legacy_source_view(name, attrs, mailbox_entries)
                        ]
                        remote_attrs_by_mailbox = {name: attrs for name, attrs in mailbox_entries}
                        remote_attrs_by_key = {
                            canonical_mailbox_path_key(name): attrs
                            for name, attrs in mailbox_entries
                        }
                        for mailbox in mailboxes:
                            try:
                                status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
                                if status != "OK":
                                    raise RuntimeError(f"select failed: {mailbox}")
                                status, data = imap.search(None, "ALL")
                                if status != "OK":
                                    raise RuntimeError(f"search failed: {mailbox}")
                                num = len((data[0] or b"").split()) if data else 0
                                key = target_key_by_mailbox.get(mailbox)
                                if key is None:
                                    key = target_key_by_mailbox.get(
                                        canonical_imap_mailbox_name(mailbox),
                                        canonical_mailbox_path_key(mailbox),
                                    )
                                remote_attrs_by_key[key] = remote_attrs_by_mailbox.get(mailbox, ())
                                alias_key = sanitized_path_key(key)
                                expected_mailbox = target_mailboxes_by_key.get(key)
                                if (
                                    expected_mailbox is not None
                                    and canonical_imap_mailbox_name(mailbox)
                                    != canonical_imap_mailbox_name(expected_mailbox)
                                ):
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
                                if (
                                    previous is not None
                                    and canonical_imap_mailbox_name(previous[0])
                                    != canonical_imap_mailbox_name(mailbox)
                                ):
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
                                key = canonical_mailbox_path_key(mailbox)
                                remote_counts[key] = -1
                                remote_mailboxes.setdefault(key, mailbox)
                        mismatched_folders = set()
                        for folder, local_count in local_counts.items():
                            if folder in remote_name_mismatch_keys:
                                mismatched_folders.add(folder)
                                continue
                            remote = remote_counts.get(folder, -1)
                            if local_count != remote:
                                remote_mailbox = remote_mailboxes.get(
                                    folder,
                                    target_mailboxes_by_key.get(folder, local_mailboxes_by_key.get(folder, folder)),
                                )
                                remote_attrs = remote_attrs_by_key.get(folder, ())
                                if (
                                    remote >= 0
                                    and _legacy_virtual_source_attrs(remote_attrs)
                                    and _legacy_remote_mailbox_content_covered(
                                        imap,
                                        remote_mailbox,
                                        local_content_identity_slots,
                                        required_flags="\\Flagged" if _is_legacy_flagged_source_view(remote_attrs) else "",
                                        require_all_local=local_count > remote,
                                    )
                                ):
                                    continue
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    mismatches.append((email, folder, local_count, remote))
                        for folder, remote_count in remote_counts.items():
                            if folder not in local_counts:
                                remote_mailbox = remote_mailboxes.get(folder, folder)
                                remote_attrs = remote_attrs_by_key.get(folder, ())
                                if (
                                    remote_count >= 0
                                    and _legacy_virtual_source_attrs(remote_attrs)
                                    and _legacy_remote_mailbox_content_covered(
                                        imap,
                                        remote_mailbox,
                                        local_content_identity_slots,
                                        required_flags="\\Flagged" if _is_legacy_flagged_source_view(remote_attrs) else "",
                                    )
                                ):
                                    continue
                            if folder not in local_counts and remote_count < 0:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    validation_errors.append((email, f"{remote_mailboxes.get(folder, folder)}: remote mailbox could not be counted"))
                            elif folder not in local_counts and remote_count == 0:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    validation_errors.append((email, f"{remote_mailboxes.get(folder, folder)}: missing locally but remote has 0 messages"))
                            elif folder not in local_counts and remote_count > 0:
                                mismatched_folders.add(folder)
                                with mismatches_lock:
                                    mismatches.append((email, folder, 0, remote_count))
                        for key, messages in local_messages.items():
                            mailbox = local_mailboxes_by_key.get(key, key)
                            if key in mismatched_folders or remote_counts.get(key, -1) < 0:
                                continue
                            remote_mailbox = remote_mailboxes.get(key, target_mailboxes_by_key.get(key, mailbox))
                            used_remote_nums: Set[bytes] = set()
                            for rel_path, data, expected_flags, expected_internaldate in messages:
                                try:
                                    found = _legacy_remote_has_message(
                                        imap,
                                        remote_mailbox,
                                        data,
                                        used_remote_nums,
                                        expected_flags,
                                        expected_internaldate,
                                    )
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
                finally:
                    if account_dir_fd is not None:
                        os.close(account_dir_fd)

            def do_validate(acc: Account) -> None:
                connectivity_failed = False
                single_account_config = Config(
                    server=config.server,
                    accounts=[acc],
                    source_server=config.source_server,
                )

                def locked_validation_action() -> None:
                    nonlocal connectivity_failed
                    if not bool(getattr(args, "no_connectivity_test", False)):
                        try:
                            test_accounts(
                                single_account_config,
                                max_workers=1,
                                imap_timeout=imap_timeout,
                                stop_event=stop_event,
                            )
                        except Exception:
                            if stop_event.is_set():
                                raise
                            connectivity_failed = True
                            with panel_reset_failed_accounts_lock:
                                legacy_connectivity_failed_accounts.add(acc.email)
                            raise
                    do_validate_unlocked(acc)

                try:
                    run_legacy_target_action_under_import_lock(
                        acc,
                        config.server,
                        in_root,
                        locked_validation_action,
                        stop_event=stop_event,
                    )
                except LegacyResetGateError as exc:
                    with panel_reset_failed_accounts_lock:
                        legacy_reset_gate_failed_accounts.add(acc.email)
                    with mismatches_lock:
                        validation_errors.append((acc.email, str(exc)))
                except Exception as exc:
                    if stop_event.is_set():
                        raise
                    if connectivity_failed:
                        return
                    with mismatches_lock:
                        validation_errors.append((acc.email, str(exc)))

            parallel_process_accounts(
                "validate",
                do_validate,
                config.accounts,
                int(args.max_workers),
                stop_on_error=False,
                stop_event=stop_event,
            )
            stop_rc = stop_requested_result("legacy validate")
            if stop_rc is not None:
                return stop_rc
            if legacy_reset_gate_failed_accounts:
                logging.warning(
                    "Validation blocked by reset state for: %s",
                    ", ".join(sorted(legacy_reset_gate_failed_accounts)),
                )
                return 4
            if legacy_connectivity_failed_accounts:
                logging.error(
                    "Connectivity tests failed for: %s",
                    ", ".join(sorted(legacy_connectivity_failed_accounts)),
                )
                return 3
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
            try:
                logging.info("Running audit on %s (%s) ...", in_root, "local-only" if bool(getattr(args, "audit_offline", False)) else "local + remote counts")
                audit_config = Config(
                    server=config.server,
                    accounts=config.accounts,
                    source_server=config.source_server or config.server,
                )
                ok, audit_issues = _legacy_audit_export_with_target_locks(
                    in_root,
                    audit_config,
                    int(args.max_workers),
                    check_remote=not bool(getattr(args, "audit_offline", False)),
                    require_integrity_metadata=True,
                    stop_event=stop_event,
                )
                journal_issues = _legacy_pending_import_journal_issues(in_root, config, repair_trailing=False)
                stop_rc = stop_requested_result("legacy audit")
                if stop_rc is not None:
                    return stop_rc
                if journal_issues:
                    audit_issues.extend(journal_issues)
                    ok = False
                if ok:
                    logging.info("Audit passed: exported data looks consistent for all accounts")
                    return 0
                logging.error("Audit found %d issue(s):", len(audit_issues))
                for line in audit_issues:
                    logging.error("[audit] %s", line)
                return 4
            except Exception as exc:
                if stop_event.is_set():
                    logging.warning("Legacy audit stopped: %s", exc)
                    return 130
                logging.exception("Fatal audit error: %s", exc)
                return 4
        else:
            logging.error("Unknown mode: %s", args.mode)
            return 2
    except Exception as exc:
        if stop_event.is_set():
            logging.warning("Stop requested; aborting after interruption: %s", exc)
            return 130
        logging.exception("Fatal error: %s", exc)
        return 1

    stop_rc = stop_requested_result(args.mode)
    if stop_rc is not None:
        return stop_rc
    logging.info("Done. Log file: %s", log_file)
    return 0
