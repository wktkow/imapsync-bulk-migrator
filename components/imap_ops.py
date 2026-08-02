import contextlib
import errno
import fcntl
import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import stat
import sys
import time
from collections import Counter, deque
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Tuple

import idna
import imaplib

from .models import Account, ServerConfig
from .content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_issue, legacy_content_binding_sha256
from .utils import (
    decode_imap_utf7,
    encode_imap_utf7,
    parse_imap_uid_search_data,
    parse_imap_uid_token,
    quote_imap_search_value,
    sanitize_for_path,
    sanitized_path_key,
)


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
IMPORT_LOCK_WAIT_SECONDS = 0.1
LEGACY_RESET_STATE_FILENAME = "reset-state.json"
LEGACY_GLOBAL_STATE_PARENT = (
    Path("/private/var/tmp") if sys.platform == "darwin" else Path("/var/tmp")
)
LEGACY_GLOBAL_STATE_DIR_PREFIX = "imapsync-bulk-migrator"
LEGACY_GLOBAL_STATE_NAMESPACE = "legacy-target-state"
LEGACY_GLOBAL_LOCK_DIRNAME = "locks"
LEGACY_GLOBAL_RESET_DIRNAME = "resets"
_HAS_DESCRIPTOR_RELATIVE_OPEN = os.open in os.supports_dir_fd
_HAS_DESCRIPTOR_RELATIVE_MKDIR = _HAS_DESCRIPTOR_RELATIVE_OPEN and os.mkdir in os.supports_dir_fd
LEGACY_ACCOUNT_RESERVED_PATHS = frozenset(
    {
        "export-state.json",
        "import.journal.jsonl",
        "manifest.jsonl",
        LEGACY_RESET_STATE_FILENAME,
    }
)
_LEGACY_ACCOUNT_RESERVED_PATH_KEYS = frozenset(path.casefold() for path in LEGACY_ACCOUNT_RESERVED_PATHS)
_LEGACY_IMPORT_JOURNAL_STATUSES = {"pending", "committed", "failed"}
_LEGACY_RESET_STATE_PHASES = {"prepared", "journal_archived", "reset_started"}
_LEGACY_RESET_PHASE_ORDER = {
    "prepared": 0,
    "journal_archived": 1,
    "reset_started": 2,
}
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_LEGACY_UIDVALIDITY_RE = re.compile(r"[1-9][0-9]*")
_LEGACY_UIDVALIDITY_MAX = 0xFFFFFFFF
_IMAP_INTERNALDATE_RE = re.compile(
    r"^(?P<day>[ 0][1-9]|[12][0-9]|3[01])-"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-"
    r"(?P<year>\d{4}) "
    r"(?P<hour>[01]\d|2[0-3]):(?P<minute>[0-5]\d):(?P<second>[0-5]\d) "
    r"(?P<zone_sign>[+-])(?P<zone_hour>\d{2})(?P<zone_minute>\d{2})$",
    re.IGNORECASE | re.ASCII,
)
_IMAP_MONTH_NUMBER = {
    month.lower(): index
    for index, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        1,
    )
}
_FETCH_RESPONSE_START_RE = re.compile(r"^\s*\d+\s+\(")


class _LegacyAppendOutcomeUncertain(RuntimeError):
    """Raised when APPEND may have reached the target but no outcome was confirmed."""


class LegacyResetGateError(RuntimeError):
    """Raised when an ordinary target action is blocked by reset state."""


class _LegacyMailboxEntry(NamedTuple):
    name: str
    attributes: Tuple[str, ...]
    delimiter: str


def quote_mailbox_name(mailbox: str) -> str:
    if mailbox.upper() == "INBOX":
        return "INBOX"
    encoded = encode_imap_utf7(mailbox)
    escaped = encoded.replace("\\", "\\\\").replace('"', r"\"")
    return f'"{escaped}"'


def ensure_private_dir(path: Path, *, label: str = "directory") -> None:
    dir_fd, dir_path = _open_or_create_legacy_dir(path, label)
    try:
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, label)
        _secure_legacy_private_dir_fd(dir_fd, dir_path, label)
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, label)
    finally:
        os.close(dir_fd)


def _legacy_effective_uid() -> int:
    get_effective_uid = getattr(os, "geteuid", None)
    if not callable(get_effective_uid):
        raise RuntimeError("platform does not expose an effective UID for legacy artifact ownership checks")
    try:
        return int(get_effective_uid())
    except OSError as exc:
        raise RuntimeError("unable to determine effective UID for legacy artifact ownership checks") from exc


def _secure_legacy_private_dir_fd(dir_fd: int, path: Path, label: str) -> None:
    if path == Path(path.anchor):
        raise RuntimeError(f"refusing to secure {label} filesystem root: {path}")
    stat_result = os.fstat(dir_fd)
    if not stat.S_ISDIR(stat_result.st_mode):
        raise RuntimeError(f"{label} path is not a directory: {path}")
    effective_uid = _legacy_effective_uid()
    if stat_result.st_uid != effective_uid:
        raise RuntimeError(
            f"refusing to secure {label} not owned by effective UID {effective_uid}: "
            f"{path} (owner UID {stat_result.st_uid})"
        )
    mode = stat.S_IMODE(stat_result.st_mode)
    unsafe_shared_bits = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    if mode & unsafe_shared_bits:
        raise RuntimeError(f"refusing to secure shared {label} directory: {path} (mode {mode:#05o})")
    try:
        os.fchmod(dir_fd, PRIVATE_DIR_MODE)
    except OSError as exc:
        raise RuntimeError(f"unable to set private permissions on {label} directory: {path}") from exc
    final_stat = os.fstat(dir_fd)
    final_mode = stat.S_IMODE(final_stat.st_mode)
    if not stat.S_ISDIR(final_stat.st_mode):
        raise RuntimeError(f"{label} path is no longer a directory: {path}")
    if final_stat.st_uid != effective_uid:
        raise RuntimeError(
            f"{label} ownership changed while securing {path}: "
            f"expected UID {effective_uid}, found {final_stat.st_uid}"
        )
    if final_mode != PRIVATE_DIR_MODE:
        raise RuntimeError(
            f"{label} directory permissions are not private: "
            f"{path} (expected {PRIVATE_DIR_MODE:#05o}, found {final_mode:#05o})"
        )


def legacy_reserved_mailbox_path_issue(mailbox: str, path: Optional[str] = None) -> Optional[str]:
    sanitized = sanitize_for_path(mailbox) if path is None else path
    if sanitized.casefold() not in _LEGACY_ACCOUNT_RESERVED_PATH_KEYS:
        return None
    return f"mailbox {mailbox!r} maps to reserved legacy account artifact path {sanitized!r}"


def _raise_if_symlink(path: Path, label: str) -> None:
    if _legacy_symlink_component(path) is not None:
        raise RuntimeError(f"refusing to use symlinked {label}: {path}")


def _legacy_symlink_component(path: Path) -> Optional[Path]:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            current = current.parent
            continue
        current = current / part
        if current.is_symlink():
            return current
    return None


def _legacy_normalized_absolute_path(path: Path) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    parts: List[str] = []
    for part in absolute.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return Path(absolute.anchor).joinpath(*parts)


def _legacy_parent_matches_fd(parent_path: Path, parent_fd: int) -> bool:
    try:
        current = os.stat(parent_path, follow_symlinks=False)
    except OSError:
        return False
    pinned = os.fstat(parent_fd)
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == pinned.st_dev
        and current.st_ino == pinned.st_ino
    )


def _raise_if_legacy_parent_replaced(parent_path: Path, parent_fd: int, label: str) -> None:
    if not _legacy_parent_matches_fd(parent_path, parent_fd):
        raise RuntimeError(f"refusing to use replaced {label} directory: {parent_path}")


def _legacy_dir_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_or_create_legacy_dir(path: Path, label: str) -> Tuple[int, Path]:
    if not _HAS_DESCRIPTOR_RELATIVE_MKDIR:
        raise RuntimeError("platform does not support descriptor-relative legacy directory creation")
    absolute = _legacy_normalized_absolute_path(path)
    flags = _legacy_dir_open_flags()
    fd = os.open(absolute.anchor, flags)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            created = False
            try:
                os.mkdir(part, PRIVATE_DIR_MODE, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                if exc.errno != errno.EEXIST:
                    raise
            if created:
                _fsync_legacy_directory_fd(fd, current, label)
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                if exc.errno == errno.ENOTDIR:
                    with contextlib.suppress(OSError):
                        component_stat = os.stat(part, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(component_stat.st_mode):
                            raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                    raise RuntimeError(f"{label} path component is not a directory: {current / part}") from exc
                raise
            try:
                stat_result = os.fstat(next_fd)
                if not stat.S_ISDIR(stat_result.st_mode):
                    raise RuntimeError(f"{label} path component is not a directory: {current / part}")
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            current = current / part
        _raise_if_legacy_parent_replaced(absolute, fd, label)
        return fd, absolute
    except Exception:
        os.close(fd)
        raise


def _open_legacy_parent_dir(path: Path, label: str) -> Tuple[int, str, Path]:
    if not _HAS_DESCRIPTOR_RELATIVE_OPEN:
        raise RuntimeError("platform does not support descriptor-relative legacy file access")
    absolute = _legacy_normalized_absolute_path(path)
    name = absolute.name
    if not name or name in {".", ".."}:
        raise RuntimeError(f"refusing to use invalid {label} path: {path}")
    parent_path = absolute.parent
    flags = _legacy_dir_open_flags()
    fd = os.open(absolute.anchor, flags)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:-1]:
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                if exc.errno == errno.ENOTDIR:
                    with contextlib.suppress(OSError):
                        component_stat = os.stat(part, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(component_stat.st_mode):
                            raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                    raise RuntimeError(f"{label} path component is not a directory: {current / part}") from exc
                raise
            try:
                stat_result = os.fstat(next_fd)
                if not stat.S_ISDIR(stat_result.st_mode):
                    raise RuntimeError(f"{label} path component is not a directory: {current / part}")
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            current = current / part
        _raise_if_legacy_parent_replaced(parent_path, fd, label)
        return fd, name, parent_path
    except Exception:
        os.close(fd)
        raise


def _open_legacy_dir(path: Path, label: str) -> Tuple[int, Path]:
    fd, _probe_name, dir_path = _open_legacy_parent_dir(path / ".legacy-dir-probe", label)
    return fd, dir_path


def _fsync_legacy_directory_fd(dir_fd: int, path: Path, label: str) -> None:
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise RuntimeError(f"unable to fsync {label} directory for durability: {path}") from exc


def _unlink_legacy_entry_and_fsync(parent_fd: int, name: str, parent_path: Path, label: str) -> bool:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return False
    _fsync_legacy_directory_fd(parent_fd, parent_path, label)
    return True


def _read_file_no_symlink_with_stat(
    path: Path,
    label: str,
    *,
    reject_hard_links: bool = False,
) -> Tuple[bytes, os.stat_result]:
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, label)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
        raise
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise RuntimeError(f"refusing to use non-regular {label}: {path}")
        if reject_hard_links:
            _raise_if_hard_linked_private_file_fd(fd, path, label)
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, label)
    except Exception:
        os.close(fd)
        raise
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as f:
        return f.read(), stat_result


def _read_file_no_symlink(path: Path, label: str, *, reject_hard_links: bool = False) -> bytes:
    content, _stat_result = _read_file_no_symlink_with_stat(
        path,
        label,
        reject_hard_links=reject_hard_links,
    )
    return content


def _raise_if_hard_linked_private_file_fd(fd: int, path: Path, label: str) -> None:
    stat_result = os.fstat(fd)
    if getattr(stat_result, "st_nlink", 1) > 1:
        raise RuntimeError(f"refusing to use hard-linked {label}: {path}")


def _secure_atomic_write_bytes(path: Path, payload: bytes) -> None:
    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, "legacy file")
    tmp_name = f".{name}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            fd = os.open(tmp_name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise RuntimeError(f"refusing to use unsafe temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(f"refusing to use non-regular temporary file: {path.with_name(tmp_name)}") from exc
            raise
        try:
            with os.fdopen(fd, "wb") as f:
                os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            tmp_name = ""
            try:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy file")
            except Exception:
                _unlink_legacy_entry_and_fsync(parent_fd, name, parent_path, "legacy file")
                raise
            _fsync_legacy_directory_fd(parent_fd, parent_path, "legacy file")
            try:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy file")
            except Exception:
                _unlink_legacy_entry_and_fsync(parent_fd, name, parent_path, "legacy file")
                raise
        except Exception:
            if tmp_name:
                _unlink_legacy_entry_and_fsync(parent_fd, tmp_name, parent_path, "legacy file")
            raise
    finally:
        os.close(parent_fd)


def _secure_atomic_write_text(path: Path, payload: str) -> None:
    _secure_atomic_write_bytes(path, payload.encode("utf-8"))


def _secure_atomic_json(path: Path, payload: Dict[str, object]) -> None:
    _secure_atomic_write_text(path, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _legacy_canonical_dns_name(value: str) -> str:
    host = value.strip().rstrip(".")
    if not host:
        return ""
    ip_literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    address_part, scope_separator, scope_id = ip_literal.partition("%")
    try:
        address = ipaddress.ip_address(address_part)
        if scope_separator:
            if address.version != 6 or not scope_id or "%" in scope_id:
                raise ValueError("invalid scoped IP literal")
            # Interface names can be case-sensitive. Canonicalize only the
            # numeric address and preserve the scope identifier byte-for-byte.
            return f"{address.compressed.lower()}%{scope_id}"
        return address.compressed.lower()
    except ValueError:
        pass
    try:
        return idna.encode(
            host,
            uts46=True,
            std3_rules=True,
        ).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError, ValueError):
        # Preserve legacy support for IP literals and unusual-but-accepted IMAP
        # host strings while canonicalizing ordinary DNS names.
        return host.lower()


def _legacy_canonical_account_target_identity(email: str) -> str:
    local_part, separator, domain = email.rpartition("@")
    if not separator:
        return email
    return f"{local_part}@{_legacy_canonical_dns_name(domain)}"


def legacy_server_endpoint(server: ServerConfig) -> Dict[str, object]:
    return {
        "host": server.host.strip().lower().rstrip("."),
        "port": int(server.port),
        "ssl": bool(server.ssl),
        "starttls": bool(server.starttls),
    }


def legacy_server_endpoint_digest(server: ServerConfig) -> str:
    payload = json.dumps(legacy_server_endpoint(server), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def subscribe_mailbox(imap: imaplib.IMAP4, mailbox: str) -> None:
    subscribe = getattr(imap, "subscribe", None)
    if not callable(subscribe):
        return
    try:
        result = subscribe(quote_mailbox_name(mailbox))
    except Exception as exc:
        logging.warning("[import] failed to subscribe mailbox %s: %s", mailbox, exc)
        return
    status = result[0] if isinstance(result, (tuple, list)) and result else result
    if isinstance(status, bytes):
        status = status.decode("ascii", errors="ignore")
    if isinstance(status, str) and status.upper() != "OK":
        logging.warning("[import] failed to subscribe mailbox %s: %s", mailbox, result)


@contextlib.contextmanager
def imap_connection(server: ServerConfig, account: Account) -> Iterator[imaplib.IMAP4]:
    """Context-managed IMAP connection.

    Handles SSL/STARTTLS negotiation and ensures logout on exit.
    """
    if not server.ssl and not server.starttls:
        raise RuntimeError("refusing to send IMAP login credentials over a cleartext connection; enable SSL or STARTTLS")
    if server.ssl:
        imap = imaplib.IMAP4_SSL(host=server.host, port=server.port, ssl_context=ssl.create_default_context())
    else:
        imap = imaplib.IMAP4(host=server.host, port=server.port)
    try:
        if (not server.ssl) and server.starttls:
            imap.starttls(ssl_context=ssl.create_default_context())
        imap.login(account.email, account.password)
        yield imap
    finally:
        with contextlib.suppress(Exception):
            imap.logout()


def _mailbox_sort_key(mailbox: str) -> Tuple[int, str]:
    return (0 if mailbox.upper() == "INBOX" else 1, mailbox.lower())


def _legacy_mailbox_path_segments(mailbox: str, delimiter: str) -> Tuple[str, ...]:
    if delimiter and delimiter in mailbox:
        segments = tuple(segment for segment in mailbox.split(delimiter) if segment)
        if segments:
            return segments
    return (mailbox,)


def _legacy_mailbox_metadata(
    mailbox: str,
    message_count: int,
    delimiter: str,
    uidvalidity: str = "",
    covered_by_regular_content: bool = False,
    source_attributes: Tuple[str, ...] = (),
) -> Dict[str, object]:
    payload: Dict[str, object] = {
        "mailbox": mailbox,
        "message_count": message_count,
    }
    if covered_by_regular_content:
        payload["covered_by_regular_content"] = True
    if source_attributes:
        payload["source_attributes"] = list(source_attributes)
    if uidvalidity:
        payload["uidvalidity"] = uidvalidity
    segments = _legacy_mailbox_path_segments(mailbox, delimiter)
    if len(segments) > 1:
        payload["source_delimiter"] = delimiter
        payload["source_path_segments"] = list(segments)
    return payload


def _legacy_export_state_mailbox_metadata(
    mailbox: str,
    path: str,
    message_count: int,
    delimiter: str,
    uidvalidity: str = "",
    covered_by_regular_content: bool = False,
    source_attributes: Tuple[str, ...] = (),
) -> Dict[str, object]:
    payload = _legacy_mailbox_metadata(
        mailbox,
        message_count,
        delimiter,
        uidvalidity,
        covered_by_regular_content,
        source_attributes,
    )
    payload["path"] = path
    return payload


def _legacy_validate_path_segments(value: object, mailbox: str, delimiter: object, label: str) -> Tuple[str, ...]:
    if value is None:
        if delimiter not in (None, ""):
            raise RuntimeError(f"{label}: source_delimiter without source_path_segments")
        return ()
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"{label}: invalid source_path_segments")
    segments: List[str] = []
    for segment in value:
        if not isinstance(segment, str) or not segment:
            raise RuntimeError(f"{label}: invalid source_path_segments")
        segments.append(segment)
    if delimiter is not None and not isinstance(delimiter, str):
        raise RuntimeError(f"{label}: invalid source_delimiter")
    if len(segments) > 1 and (not isinstance(delimiter, str) or not delimiter):
        raise RuntimeError(f"{label}: invalid source_delimiter")
    if isinstance(delimiter, str) and delimiter and delimiter.join(segments) != mailbox:
        raise RuntimeError(f"{label}: source_path_segments mismatch")
    if (not delimiter) and segments[0] != mailbox:
        raise RuntimeError(f"{label}: source_path_segments mismatch")
    return tuple(segments)


def _legacy_hierarchy_metadata(
    record: Mapping[str, object],
    mailbox: str,
    label: str,
) -> Tuple[str, Tuple[str, ...]]:
    segments = _legacy_validate_path_segments(
        record.get("source_path_segments"),
        mailbox,
        record.get("source_delimiter"),
        label,
    )
    if not segments:
        return "", ()
    delimiter = record.get("source_delimiter")
    return (delimiter if isinstance(delimiter, str) else "", segments)


def _legacy_uidvalidity_metadata(record: Mapping[str, object], label: str) -> str:
    value = record.get("uidvalidity")
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not _valid_legacy_uidvalidity(value):
        raise RuntimeError(f"{label}: invalid uidvalidity metadata")
    return value


def _valid_legacy_uidvalidity(value: str) -> bool:
    return bool(_LEGACY_UIDVALIDITY_RE.fullmatch(value) and int(value) <= _LEGACY_UIDVALIDITY_MAX)


def selected_uidvalidity(imap: imaplib.IMAP4) -> str:
    with contextlib.suppress(Exception):
        _typ, data = imap.response("UIDVALIDITY")
        if data and data[0]:
            value = data[0].decode(errors="ignore") if isinstance(data[0], bytes) else str(data[0])
            value = value.strip()
            if _valid_legacy_uidvalidity(value):
                return value
    return ""


def require_selected_uidvalidity(imap: imaplib.IMAP4, mailbox: str) -> str:
    uidvalidity = selected_uidvalidity(imap)
    if not uidvalidity:
        raise RuntimeError(f"Selected mailbox {mailbox} did not provide valid UIDVALIDITY")
    return uidvalidity


def _legacy_target_mailbox_name(source_mailbox: str, source_path_segments: Tuple[str, ...], target_delimiter: str) -> str:
    if len(source_path_segments) > 1 and target_delimiter:
        return target_delimiter.join(source_path_segments)
    return source_mailbox


def _legacy_target_hierarchy_delimiter(imap: imaplib.IMAP4) -> str:
    try:
        status, data = imap.list()
    except Exception:
        return ""
    status_text = status.decode("ascii", errors="ignore") if isinstance(status, bytes) else str(status)
    if status_text.upper() != "OK":
        return ""
    for raw in data or []:
        with contextlib.suppress(Exception):
            from .provider_ops import parse_list_entry

            info = parse_list_entry(raw)
            if info is not None and info.delimiter:
                return str(info.delimiter)
    return ""


def _list_mailboxes_with_special_use(imap: imaplib.IMAP4) -> Tuple[str, object]:
    def _normal_status(value: object) -> str:
        return value.decode("ascii", errors="ignore") if isinstance(value, bytes) else str(value)

    def _plain_list() -> Tuple[str, object]:
        status, data = imap.list()
        return _normal_status(status), data

    try:
        status, data = imap.list('""', '"*" RETURN (SPECIAL-USE)')
    except TypeError:
        return _plain_list()
    except imaplib.IMAP4.abort:
        raise
    except imaplib.IMAP4.error:
        return _plain_list()
    status_text = _normal_status(status)
    if status_text.upper() == "OK":
        return status_text, data
    return _plain_list()


def _list_selectable_mailbox_details(imap: imaplib.IMAP4) -> List[_LegacyMailboxEntry]:
    status, data = _list_mailboxes_with_special_use(imap)
    if status != "OK":
        raise RuntimeError("Failed to list mailboxes")
    mailboxes: List[_LegacyMailboxEntry] = []
    for raw in data or []:
        if raw is None:
            continue
        info = None
        with contextlib.suppress(Exception):
            from .provider_ops import parse_list_entry

            info = parse_list_entry(raw)
        if info is not None:
            attr_lowers = {attr.lower() for attr in info.attributes}
            if not attr_lowers & {"\\noselect", "\\nonexistent"}:
                mailboxes.append(_LegacyMailboxEntry(info.name, tuple(info.attributes), str(info.delimiter or "")))
            continue
        if not isinstance(raw, (bytes, bytearray)):
            continue
        line = raw.decode(errors="ignore").strip()
        attrs_raw = line[1 : line.find(")")] if line.startswith("(") and ")" in line else ""
        attrs = tuple(attr for attr in attrs_raw.split() if attr)
        if any(attr.lower() in {"\\noselect", "\\nonexistent"} for attr in attrs):
            continue
        m = re.findall(r'"([^"]+)"\s*$', line)
        if m:
            mailboxes.append(_LegacyMailboxEntry(
                decode_imap_utf7(m[0].replace(r"\"", '"').replace(r"\\", "\\")),
                attrs,
                "",
            ))
        else:
            parts = line.rsplit(" ", 1)
            if parts:
                candidate = parts[-1].strip().strip('"')
                if candidate:
                    mailboxes.append(_LegacyMailboxEntry(decode_imap_utf7(candidate), attrs, ""))
    unique: List[_LegacyMailboxEntry] = []
    seen = set()
    for entry in mailboxes:
        if entry.name not in seen:
            seen.add(entry.name)
            unique.append(entry)
    unique.sort(key=lambda item: _mailbox_sort_key(item.name))
    return unique


def _list_selectable_mailbox_entries(imap: imaplib.IMAP4) -> List[Tuple[str, Tuple[str, ...]]]:
    return [(entry.name, entry.attributes) for entry in _list_selectable_mailbox_details(imap)]


def _is_legacy_all_source_view(attributes: Tuple[str, ...]) -> bool:
    attr_lowers = {attr.lower() for attr in attributes}
    return "\\all" in attr_lowers


def _is_legacy_flagged_source_view(attributes: Tuple[str, ...]) -> bool:
    attr_lowers = {attr.lower() for attr in attributes}
    return "\\flagged" in attr_lowers


def _legacy_source_attributes_metadata(meta: Mapping[str, object], label: str) -> Tuple[str, ...]:
    raw = meta.get("source_attributes")
    if raw is None:
        return ()
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        raise RuntimeError(f"{label}: invalid source_attributes")
    return tuple(raw)


def _legacy_source_attributes_key(attributes: Tuple[str, ...]) -> frozenset[str]:
    return frozenset(attr.lower() for attr in attributes)


def _legacy_trusted_covered_by_regular_content(meta: Mapping[str, object], label: str) -> bool:
    if meta.get("covered_by_regular_content") is not True:
        return False
    attributes = _legacy_source_attributes_metadata(meta, label)
    if _is_legacy_all_source_view(attributes) or _is_legacy_flagged_source_view(attributes):
        return True
    raise RuntimeError(f"{label}: covered_by_regular_content requires source_attributes with \\All or \\Flagged")


def _should_skip_legacy_source_view(
    name: str,
    attributes: Tuple[str, ...],
    mailboxes: List[Tuple[str, Tuple[str, ...]]],
) -> bool:
    return False


def list_export_scope_mailboxes(imap: imaplib.IMAP4) -> List[str]:
    mailboxes = _list_selectable_mailbox_entries(imap)
    return [
        name
        for name, attrs in mailboxes
        if not _should_skip_legacy_source_view(name, attrs, mailboxes)
    ]


def list_all_mailboxes(imap: imaplib.IMAP4) -> List[str]:
    """Return a stable, de-duplicated, sorted list of mailbox names.

    Prefers a quoted name at the end of LIST lines; falls back to the last atom.
    INBOX is sorted first.
    """
    return [name for name, _attrs in _list_selectable_mailbox_entries(imap)]


def fetch_all_uids(imap: imaplib.IMAP4, mailbox: str) -> List[int]:
    """Select a mailbox and return all message UIDs in ascending order."""
    uids, _uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox)
    return uids


def _search_selected_uids(imap: imaplib.IMAP4, mailbox: str) -> List[int]:
    status, data = imap.uid("search", "ALL")
    if status != "OK":
        raise RuntimeError(f"Failed to search UIDs in {mailbox}")
    return parse_imap_uid_search_data(data, label=f"UID SEARCH response for {mailbox}")


def fetch_all_uids_and_uidvalidity(imap: imaplib.IMAP4, mailbox: str) -> Tuple[List[int], str]:
    """Select a mailbox and return all message UIDs plus the selected UIDVALIDITY."""
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Failed to select mailbox {mailbox}")
    uidvalidity = require_selected_uidvalidity(imap, mailbox)
    uids = _search_selected_uids(imap, mailbox)
    return uids, uidvalidity


def _canonical_legacy_flag_set(flags: Optional[str]) -> frozenset[str]:
    normalized = []
    for token in str(flags or "").split():
        if not token:
            continue
        normalized.append(token.upper() if token.startswith("\\") else token)
    return frozenset(normalized)


def _legacy_target_flag_set(flags: Optional[str]) -> frozenset[str]:
    return frozenset(flag for flag in _canonical_legacy_flag_set(flags) if flag != "\\RECENT")


def _legacy_flags_from_fetch_response(fetch_response: List[object]) -> Optional[str]:
    for part in fetch_response:
        meta = part[0] if isinstance(part, tuple) and part else part
        if isinstance(meta, (bytes, bytearray)):
            meta_str = bytes(meta).decode(errors="ignore")
        else:
            meta_str = str(meta or "")
        m_flags = re.search(r"FLAGS \((.*?)\)", meta_str, flags=re.IGNORECASE)
        if m_flags:
            return m_flags.group(1)
    return None


def _legacy_internaldate_from_fetch_response(fetch_response: List[object]) -> Optional[str]:
    for part in fetch_response:
        meta = part[0] if isinstance(part, tuple) and part else part
        if isinstance(meta, (bytes, bytearray)):
            meta_str = bytes(meta).decode(errors="ignore")
        else:
            meta_str = str(meta or "")
        match = re.search(r'INTERNALDATE\s+"([^"]+)"', meta_str, flags=re.IGNORECASE)
        if match:
            return _normalized_legacy_internaldate(match.group(1))
    return None


def _legacy_fetch_metadata_values(meta_chunks: List[str]) -> Tuple[Optional[str], Optional[str]]:
    meta_str = " ".join(chunk for chunk in meta_chunks if chunk)
    flags: Optional[str] = None
    internaldate: Optional[str] = None
    m_flags = re.search(r"FLAGS \((.*?)\)", meta_str, flags=re.IGNORECASE)
    if m_flags:
        flags = m_flags.group(1)
    m_int = re.search(r'INTERNALDATE\s+"([^"]+)"', meta_str, flags=re.IGNORECASE)
    if m_int:
        internaldate = _normalized_legacy_internaldate(m_int.group(1))
    return flags, internaldate


def _legacy_fetch_metadata_for_uid(
    fetch_response: List[object],
    expected_uid: int,
) -> Tuple[Optional[str], Optional[str]]:
    meta_chunks: List[str] = []
    active_expected = False
    for part in fetch_response:
        meta = part[0] if isinstance(part, tuple) and part else part
        if isinstance(meta, (bytes, bytearray)):
            meta_str = bytes(meta).decode(errors="ignore")
        else:
            meta_str = str(meta or "")
        if not meta_str:
            continue
        response_uids = _fetch_response_uids(meta_str)
        if response_uids:
            if expected_uid in response_uids:
                if any(uid != expected_uid for uid in response_uids):
                    raise RuntimeError(f"fetch response for UID {expected_uid} included multiple UIDs")
                meta_chunks.append(meta_str)
                active_expected = True
            else:
                active_expected = False
            continue
        if _FETCH_RESPONSE_START_RE.match(meta_str):
            active_expected = False
            continue
        if active_expected:
            meta_chunks.append(meta_str)
    if not meta_chunks:
        raise RuntimeError(f"fetch response for UID {expected_uid} did not include UID metadata")
    return _legacy_fetch_metadata_values(meta_chunks)


def _fetch_response_sequence_number(meta_str: str) -> Optional[int]:
    match = _FETCH_RESPONSE_START_RE.match(meta_str)
    if not match:
        return None
    with contextlib.suppress(ValueError):
        return int(meta_str[: match.end() - 1].strip())
    return None


def _imap_sequence_number(value: bytes) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise RuntimeError(f"invalid IMAP sequence number {value!r}") from exc
    if number <= 0:
        raise RuntimeError(f"invalid IMAP sequence number {value!r}")
    return number


def _legacy_fetch_body_part_matches_sequence(part: object, expected_sequence: bytes) -> bool:
    if not (isinstance(part, tuple) and len(part) == 2):
        return False
    meta = part[0]
    if isinstance(meta, (bytes, bytearray)):
        meta_str = bytes(meta).decode(errors="ignore")
    else:
        meta_str = str(meta or "")
    sequence_num = _fetch_response_sequence_number(meta_str)
    return sequence_num == _imap_sequence_number(expected_sequence)


def _legacy_search_target_uids(imap: imaplib.IMAP4, message_id: str, *, mailbox: str) -> List[int]:
    if message_id:
        quoted_message_id = quote_imap_search_value(message_id)
        status, search_data = imap.uid("search", "HEADER", "Message-ID", quoted_message_id)
    else:
        status, search_data = imap.uid("search", "ALL")
    if status != "OK" or not search_data or not search_data[0]:
        return []
    return parse_imap_uid_search_data(search_data, label=f"target UID SEARCH response for {mailbox}")


def _legacy_fetch_metadata_for_sequence(
    fetch_response: List[object],
    expected_sequence: bytes,
) -> Tuple[Optional[str], Optional[str]]:
    expected_num = _imap_sequence_number(expected_sequence)
    meta_chunks: List[str] = []
    active_expected = False
    for part in fetch_response:
        meta = part[0] if isinstance(part, tuple) and part else part
        if isinstance(meta, (bytes, bytearray)):
            meta_str = bytes(meta).decode(errors="ignore")
        else:
            meta_str = str(meta or "")
        if not meta_str:
            continue
        sequence_num = _fetch_response_sequence_number(meta_str)
        if sequence_num is not None:
            if sequence_num == expected_num:
                meta_chunks.append(meta_str)
                active_expected = True
            else:
                active_expected = False
            continue
        if active_expected:
            meta_chunks.append(meta_str)
    if not meta_chunks:
        raise RuntimeError(f"fetch response for sequence {expected_num} did not include matching metadata")
    return _legacy_fetch_metadata_values(meta_chunks)


def _legacy_metadata_for_fetch_body_part(
    fetch_response: List[object],
    body_part_index: int,
) -> Tuple[Optional[str], Optional[str]]:
    meta_chunks: List[str] = []
    active = False
    for index, part in enumerate(fetch_response):
        if isinstance(part, tuple) and len(part) == 2:
            active = index == body_part_index
            if active:
                meta = part[0]
                if isinstance(meta, (bytes, bytearray)):
                    meta_str = bytes(meta).decode(errors="ignore")
                else:
                    meta_str = str(meta or "")
                if meta_str:
                    meta_chunks.append(meta_str)
            continue
        if not active or not isinstance(part, (bytes, bytearray)):
            continue
        meta_str = bytes(part).decode(errors="ignore")
        if _FETCH_RESPONSE_START_RE.match(meta_str):
            active = False
            continue
        meta_chunks.append(meta_str)
    return _legacy_fetch_metadata_values(meta_chunks)


def _legacy_missing_target_flags(expected_flags: Optional[str], actual_flags: Optional[str]) -> List[str]:
    expected = _legacy_target_flag_set(expected_flags)
    if not expected:
        return []
    actual = _legacy_target_flag_set(actual_flags)
    return sorted(expected - actual, key=str.upper)


def _merge_legacy_flag_strings(existing_flags: str, additional_flags: str) -> str:
    merged: List[str] = []
    seen: set[str] = set()
    for flags in (existing_flags, additional_flags):
        for token in str(flags or "").split():
            if not token or token.upper() == "\\RECENT":
                continue
            canonical = next(iter(_canonical_legacy_flag_set(token)), token)
            if canonical in seen:
                continue
            seen.add(canonical)
            merged.append(token)
    return " ".join(merged)


def _legacy_flags_arg_from_tokens(tokens: Iterable[str]) -> str:
    flags = [flag for flag in tokens if flag and flag.strip()]
    return "(" + " ".join(flags) + ")" if flags else ""


def _fetch_legacy_flags_for_uid(imap: imaplib.IMAP4, mailbox: str, uid: int) -> str:
    status, data = imap.uid("fetch", str(uid), "(UID FLAGS)")
    if status != "OK":
        raise RuntimeError(f"fetch flags failed in {mailbox} for UID {uid}")
    flags, _internaldate = _legacy_fetch_metadata_for_uid(list(data or []), int(uid))
    if flags is None:
        raise RuntimeError(f"fetch returned no flags in {mailbox} for UID {uid}")
    return flags


def verify_legacy_mailbox_uid_set_stable(
    imap: imaplib.IMAP4,
    mailbox: str,
    initial_uids: List[int],
    uidvalidity: str,
    initial_flags_by_uid: Optional[Mapping[int, str]] = None,
) -> None:
    status, response = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Failed to reselect mailbox {mailbox} after export: {response}")
    final_uidvalidity = require_selected_uidvalidity(imap, mailbox)
    if final_uidvalidity != uidvalidity:
        raise RuntimeError(
            f"UIDVALIDITY changed during export of {mailbox}: "
            f"{uidvalidity} -> {final_uidvalidity}"
        )
    final_uids = _search_selected_uids(imap, mailbox)
    if final_uids != initial_uids:
        raise RuntimeError(f"UID set changed during export of {mailbox}")
    if initial_flags_by_uid is not None:
        expected_uids = sorted(int(uid) for uid in initial_flags_by_uid)
        if expected_uids != initial_uids:
            raise RuntimeError(f"internal flag snapshot mismatch during export of {mailbox}")
        for uid in initial_uids:
            final_flags = _fetch_legacy_flags_for_uid(imap, mailbox, uid)
            if _canonical_legacy_flag_set(final_flags) != _canonical_legacy_flag_set(initial_flags_by_uid[uid]):
                raise RuntimeError(f"FLAGS changed during export of {mailbox} for UID {uid}")


def _legacy_import_journal_path(account_dir: Path) -> Path:
    return account_dir / "import.journal.jsonl"


def _legacy_reset_state_path(account_dir: Path) -> Path:
    return account_dir / LEGACY_RESET_STATE_FILENAME


def _legacy_global_state_root() -> Path:
    return _legacy_normalized_absolute_path(
        LEGACY_GLOBAL_STATE_PARENT
        / f"{LEGACY_GLOBAL_STATE_DIR_PREFIX}-{_legacy_effective_uid()}"
    )


def _legacy_global_state_namespace_dir() -> Path:
    return _legacy_global_state_root() / LEGACY_GLOBAL_STATE_NAMESPACE


def _legacy_global_lock_dir() -> Path:
    return _legacy_global_state_namespace_dir() / LEGACY_GLOBAL_LOCK_DIRNAME


def _legacy_global_reset_dir() -> Path:
    return _legacy_global_state_namespace_dir() / LEGACY_GLOBAL_RESET_DIRNAME


def _ensure_legacy_global_state_dirs() -> None:
    root = _legacy_global_state_root()
    namespace = _legacy_global_state_namespace_dir()
    ensure_private_dir(root, label="legacy global state directory")
    ensure_private_dir(namespace, label="legacy global state namespace")
    ensure_private_dir(_legacy_global_lock_dir(), label="legacy global target lock directory")
    ensure_private_dir(_legacy_global_reset_dir(), label="legacy global reset state directory")


def _legacy_global_reset_state_path(server: ServerConfig, account: Account) -> Path:
    return _legacy_global_reset_dir() / f"legacy-{_legacy_target_coordination_id(server, account)}.json"


def _legacy_reset_state_stat_issue(
    stat_result: os.stat_result,
    effective_uid: int,
) -> Optional[str]:
    if not stat.S_ISREG(stat_result.st_mode):
        return "is not a regular file"
    if getattr(stat_result, "st_nlink", 1) != 1:
        return f"has {getattr(stat_result, 'st_nlink', 0)} hard links"
    if stat_result.st_uid != effective_uid:
        return f"is owned by UID {stat_result.st_uid}, not effective UID {effective_uid}"
    mode = stat.S_IMODE(stat_result.st_mode)
    if mode != PRIVATE_FILE_MODE:
        return f"has unsafe mode {mode:#05o}, expected {PRIVATE_FILE_MODE:#05o}"
    return None


def _require_legacy_reset_state_visible(
    path: Path,
    pinned_stat: os.stat_result,
    label: str,
) -> None:
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, label)
    try:
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, label)
        try:
            visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(f"{label} changed while in use: {path}") from exc
        issue = _legacy_reset_state_stat_issue(visible_stat, _legacy_effective_uid())
        if issue:
            raise RuntimeError(f"refusing to use {label} {path}: {issue}")
        if (
            visible_stat.st_dev != pinned_stat.st_dev
            or visible_stat.st_ino != pinned_stat.st_ino
        ):
            raise RuntimeError(f"{label} changed while in use: {path}")
    finally:
        os.close(parent_fd)


def _legacy_reset_state_bound_server(
    state: Mapping[str, object],
    path: Path,
) -> ServerConfig:
    endpoint = state.get("target_server")
    expected_keys = {"host", "port", "ssl", "starttls"}
    if not isinstance(endpoint, dict) or set(endpoint) != expected_keys:
        raise RuntimeError(f"legacy reset state has invalid target_server in {path}")
    host = endpoint.get("host")
    port = endpoint.get("port")
    use_ssl = endpoint.get("ssl")
    starttls = endpoint.get("starttls")
    if not isinstance(host, str) or not host:
        raise RuntimeError(f"legacy reset state has invalid target_server in {path}")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError(f"legacy reset state has invalid target_server in {path}")
    if type(use_ssl) is not bool or type(starttls) is not bool or use_ssl == starttls:
        raise RuntimeError(f"legacy reset state has invalid target_server in {path}")
    bound_server = ServerConfig(
        host=host,
        port=port,
        ssl=use_ssl,
        starttls=starttls,
    )
    if endpoint != legacy_server_endpoint(bound_server):
        raise RuntimeError(f"legacy reset state has non-canonical target_server in {path}")
    return bound_server


def _parse_legacy_reset_state(
    raw: bytes,
    path: Path,
    *,
    account: Account,
    server: ServerConfig,
    expected_owner_root: Optional[Path],
    allow_legacy_schema: bool,
    allow_unrelated_target: bool = False,
) -> Dict[str, object]:
    try:
        state = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"legacy reset state is malformed: {path}: {exc}") from exc
    if not isinstance(state, dict):
        raise RuntimeError(f"legacy reset state is not an object: {path}")
    common_keys = {
        "schema_version",
        "status",
        "phase",
        "account",
        "target",
        "target_server",
        "started_at",
        "updated_at",
    }
    schema_version = state.get("schema_version")
    if schema_version == 1 and allow_legacy_schema:
        expected_keys = common_keys
    elif schema_version == 2:
        expected_keys = common_keys | {"owner_staging_root", "reset_id"}
    else:
        raise RuntimeError(f"legacy reset state has unsupported schema_version in {path}")
    unknown_keys = sorted(str(key) for key in set(state) - expected_keys)
    missing_keys = sorted(expected_keys - set(state))
    if unknown_keys:
        raise RuntimeError(
            f"legacy reset state has unknown field(s) in {path}: " + ", ".join(unknown_keys)
        )
    if missing_keys:
        raise RuntimeError(
            f"legacy reset state is missing field(s) in {path}: " + ", ".join(missing_keys)
        )
    if state.get("status") != "in_progress":
        raise RuntimeError(f"legacy reset state has invalid status in {path}")
    phase = state.get("phase")
    if not isinstance(phase, str) or phase not in _LEGACY_RESET_STATE_PHASES:
        raise RuntimeError(f"legacy reset state has invalid phase in {path}")
    state_account = state.get("account")
    if state_account != account.email:
        raise RuntimeError(
            f"legacy reset state account mismatch in {path}: "
            f"state={state_account!r} config={account.email!r}"
        )
    bound_server = _legacy_reset_state_bound_server(state, path)
    bound_target = _legacy_import_target_id(bound_server, account)
    if state.get("target") != bound_target:
        raise RuntimeError(
            f"legacy reset state target does not match target_server in {path}"
        )
    expected_target = _legacy_import_target_id(server, account)
    expected_server = legacy_server_endpoint(server)
    if (
        bound_target != expected_target
        or state.get("target_server") != expected_server
    ) and not allow_unrelated_target:
        raise RuntimeError(
            f"legacy reset state target mismatch in {path}; rerun with the original target configuration"
        )
    for timestamp_field in ("started_at", "updated_at"):
        value = state.get(timestamp_field)
        if type(value) is not int or value < 0:
            raise RuntimeError(f"legacy reset state has invalid {timestamp_field} in {path}")
    if schema_version == 2:
        owner_root = state.get("owner_staging_root")
        if not isinstance(owner_root, str) or not owner_root:
            raise RuntimeError(f"legacy reset state has invalid owner_staging_root in {path}")
        owner_path = Path(owner_root)
        if (
            not owner_path.is_absolute()
            or str(_legacy_normalized_absolute_path(owner_path)) != owner_root
        ):
            raise RuntimeError(f"legacy reset state has invalid owner_staging_root in {path}")
        if expected_owner_root is not None:
            expected_owner = str(_legacy_normalized_absolute_path(expected_owner_root))
            if owner_root != expected_owner:
                raise RuntimeError(
                    f"legacy reset state owner staging root mismatch in {path}: "
                    f"state={owner_root!r} config={expected_owner!r}"
                )
        reset_id = state.get("reset_id")
        if not isinstance(reset_id, str) or _SHA256_HEX_RE.fullmatch(reset_id) is None:
            raise RuntimeError(f"legacy reset state has invalid reset_id in {path}")
    return state


def _load_legacy_reset_state_with_stat(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    *,
    allow_unrelated_target: bool = False,
) -> Tuple[Optional[Dict[str, object]], Optional[os.stat_result]]:
    path = _legacy_reset_state_path(account_dir)
    _raise_if_symlink(account_dir, "legacy account directory")
    if not account_dir.exists():
        return None, None
    if not account_dir.is_dir():
        raise RuntimeError(f"legacy account path is not a directory: {account_dir}")
    try:
        raw, state_stat = _read_file_no_symlink_with_stat(
            path,
            "legacy reset state",
            reject_hard_links=True,
        )
    except FileNotFoundError:
        return None, None
    issue = _legacy_reset_state_stat_issue(state_stat, _legacy_effective_uid())
    if issue:
        raise RuntimeError(f"refusing to use legacy reset state {path}: {issue}")
    _require_legacy_reset_state_visible(path, state_stat, "legacy reset state")
    state = _parse_legacy_reset_state(
        raw,
        path,
        account=account,
        server=server,
        expected_owner_root=account_dir.parent,
        allow_legacy_schema=True,
        allow_unrelated_target=allow_unrelated_target,
    )
    return state, state_stat


def _load_legacy_reset_state(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    *,
    allow_unrelated_target: bool = False,
) -> Optional[Dict[str, object]]:
    state, _state_stat = _load_legacy_reset_state_with_stat(
        account_dir,
        account,
        server,
        allow_unrelated_target=allow_unrelated_target,
    )
    return state


def _load_legacy_global_reset_state_with_stat(
    account: Account,
    server: ServerConfig,
) -> Tuple[Optional[Dict[str, object]], Optional[os.stat_result]]:
    _ensure_legacy_global_state_dirs()
    path = _legacy_global_reset_state_path(server, account)
    try:
        raw, state_stat = _read_file_no_symlink_with_stat(
            path,
            "legacy global reset state",
            reject_hard_links=True,
        )
    except FileNotFoundError:
        return None, None
    issue = _legacy_reset_state_stat_issue(state_stat, _legacy_effective_uid())
    if issue:
        raise RuntimeError(f"refusing to use legacy global reset state {path}: {issue}")
    _require_legacy_reset_state_visible(path, state_stat, "legacy global reset state")
    state = _parse_legacy_reset_state(
        raw,
        path,
        account=account,
        server=server,
        expected_owner_root=None,
        allow_legacy_schema=False,
    )
    return state, state_stat


def _load_legacy_global_reset_state(
    account: Account,
    server: ServerConfig,
) -> Optional[Dict[str, object]]:
    state, _state_stat = _load_legacy_global_reset_state_with_stat(account, server)
    return state


def _legacy_reset_owner_root(account_dir: Path) -> str:
    return str(_legacy_normalized_absolute_path(account_dir.parent))


def _legacy_reset_states_identify_same_reset(
    first: Mapping[str, object],
    second: Mapping[str, object],
) -> bool:
    keys = (
        "schema_version",
        "status",
        "account",
        "target",
        "target_server",
        "owner_staging_root",
        "reset_id",
        "started_at",
    )
    return all(first.get(key) == second.get(key) for key in keys)


def _legacy_v1_state_matches_global(
    local_state: Mapping[str, object],
    global_state: Mapping[str, object],
) -> bool:
    keys = (
        "status",
        "phase",
        "account",
        "target",
        "target_server",
        "started_at",
    )
    return all(local_state.get(key) == global_state.get(key) for key in keys)


def _persist_legacy_reset_state_file(
    path: Path,
    state: Dict[str, object],
    *,
    account: Account,
    server: ServerConfig,
    global_state: bool,
) -> None:
    _secure_atomic_json(path, state)
    if global_state:
        persisted = _load_legacy_global_reset_state(account, server)
    else:
        persisted = _load_legacy_reset_state(path.parent, account, server)
    if persisted != state:
        raise RuntimeError(f"legacy reset state changed while updating: {path}")


def _new_legacy_reset_state(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    *,
    phase: str,
    started_at: int,
    reset_id: str,
) -> Dict[str, object]:
    if phase not in _LEGACY_RESET_STATE_PHASES:
        raise ValueError(f"invalid legacy reset state phase: {phase}")
    return {
        "schema_version": 2,
        "status": "in_progress",
        "phase": phase,
        "account": account.email,
        "target": _legacy_import_target_id(server, account),
        "target_server": legacy_server_endpoint(server),
        "owner_staging_root": _legacy_reset_owner_root(account_dir),
        "reset_id": reset_id,
        "started_at": started_at,
        "updated_at": int(time.time()),
    }


def _write_legacy_reset_state_pair(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    state: Dict[str, object],
) -> None:
    # The global gate is created/advanced first and removed last. A crash can
    # therefore leave the local evidence lagging, but cannot open another root.
    _persist_legacy_reset_state_file(
        _legacy_global_reset_state_path(server, account),
        state,
        account=account,
        server=server,
        global_state=True,
    )
    _persist_legacy_reset_state_file(
        _legacy_reset_state_path(account_dir),
        state,
        account=account,
        server=server,
        global_state=False,
    )


def _legacy_reset_gate_error(account: Account, exc: Exception) -> LegacyResetGateError:
    return LegacyResetGateError(
        f"invalid legacy reset state for {account.email}: {exc}"
    )


def _require_legacy_reset_gate_open(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    *,
    allow_reset_resume: bool = False,
    allow_unrelated_local_target: bool = False,
) -> None:
    if allow_reset_resume and allow_unrelated_local_target:
        raise ValueError(
            "reset resume cannot ignore local state for another target"
        )
    try:
        local_state = _load_legacy_reset_state(
            account_dir,
            account,
            server,
            allow_unrelated_target=allow_unrelated_local_target,
        )
        global_state = _load_legacy_global_reset_state(account, server)
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc

    if (
        allow_unrelated_local_target
        and local_state is not None
    ):
        local_bound_server = _legacy_reset_state_bound_server(
            local_state,
            _legacy_reset_state_path(account_dir),
        )
        local_is_for_contacted_target = (
            _legacy_target_coordination_id(local_bound_server, account)
            == _legacy_target_coordination_id(server, account)
        )
        # The local filename is retained for compatibility and therefore cannot
        # be endpoint-keyed. A remote action on another endpoint may disregard
        # it only after the secure loader proves its complete self-binding.
        if not local_is_for_contacted_target:
            local_state = None

    owner_root = _legacy_reset_owner_root(account_dir)
    if global_state is not None:
        global_owner = str(global_state["owner_staging_root"])
        if global_owner != owner_root:
            raise LegacyResetGateError(
                f"legacy reset is owned by staging root {global_owner!r} for "
                f"{account.email}; resume there with the original target configuration and --reset"
            )
        if local_state is not None:
            if local_state.get("schema_version") == 1:
                states_match = _legacy_v1_state_matches_global(local_state, global_state)
            else:
                local_phase = str(local_state.get("phase"))
                global_phase = str(global_state.get("phase"))
                states_match = _legacy_reset_states_identify_same_reset(
                    local_state,
                    global_state,
                ) and (
                    local_phase == global_phase
                    or (
                        allow_reset_resume
                        and _LEGACY_RESET_PHASE_ORDER[local_phase]
                        < _LEGACY_RESET_PHASE_ORDER[global_phase]
                    )
                )
            if not states_match:
                raise LegacyResetGateError(
                    f"local and global legacy reset state disagree for {account.email}; "
                    "rerun from the owner staging root with --reset"
                )
        if allow_reset_resume:
            return
        raise LegacyResetGateError(
            f"legacy reset is in progress for {account.email} at phase "
            f"{global_state['phase']}; rerun import from staging root {global_owner!r} "
            "with the original target configuration and --reset"
        )

    if local_state is not None and not allow_reset_resume:
        raise LegacyResetGateError(
            f"legacy reset is in progress for {account.email} at phase "
            f"{local_state['phase']}; rerun import with the original target "
            "configuration and --reset"
        )


def legacy_reset_state_issues(
    in_root: Path,
    accounts: Iterable[Account],
    server: ServerConfig,
    *,
    allow_resume: bool = False,
    allow_unrelated_local_target: bool = False,
) -> List[str]:
    """Return reset-state gates without contacting the target server."""

    issues: List[str] = []
    for account in accounts:
        try:
            _require_legacy_reset_gate_open(
                in_root / sanitize_for_path(account.email),
                account,
                server,
                allow_reset_resume=allow_resume,
                allow_unrelated_local_target=allow_unrelated_local_target,
            )
        except LegacyResetGateError as exc:
            issues.append(str(exc))
    return issues


def _require_legacy_global_reset_gate_open(
    account: Account,
    server: ServerConfig,
) -> None:
    try:
        global_state = _load_legacy_global_reset_state(account, server)
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc
    if global_state is not None:
        raise LegacyResetGateError(
            f"legacy reset is in progress for {account.email} at phase "
            f"{global_state['phase']}; rerun import from staging root "
            f"{global_state['owner_staging_root']!r} with the original target "
            "configuration and --reset"
        )


def legacy_global_reset_state_issues(
    accounts: Iterable[Account],
    server: ServerConfig,
) -> List[str]:
    """Return authoritative global reset gates without requiring staged data."""

    issues: List[str] = []
    for account in accounts:
        try:
            _require_legacy_global_reset_gate_open(account, server)
        except LegacyResetGateError as exc:
            issues.append(str(exc))
    return issues


def _begin_legacy_reset_state(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
) -> Dict[str, object]:
    _raise_if_symlink(account_dir, "legacy account directory")
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    ensure_private_dir(account_dir, label="legacy account directory")
    try:
        local_state = _load_legacy_reset_state(account_dir, account, server)
        global_state = _load_legacy_global_reset_state(account, server)
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc

    owner_root = _legacy_reset_owner_root(account_dir)
    if global_state is not None and global_state.get("owner_staging_root") != owner_root:
        raise LegacyResetGateError(
            f"legacy reset is owned by staging root "
            f"{global_state.get('owner_staging_root')!r} for {account.email}; "
            "resume there with the original target configuration and --reset"
        )

    if global_state is not None:
        try:
            if local_state is None:
                _persist_legacy_reset_state_file(
                    _legacy_reset_state_path(account_dir),
                    global_state,
                    account=account,
                    server=server,
                    global_state=False,
                )
            elif local_state.get("schema_version") == 1:
                if not _legacy_v1_state_matches_global(local_state, global_state):
                    raise RuntimeError("local legacy reset evidence does not match the global gate")
                _persist_legacy_reset_state_file(
                    _legacy_reset_state_path(account_dir),
                    global_state,
                    account=account,
                    server=server,
                    global_state=False,
                )
            else:
                if not _legacy_reset_states_identify_same_reset(local_state, global_state):
                    raise RuntimeError("local legacy reset evidence identifies a different reset")
                local_phase = str(local_state.get("phase"))
                global_phase = str(global_state.get("phase"))
                if _LEGACY_RESET_PHASE_ORDER[local_phase] > _LEGACY_RESET_PHASE_ORDER[global_phase]:
                    raise RuntimeError("local legacy reset evidence is ahead of the global gate")
                if local_state != global_state:
                    if local_phase == global_phase:
                        raise RuntimeError("local legacy reset evidence differs from the global gate")
                    _persist_legacy_reset_state_file(
                        _legacy_reset_state_path(account_dir),
                        global_state,
                        account=account,
                        server=server,
                        global_state=False,
                    )
        except Exception as exc:
            raise _legacy_reset_gate_error(account, exc) from exc
        logging.warning(
            "[import-reset] %s: resuming interrupted reset from phase %s",
            account.email,
            global_state["phase"],
        )
        return global_state

    try:
        if local_state is not None:
            if local_state.get("schema_version") == 2:
                adopted = dict(local_state)
            else:
                adopted = _new_legacy_reset_state(
                    account_dir,
                    account,
                    server,
                    phase=str(local_state["phase"]),
                    started_at=int(local_state["started_at"]),
                    reset_id=hashlib.sha256(os.urandom(32)).hexdigest(),
                )
            _write_legacy_reset_state_pair(account_dir, account, server, adopted)
            logging.warning(
                "[import-reset] %s: adopted local interrupted reset evidence at phase %s",
                account.email,
                adopted["phase"],
            )
            return adopted

        state = _new_legacy_reset_state(
            account_dir,
            account,
            server,
            phase="prepared",
            started_at=int(time.time()),
            reset_id=hashlib.sha256(os.urandom(32)).hexdigest(),
        )
        _write_legacy_reset_state_pair(account_dir, account, server, state)
        return state
    except LegacyResetGateError:
        raise
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc


def _transition_legacy_reset_state(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    state: Mapping[str, object],
    phase: str,
) -> Dict[str, object]:
    current_phase = state.get("phase")
    allowed_transition = {
        ("prepared", "journal_archived"),
        ("journal_archived", "reset_started"),
    }
    if (current_phase, phase) not in allowed_transition:
        raise RuntimeError(
            f"invalid legacy reset state transition for {account.email}: "
            f"{current_phase!r} -> {phase!r}"
        )
    try:
        local_state = _load_legacy_reset_state(account_dir, account, server)
        global_state = _load_legacy_global_reset_state(account, server)
        if local_state != dict(state) or global_state != dict(state):
            raise RuntimeError(
                f"legacy reset state changed before transition for {account.email}"
            )
        started_at = state.get("started_at")
        reset_id = state.get("reset_id")
        if (
            type(started_at) is not int
            or started_at < 0
            or not isinstance(reset_id, str)
        ):
            raise RuntimeError(f"invalid legacy reset state transition for {account.email}")
        next_state = _new_legacy_reset_state(
            account_dir,
            account,
            server,
            phase=phase,
            started_at=started_at,
            reset_id=reset_id,
        )
        _write_legacy_reset_state_pair(account_dir, account, server, next_state)
        return next_state
    except LegacyResetGateError:
        raise
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc


def _unlink_expected_legacy_reset_state(
    path: Path,
    state: Optional[Dict[str, object]],
    state_stat: Optional[os.stat_result],
    expected_state: Mapping[str, object],
    *,
    label: str,
) -> None:
    if state is None or state_stat is None:
        raise RuntimeError(f"{label} disappeared before successful reset completion: {path}")
    if state.get("phase") != "reset_started" or state != dict(expected_state):
        raise RuntimeError(f"{label} changed before successful reset completion: {path}")
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, label)
    try:
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, label)
        try:
            visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"{label} disappeared before successful reset completion: {path}"
            ) from exc
        issue = _legacy_reset_state_stat_issue(visible_stat, _legacy_effective_uid())
        if issue:
            raise RuntimeError(f"refusing to clear {label} {path}: {issue}")
        if (
            visible_stat.st_dev != state_stat.st_dev
            or visible_stat.st_ino != state_stat.st_ino
        ):
            raise RuntimeError(f"{label} changed before successful reset completion: {path}")
        os.unlink(name, dir_fd=parent_fd)
        _fsync_legacy_directory_fd(parent_fd, parent_path, label)
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, label)
    finally:
        os.close(parent_fd)


def _clear_legacy_reset_state(
    account_dir: Path,
    account: Account,
    server: ServerConfig,
    expected_state: Mapping[str, object],
) -> None:
    try:
        local_state, local_stat = _load_legacy_reset_state_with_stat(
            account_dir,
            account,
            server,
        )
        global_state, global_stat = _load_legacy_global_reset_state_with_stat(
            account,
            server,
        )
        _unlink_expected_legacy_reset_state(
            _legacy_reset_state_path(account_dir),
            local_state,
            local_stat,
            expected_state,
            label="legacy reset state",
        )
        _unlink_expected_legacy_reset_state(
            _legacy_global_reset_state_path(server, account),
            global_state,
            global_stat,
            expected_state,
            label="legacy global reset state",
        )
    except LegacyResetGateError:
        raise
    except Exception as exc:
        raise _legacy_reset_gate_error(account, exc) from exc


def _stop_requested(stop_event: Optional[object]) -> bool:
    return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())


def _raise_if_stopped(stop_event: Optional[object], label: str) -> None:
    if _stop_requested(stop_event):
        raise RuntimeError(f"{label}: stop requested before completion")


def archive_legacy_import_journal_for_reset(account_dir: Path) -> Optional[Path]:
    _raise_if_symlink(account_dir, "legacy account directory")
    path = _legacy_import_journal_path(account_dir)
    _raise_if_symlink(path, "legacy import journal")
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, "legacy import journal")
    try:
        _journal_rows, journal_stat = _load_legacy_import_journal_with_stat(account_dir, repair_trailing=False)
        if journal_stat is None:
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
            return None
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
        stamp = int(time.time())
        for idx in range(1000):
            suffix = f"reset-{stamp}" if idx == 0 else f"reset-{stamp}-{idx}"
            archive_name = f"import.journal.{suffix}.jsonl"
            try:
                os.stat(archive_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
                try:
                    visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise RuntimeError(f"legacy import journal changed during archive: {path}") from exc
                if (
                    visible_stat.st_dev != journal_stat.st_dev
                    or visible_stat.st_ino != journal_stat.st_ino
                    or stat.S_ISLNK(visible_stat.st_mode)
                    or not stat.S_ISREG(visible_stat.st_mode)
                    or getattr(visible_stat, "st_nlink", 1) > 1
                ):
                    raise RuntimeError(f"legacy import journal changed during archive: {path}")
                os.rename(name, archive_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
                _fsync_legacy_directory_fd(parent_fd, parent_path, "legacy import journal")
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
                return account_dir / archive_name
        raise RuntimeError(f"unable to archive import journal for reset: {path}")
    finally:
        os.close(parent_fd)


def _legacy_import_target_id(server: ServerConfig, account: Account) -> str:
    endpoint = legacy_server_endpoint(server)
    seed = {
        "host": endpoint["host"],
        "port": endpoint["port"],
        "ssl": endpoint["ssl"],
        "starttls": endpoint["starttls"],
        # This durable identifier is stored in existing import journals. Keep
        # its historical byte semantics; global coordination uses a separate
        # canonical identity below.
        "account": account.email,
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()


def _legacy_target_coordination_id(server: ServerConfig, account: Account) -> str:
    seed = {
        "host": _legacy_canonical_dns_name(server.host),
        "port": int(server.port),
        "ssl": bool(server.ssl),
        "starttls": bool(server.starttls),
        # RFC email domains are case-insensitive. Preserve the local part
        # because a generic IMAP server can treat usernames as case-sensitive.
        "account": _legacy_canonical_account_target_identity(account.email),
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()


def _legacy_target_lock_path(server: ServerConfig, account: Account) -> Path:
    return _legacy_global_lock_dir() / f"legacy-{_legacy_target_coordination_id(server, account)}.lock"


def _legacy_import_lock_path(server: ServerConfig, account: Account, in_root: Path) -> Path:
    del in_root  # Compatibility shim: target locks are independent of staging roots.
    return _legacy_target_lock_path(server, account)


def _secure_existing_legacy_import_root(in_root: Path) -> None:
    root_fd, root_path = _open_legacy_dir(in_root, "legacy import root")
    try:
        _raise_if_legacy_parent_replaced(root_path, root_fd, "legacy import root")
        _secure_legacy_private_dir_fd(root_fd, root_path, "legacy import root")
        _raise_if_legacy_parent_replaced(root_path, root_fd, "legacy import root")
    finally:
        os.close(root_fd)


def _legacy_import_lock_stat_issue(stat_result: os.stat_result, effective_uid: int) -> Optional[str]:
    if not stat.S_ISREG(stat_result.st_mode):
        return "is not a regular file"
    if getattr(stat_result, "st_nlink", 1) != 1:
        return f"has {getattr(stat_result, 'st_nlink', 0)} hard links"
    if stat_result.st_uid != effective_uid:
        return f"is owned by UID {stat_result.st_uid}, not effective UID {effective_uid}"
    mode = stat.S_IMODE(stat_result.st_mode)
    if mode != PRIVATE_FILE_MODE:
        return f"has unsafe mode {mode:#05o}, expected {PRIVATE_FILE_MODE:#05o}"
    return None


def _require_legacy_import_lock_visible(
    lock_fd: int,
    parent_fd: int,
    name: str,
    lock_path: Path,
    effective_uid: int,
) -> None:
    lock_stat = os.fstat(lock_fd)
    issue = _legacy_import_lock_stat_issue(lock_stat, effective_uid)
    if issue:
        raise RuntimeError(f"refusing to use legacy import lock {lock_path}: {issue}")
    try:
        visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"legacy import lock changed while in use: {lock_path}") from exc
    visible_issue = _legacy_import_lock_stat_issue(visible_stat, effective_uid)
    if visible_issue:
        raise RuntimeError(f"refusing to use legacy import lock {lock_path}: {visible_issue}")
    if visible_stat.st_dev != lock_stat.st_dev or visible_stat.st_ino != lock_stat.st_ino:
        raise RuntimeError(f"legacy import lock changed while in use: {lock_path}")


def _open_legacy_import_lock(lock_path: Path) -> Tuple[int, int, Path, str]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("platform cannot safely open legacy import lock files without O_NOFOLLOW")
    parent_fd, name, parent_path = _open_legacy_parent_dir(lock_path, "legacy import lock")
    flags = os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    created = False
    try:
        try:
            lock_fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            lock_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise RuntimeError(f"refusing to use symlinked legacy import lock: {lock_path}") from exc
        if exc.errno in {errno.EISDIR, errno.ENXIO}:
            raise RuntimeError(f"refusing to use non-regular legacy import lock: {lock_path}") from exc
        raise RuntimeError(f"unable to open legacy import lock: {lock_path}") from exc
    try:
        effective_uid = _legacy_effective_uid()
        initial_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(initial_stat.st_mode):
            raise RuntimeError(f"refusing to use non-regular legacy import lock: {lock_path}")
        if getattr(initial_stat, "st_nlink", 1) != 1:
            raise RuntimeError(f"refusing to use hard-linked legacy import lock: {lock_path}")
        if initial_stat.st_uid != effective_uid:
            raise RuntimeError(
                f"refusing to use legacy import lock not owned by effective UID {effective_uid}: "
                f"{lock_path} (owner UID {initial_stat.st_uid})"
            )
        if created:
            try:
                os.fchmod(lock_fd, PRIVATE_FILE_MODE)
            except OSError as exc:
                raise RuntimeError(f"unable to set private permissions on legacy import lock: {lock_path}") from exc
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import lock")
        _require_legacy_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        if created:
            os.fsync(lock_fd)
            _fsync_legacy_directory_fd(parent_fd, parent_path, "legacy import lock")
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import lock")
            _require_legacy_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        return lock_fd, parent_fd, parent_path, name
    except Exception:
        os.close(lock_fd)
        os.close(parent_fd)
        raise


@contextlib.contextmanager
def _legacy_global_target_lock(
    server: ServerConfig,
    account: Account,
    *,
    stop_event: Optional[object],
) -> Iterator[None]:
    _ensure_legacy_global_state_dirs()
    lock_path = _legacy_target_lock_path(server, account)
    lock_fd, parent_fd, parent_path, name = _open_legacy_import_lock(lock_path)
    try:
        effective_uid = _legacy_effective_uid()
        while True:
            _raise_if_stopped(stop_event, f"legacy import {account.email} lock wait")
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import lock")
            _require_legacy_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise RuntimeError(f"unable to acquire legacy import lock: {lock_path}") from exc
            wait = getattr(stop_event, "wait", None) if stop_event is not None else None
            if callable(wait):
                if wait(IMPORT_LOCK_WAIT_SECONDS):
                    raise RuntimeError(f"legacy import {account.email} lock wait: stop requested before completion")
            else:
                time.sleep(IMPORT_LOCK_WAIT_SECONDS)
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import lock")
        _require_legacy_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        _raise_if_stopped(stop_event, f"legacy import {account.email} lock wait")
        yield
    finally:
        try:
            os.close(lock_fd)
        finally:
            os.close(parent_fd)


@contextlib.contextmanager
def _legacy_import_lock(
    server: ServerConfig,
    account: Account,
    in_root: Path,
    *,
    stop_event: Optional[object],
) -> Iterator[None]:
    _raise_if_symlink(in_root, "legacy import root")
    _secure_existing_legacy_import_root(in_root)
    with _legacy_global_target_lock(
        server,
        account,
        stop_event=stop_event,
    ):
        yield


def _legacy_import_key(account_dir: Path, eml_path: Path, mailbox: str, data: bytes) -> str:
    rel_path = eml_path.relative_to(account_dir).as_posix()
    digest = hashlib.sha256(data).hexdigest()
    seed = f"{mailbox}\0{rel_path}\0{len(data)}\0{digest}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _legacy_import_content_identity(mailbox: str, data: bytes) -> Tuple[str, int, str]:
    return mailbox, len(data), hashlib.sha256(data).hexdigest()


def _imap_append_wire_bytes(data: bytes) -> bytes:
    return imaplib.MapCRLF.sub(imaplib.CRLF, data)


def _normalized_legacy_internaldate(value: object) -> str:
    if not isinstance(value, str):
        return ""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _parse_legacy_internaldate(value: object) -> Optional[datetime]:
    """Parse an IMAP INTERNALDATE without locale-dependent month handling."""
    normalized = _normalized_legacy_internaldate(value)
    match = _IMAP_INTERNALDATE_RE.fullmatch(normalized)
    if match is None:
        return None
    zone_hour = int(match.group("zone_hour"))
    zone_minute = int(match.group("zone_minute"))
    if zone_hour > 23 or zone_minute > 59:
        return None
    zone_delta = timedelta(hours=zone_hour, minutes=zone_minute)
    if match.group("zone_sign") == "-":
        zone_delta = -zone_delta
    try:
        parsed = datetime(
            int(match.group("year")),
            _IMAP_MONTH_NUMBER[match.group("month").lower()],
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=timezone(zone_delta),
        )
        return parsed
    except (KeyError, OverflowError, ValueError):
        return None


def _legacy_internaldate_utc_key(value: object) -> str:
    parsed = _parse_legacy_internaldate(value)
    if parsed is None:
        return ""
    offset = parsed.utcoffset()
    if offset is None:
        return ""
    local_seconds = (
        (parsed.toordinal() - 1) * 24 * 60 * 60
        + parsed.hour * 60 * 60
        + parsed.minute * 60
        + parsed.second
    )
    return str(local_seconds - int(offset.total_seconds()))


def _legacy_internaldates_equal(first: object, second: object) -> bool:
    first_key = _legacy_internaldate_utc_key(first)
    return bool(first_key and first_key == _legacy_internaldate_utc_key(second))


def _legacy_internaldate_for_append(value: str) -> Optional[str]:
    if value == "":
        return None
    if _parse_legacy_internaldate(value) is None:
        raise ValueError("invalid IMAP INTERNALDATE")
    if value.startswith('"') and value.endswith('"'):
        return value
    return f'"{value}"'


def _maximum_bipartite_matching(
    edges: List[List[int]],
    right_count: int,
) -> Tuple[int, set[int]]:
    """Return maximum match size/right vertices without recursive augmenting paths."""
    match_for_left = [-1] * len(edges)
    match_for_right = [-1] * right_count
    for start_left in sorted(range(len(edges)), key=lambda index: (len(edges[index]), index)):
        visited_left = {start_left}
        visited_right: set[int] = set()
        parent_left_for_right: Dict[int, int] = {}
        pending = deque([start_left])
        free_right = -1
        while pending and free_right < 0:
            left = pending.popleft()
            for right in edges[left]:
                if right in visited_right:
                    continue
                visited_right.add(right)
                parent_left_for_right[right] = left
                matched_left = match_for_right[right]
                if matched_left < 0:
                    free_right = right
                    break
                if matched_left not in visited_left:
                    visited_left.add(matched_left)
                    pending.append(matched_left)
        if free_right < 0:
            continue
        right = free_right
        while right >= 0:
            left = parent_left_for_right[right]
            previous_right = match_for_left[left]
            match_for_left[left] = right
            match_for_right[right] = left
            right = previous_right
    return sum(1 for right in match_for_left if right >= 0), {
        right for right in match_for_left if right >= 0
    }


def _message_id_header(data: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


def _legacy_used_uid_key(uidvalidity: str, uid: int) -> bytes:
    return f"{uidvalidity}:{uid}".encode("ascii")


def _legacy_used_uid_namespace(imap: imaplib.IMAP4) -> str:
    return selected_uidvalidity(imap) or "unknown"


def _legacy_remote_has_message(
    imap: imaplib.IMAP4,
    mailbox: str,
    data: bytes,
    used_nums: set[bytes],
    expected_flags: str = "",
    expected_internaldate: str = "",
    *,
    restore_missing_flags: bool = False,
) -> bool:
    data = _imap_append_wire_bytes(data)
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=not restore_missing_flags)
    if status != "OK":
        return False
    uidvalidity = _legacy_used_uid_namespace(imap)
    message_id = _message_id_header(data)
    search_uids = _legacy_search_target_uids(imap, message_id, mailbox=mailbox)
    if not search_uids:
        return False
    expected_hash = hashlib.sha256(data).hexdigest()
    expected_size = len(data)
    for uid in search_uids:
        uid_token = str(uid).encode("ascii")
        used_key = _legacy_used_uid_key(uidvalidity, uid)
        if used_key in used_nums or uid_token in used_nums:
            continue
        status, fetched = imap.uid("fetch", str(uid), "(UID RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[])")
        if status != "OK":
            continue
        body, actual_flags, actual_date = _parse_fetch_response_for_uid(list(fetched or []), uid)
        if body is None:
            continue
        if len(body) != expected_size or hashlib.sha256(body).hexdigest() != expected_hash:
            continue
        expected_date = _normalized_legacy_internaldate(expected_internaldate)
        if expected_date and not _legacy_internaldates_equal(actual_date, expected_date):
            continue
        missing_flags = _legacy_missing_target_flags(
            expected_flags,
            actual_flags,
        )
        if missing_flags:
            if not restore_missing_flags:
                continue
            flags_arg = _legacy_flags_arg_from_tokens(missing_flags)
            status, response = imap.uid("store", str(uid), "+FLAGS.SILENT", flags_arg)
            if status != "OK":
                raise RuntimeError(f"failed to restore legacy flags in {mailbox}: {response}")
            status, refetched = imap.uid("fetch", str(uid), "(UID FLAGS)")
            if status != "OK":
                raise RuntimeError(f"failed to verify restored legacy flags in {mailbox}: {refetched}")
            refetched_flags, _refetched_date = _legacy_fetch_metadata_for_uid(
                list(refetched or []),
                uid,
            )
            remaining = _legacy_missing_target_flags(
                expected_flags,
                refetched_flags,
            )
            if remaining:
                raise RuntimeError(
                    f"remote flags missing after restore in {mailbox}: " + ", ".join(remaining)
                )
        used_nums.add(used_key)
        return True
    return False


def _latest_legacy_rows_by_key(rows: List[Dict[str, str]], target_id: str) -> Dict[str, Dict[str, str]]:
    latest: Dict[str, Dict[str, str]] = {}
    for row in rows:
        key = row.get("key", "")
        if key and row.get("target") == target_id:
            latest[key] = row
    return latest


def _latest_legacy_status_by_key(rows: List[Dict[str, str]], target_id: str) -> Dict[str, str]:
    latest: Dict[str, str] = {}
    for key, row in _latest_legacy_rows_by_key(rows, target_id).items():
        latest[key] = row.get("status", "")
    return latest


def _latest_legacy_committed_keys(rows: List[Dict[str, str]], target_id: str) -> set[str]:
    return {
        key
        for key, status in _latest_legacy_status_by_key(rows, target_id).items()
        if status == "committed"
    }


def _unresolved_legacy_pending_keys(rows: List[Dict[str, str]], target_id: str) -> set[str]:
    return {
        key
        for key, status in _latest_legacy_status_by_key(rows, target_id).items()
        if status == "pending"
    }


def _legacy_journal_content_identity(row: Mapping[str, str]) -> Optional[Tuple[str, int, str]]:
    mailbox = row.get("mailbox", "")
    if not mailbox:
        return None
    size_raw = row.get("rfc822_size", "")
    try:
        size = int(size_raw)
    except (TypeError, ValueError):
        return None
    if size < 0:
        return None
    digest = row.get("content_sha256", "").lower()
    if not _SHA256_HEX_RE.fullmatch(digest):
        return None
    return mailbox, size, digest


def _legacy_journal_content_counts(
    rows: List[Dict[str, str]],
    target_id: str,
    status: str,
) -> Counter[Tuple[str, int, str]]:
    counts: Counter[Tuple[str, int, str]] = Counter()
    for row in _latest_legacy_rows_by_key(rows, target_id).values():
        if row.get("status") != status:
            continue
        identity = _legacy_journal_content_identity(row)
        if identity is not None:
            counts[identity] += 1
    return counts


def _load_legacy_import_journal_with_stat(
    account_dir: Path,
    *,
    repair_trailing: bool = True,
    allow_unterminated_trailing: bool = False,
) -> Tuple[List[Dict[str, str]], Optional[os.stat_result]]:
    path = _legacy_import_journal_path(account_dir)
    rows: List[Dict[str, str]] = []
    _raise_if_symlink(path, "legacy import journal")
    if path.is_dir():
        issue = legacy_reserved_mailbox_path_issue(path.name, path.name)
        raise RuntimeError(f"invalid legacy account layout: {issue}")
    if not path.exists():
        return rows, None
    try:
        raw, journal_stat = _read_file_no_symlink_with_stat(
            path,
            "legacy import journal",
            reject_hard_links=True,
        )
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            return rows, None
        raise
    trailing_row_unterminated = bool(raw) and not raw.endswith(b"\n")
    lines = raw.splitlines()
    needs_rewrite = False
    for line_no, raw_line in enumerate(lines, 1):
        if trailing_row_unterminated and line_no == len(lines):
            if repair_trailing or allow_unterminated_trailing:
                if repair_trailing:
                    logging.warning("[import] ignoring incomplete trailing journal row: %s", path)
                    needs_rewrite = True
                break
            raise RuntimeError(f"import journal row {line_no} is not newline-terminated: {path}")
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            if repair_trailing and line_no == len(lines):
                logging.warning("[import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise RuntimeError(f"import journal row {line_no} is malformed UTF-8: {path}") from None
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            if repair_trailing and line_no == len(lines):
                logging.warning("[import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise RuntimeError(f"import journal row {line_no} is malformed: {path}") from None
        if not isinstance(row, dict):
            raise RuntimeError(f"import journal row {line_no} is not an object: {path}")
        for required in ("key", "target"):
            value = row.get(required)
            if not isinstance(value, str) or not value.strip():
                raise RuntimeError(f"import journal row {line_no} is missing {required}: {path}")
            if not _SHA256_HEX_RE.fullmatch(value):
                raise RuntimeError(f"import journal row {line_no} has invalid {required}: {path}")
        coerced = {str(k): str(v) for k, v in row.items()}
        status = coerced.get("status", "")
        if status not in _LEGACY_IMPORT_JOURNAL_STATUSES:
            raise RuntimeError(
                f"import journal row {line_no} has invalid status: {status or '<missing>'}: {path}"
            )
        rows.append(coerced)
    if needs_rewrite:
        _write_legacy_import_journal(account_dir, rows)
        journal_stat = None
    return rows, journal_stat


def _load_legacy_import_journal(account_dir: Path, *, repair_trailing: bool = True) -> List[Dict[str, str]]:
    rows, _journal_stat = _load_legacy_import_journal_with_stat(
        account_dir,
        repair_trailing=repair_trailing,
    )
    return rows


def _load_legacy_import_journal_complete_prefix(account_dir: Path) -> List[Dict[str, str]]:
    """Read every durable journal row without repairing an interrupted final append."""
    rows, _journal_stat = _load_legacy_import_journal_with_stat(
        account_dir,
        repair_trailing=False,
        allow_unterminated_trailing=True,
    )
    return rows


def _write_legacy_import_journal(account_dir: Path, rows: List[Dict[str, str]]) -> None:
    path = _legacy_import_journal_path(account_dir)
    payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    _secure_atomic_write_text(path, payload)


def _append_legacy_import_journal(account_dir: Path, row: Dict[str, str]) -> None:
    path = _legacy_import_journal_path(account_dir)
    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_legacy_parent_dir(path, "legacy import journal")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = -1
    try:
        fd = os.open(name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise RuntimeError(f"refusing to use symlinked legacy import journal: {path}") from exc
        if exc.errno == errno.ENXIO:
            raise RuntimeError(f"refusing to use non-regular legacy import journal: {path}") from exc
        raise
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise RuntimeError(f"refusing to use non-regular legacy import journal: {path}")
        _raise_if_hard_linked_private_file_fd(fd, path, "legacy import journal")
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
        file_obj = os.fdopen(fd, "a", encoding="utf-8")
        fd = -1
        with file_obj as f:
            os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
            json.dump(row, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
        try:
            visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise RuntimeError(f"legacy import journal changed during append: {path}") from exc
        if (
            visible_stat.st_dev != stat_result.st_dev
            or visible_stat.st_ino != stat_result.st_ino
            or stat.S_ISLNK(visible_stat.st_mode)
            or not stat.S_ISREG(visible_stat.st_mode)
        ):
            raise RuntimeError(f"legacy import journal changed during append: {path}")
        _fsync_legacy_directory_fd(parent_fd, parent_path, "legacy import journal")
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def _fetch_response_uid(meta_str: str) -> Optional[int]:
    uids = _fetch_response_uids(meta_str)
    if not uids:
        return None
    return uids[0]


def _fetch_response_uids(meta_str: str) -> List[int]:
    uids: List[int] = []
    depth = 0
    in_quote = False
    escaped = False
    idx = 0
    while idx < len(meta_str):
        ch = meta_str[idx]
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            idx += 1
            continue
        if ch == '"':
            in_quote = True
            idx += 1
            continue
        if ch == "(":
            depth += 1
            idx += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            idx += 1
            continue
        if depth <= 1 and meta_str[idx : idx + 3].upper() == "UID":
            before = meta_str[idx - 1] if idx else ""
            after_idx = idx + 3
            after = meta_str[after_idx] if after_idx < len(meta_str) else ""
            if (not before or not (before.isalnum() or before in "_-")) and after.isspace():
                digit_idx = after_idx
                while digit_idx < len(meta_str) and meta_str[digit_idx].isspace():
                    digit_idx += 1
                digit_start = digit_idx
                while digit_idx < len(meta_str) and meta_str[digit_idx].isdigit():
                    digit_idx += 1
                next_ch = meta_str[digit_idx] if digit_idx < len(meta_str) else ""
                if digit_idx > digit_start and (not next_ch or not (next_ch.isalnum() or next_ch in "_-")):
                    uids.append(
                        parse_imap_uid_token(
                            meta_str[digit_start:digit_idx],
                            label="FETCH UID response",
                        )
                    )
                    idx = digit_idx
                    continue
        idx += 1
    return uids


def _parse_fetch_response_for_uid(
    fetch_response: List[object],
    expected_uid: int,
) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Parse a FETCH response into payload bytes and metadata.

    Returns (msg_bytes, flags, internaldate). Any of them can be None.
    """
    if not fetch_response:
        return None, None, None
    msg_bytes: Optional[bytes] = None
    flags: Optional[str] = None
    internaldate: Optional[str] = None
    body_parts: List[bytes] = []
    body_meta_chunks: List[str] = []
    active_body_meta_chunks: Optional[List[str]] = None
    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            meta = part[0]
            body = part[1]
            meta_str = meta.decode(errors="ignore") if isinstance(meta, (bytes, bytearray)) else ""
            response_uid = _fetch_response_uid(meta_str)
            if isinstance(body, (bytes, bytearray)):
                if response_uid != expected_uid:
                    if body_parts:
                        raise RuntimeError("fetch returned multiple message bodies for one UID")
                    if response_uid is not None:
                        raise RuntimeError(f"fetch returned message bytes for unexpected UID {response_uid}")
                if body_parts:
                    raise RuntimeError("fetch returned multiple message bodies for one UID")
                body_parts.append(bytes(body))
                body_meta_chunks = [meta_str] if meta_str else []
                active_body_meta_chunks = body_meta_chunks
            else:
                active_body_meta_chunks = None
        elif isinstance(part, (bytes, bytearray)):
            meta_str = part.decode(errors="ignore")
            if active_body_meta_chunks is not None:
                if _FETCH_RESPONSE_START_RE.match(meta_str):
                    active_body_meta_chunks = None
                    continue
                response_uids = _fetch_response_uids(meta_str)
                if response_uids:
                    if expected_uid in response_uids:
                        if any(uid != expected_uid for uid in response_uids):
                            raise RuntimeError(f"fetch response for UID {expected_uid} included multiple UIDs")
                        active_body_meta_chunks.append(meta_str)
                    else:
                        active_body_meta_chunks = None
                    continue
                active_body_meta_chunks.append(meta_str)
    if len(body_parts) > 1:
        raise RuntimeError("fetch returned multiple message bodies for one UID")
    if body_parts:
        msg_bytes = body_parts[0]
        meta_str = " ".join(body_meta_chunks)
        response_uids = _fetch_response_uids(meta_str)
        if expected_uid not in response_uids:
            if response_uids:
                raise RuntimeError(f"fetch returned message bytes for unexpected UID {response_uids[0]}")
            raise RuntimeError(f"fetch response for UID {expected_uid} did not include UID metadata")
        flags, internaldate = _legacy_fetch_metadata_values(body_meta_chunks)
    return msg_bytes, flags, internaldate


def _stale_legacy_export_stem(name: str) -> Optional[str]:
    if name.endswith(".eml"):
        return name[:-4]
    if name.endswith(".json") and name != ".mailbox.json":
        return name[:-5]
    return None


def _remove_stale_export_files(folder_dir: Path, expected_stems: set[str]) -> None:
    dir_fd, dir_path = _open_legacy_dir(folder_dir, "legacy mailbox")
    try:
        for name in sorted(os.listdir(dir_fd)):
            stem = _stale_legacy_export_stem(name)
            if stem is None or stem in expected_stems:
                continue
            artifact_path = folder_dir / name
            try:
                stat_result = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(stat_result.st_mode):
                raise RuntimeError(f"refusing to delete symlinked legacy export artifact: {artifact_path}")
            if not stat.S_ISREG(stat_result.st_mode):
                raise RuntimeError(f"refusing to delete non-regular legacy export artifact: {artifact_path}")
            _raise_if_legacy_parent_replaced(dir_path, dir_fd, "legacy mailbox")
            os.unlink(name, dir_fd=dir_fd)
            _fsync_legacy_directory_fd(dir_fd, dir_path, "legacy mailbox")
            _raise_if_legacy_parent_replaced(dir_path, dir_fd, "legacy mailbox")
    finally:
        os.close(dir_fd)


def _raise_if_legacy_child_dir_replaced(parent_fd: int, name: str, child_fd: int, display_path: Path) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"refusing to delete replaced legacy mailbox directory: {display_path}") from exc
    pinned = os.fstat(child_fd)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != pinned.st_dev
        or current.st_ino != pinned.st_ino
    ):
        raise RuntimeError(f"refusing to delete replaced legacy mailbox directory: {display_path}")


def _remove_legacy_dir_tree_at(
    parent_fd: int,
    name: str,
    display_path: Path,
    guard: Callable[[], None],
) -> None:
    try:
        stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(stat_result.st_mode):
        raise RuntimeError(f"refusing to delete symlinked legacy mailbox directory: {display_path}")
    if not stat.S_ISDIR(stat_result.st_mode):
        raise RuntimeError(f"refusing to delete non-directory legacy mailbox path: {display_path}")
    guard()
    child_fd = os.open(name, _legacy_dir_open_flags(), dir_fd=parent_fd)
    try:
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise RuntimeError(f"refusing to delete non-directory legacy mailbox path: {display_path}")
        if child_stat.st_dev != stat_result.st_dev or child_stat.st_ino != stat_result.st_ino:
            raise RuntimeError(f"refusing to delete replaced legacy mailbox directory: {display_path}")

        def child_guard() -> None:
            guard()
            _raise_if_legacy_child_dir_replaced(parent_fd, name, child_fd, display_path)

        child_guard()
        for child_name in sorted(os.listdir(child_fd)):
            child_path = display_path / child_name
            try:
                child_entry_stat = os.stat(child_name, dir_fd=child_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(child_entry_stat.st_mode):
                raise RuntimeError(f"refusing to delete symlinked legacy mailbox path: {child_path}")
            if stat.S_ISDIR(child_entry_stat.st_mode):
                child_guard()
                _remove_legacy_dir_tree_at(child_fd, child_name, child_path, child_guard)
                continue
            if not stat.S_ISREG(child_entry_stat.st_mode):
                raise RuntimeError(f"refusing to delete non-regular legacy mailbox path: {child_path}")
            child_guard()
            os.unlink(child_name, dir_fd=child_fd)
            _fsync_legacy_directory_fd(child_fd, display_path, "legacy mailbox directory")
            child_guard()
        child_guard()
        os.rmdir(name, dir_fd=parent_fd)
        _fsync_legacy_directory_fd(parent_fd, display_path.parent, "legacy mailbox directory")
        guard()
    finally:
        os.close(child_fd)


def _remove_stale_mailbox_dirs(account_dir: Path, expected_paths: set[str]) -> None:
    dir_fd, dir_path = _open_legacy_dir(account_dir, "legacy account")

    def guard() -> None:
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, "legacy account")

    try:
        for name in sorted(os.listdir(dir_fd)):
            if name in {"export-state.json", "import.journal.jsonl", LEGACY_RESET_STATE_FILENAME}:
                continue
            try:
                stat_result = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(stat_result.st_mode) or stat.S_ISLNK(stat_result.st_mode):
                continue
            if name not in expected_paths:
                _remove_legacy_dir_tree_at(dir_fd, name, account_dir / name, guard)
    finally:
        os.close(dir_fd)


def legacy_export_output_symlink_issues(out_root: Path, accounts: List[Account]) -> List[str]:
    issues: List[str] = []
    for account in accounts:
        account_dir = out_root / sanitize_for_path(account.email)
        if account_dir.is_symlink() or _legacy_symlink_component(account_dir) is not None:
            issues.append(f"{account.email}: account output path is a symlink: {account_dir}")
            continue
        if not account_dir.exists():
            continue
        if not account_dir.is_dir():
            issues.append(f"{account.email}: account output path is not a directory: {account_dir}")
            continue
        provider_manifest = account_dir / "manifest.jsonl"
        if provider_manifest.exists() or provider_manifest.is_symlink():
            issues.append(f"{account.email}: provider manifest present in legacy output directory: {provider_manifest}")
            continue
        for path in sorted(account_dir.rglob("*")):
            if path.is_symlink():
                rel = path.relative_to(account_dir).as_posix()
                issues.append(f"{account.email}: output path is a symlink: {rel}")
    return issues


def export_account(account: Account, server: ServerConfig, out_root: Path, ignore_errors: bool, *, stop_event: Optional[object] = None) -> None:
    """Export all messages for an account into `out_root/<email>/<folder>/`.

    Writes one .eml per message and a .json with mailbox/uid/flags/internaldate.
    """
    _raise_if_symlink(out_root, "legacy export root")
    account_dir = out_root / sanitize_for_path(account.email)
    nested_symlink_issues = legacy_export_output_symlink_issues(out_root, [account])
    if nested_symlink_issues:
        raise RuntimeError("invalid legacy export output path: " + "; ".join(nested_symlink_issues))
    ensure_private_dir(account_dir)
    existing_journal_rows = _load_legacy_import_journal(
        account_dir,
        repair_trailing=False,
    )
    pinned_recovery_artifacts_by_path, recovery_issues = _legacy_journal_recovery_artifacts(
        account_dir,
        existing_journal_rows,
        account_email=account.email,
    )
    if recovery_issues:
        raise RuntimeError(
            "invalid legacy recovery export evidence: " + "; ".join(recovery_issues)
        )
    pinned_stems_by_folder: Dict[str, set[str]] = {}
    for pinned_path in pinned_recovery_artifacts_by_path:
        relative = pinned_path.relative_to(account_dir)
        pinned_stems_by_folder.setdefault(relative.parent.as_posix(), set()).add(
            pinned_path.stem
        )
    logging.info("[export] %s: starting", account.email)
    state_path = account_dir / "export-state.json"
    source_endpoint = legacy_server_endpoint(server)
    source_endpoint_sha256 = legacy_server_endpoint_digest(server)
    _secure_atomic_json(
        state_path,
        {
            "schema_version": 1,
            "account": account.email,
            "source_server": source_endpoint,
            "source_server_sha256": source_endpoint_sha256,
            "complete": False,
            "started_at": int(time.time()),
            "mailboxes": [],
        },
    )
    mailbox_errors: List[str] = []
    export_state_mailboxes: List[Dict[str, object]] = []
    exported_regular_content: Counter[Tuple[int, str]] = Counter()
    mergeable_metadata_paths_by_content: Dict[Tuple[int, str], List[Tuple[Path, str]]] = {}

    def write_legacy_message(
        folder_dir: Path,
        mailbox: str,
        uid: int,
        msg_bytes: bytes,
        flags: str,
        internaldate: str,
        uidvalidity: Optional[str],
        digest: str,
    ) -> str:
        base = f"u{int(uid):010d}"
        meta = {
            "account": account.email,
            "mailbox": mailbox,
            "uid": int(uid),
            "flags": flags or "",
            "internaldate": internaldate or "",
            "rfc822_size": len(msg_bytes),
            "content_sha256": digest,
        }
        if uidvalidity:
            meta["uidvalidity"] = uidvalidity
        source_segments = _legacy_mailbox_path_segments(
            mailbox,
            mailbox_delimiter_by_name.get(mailbox, ""),
        )
        if len(source_segments) > 1:
            meta["source_delimiter"] = mailbox_delimiter_by_name.get(mailbox, "")
            meta["source_path_segments"] = list(source_segments)
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        candidate = base
        collision_index = 0
        while True:
            eml_path = folder_dir / f"{candidate}.eml"
            pinned_artifact = pinned_recovery_artifacts_by_path.get(eml_path)
            if pinned_artifact is None:
                break
            if pinned_artifact.data == msg_bytes and pinned_artifact.metadata == meta:
                return candidate
            collision_index += 1
            candidate = f"{base}-reexport-{str(meta[CONTENT_BINDING_FIELD])[:16]}"
            if collision_index > 1:
                candidate += f"-{collision_index}"
        meta_path = folder_dir / f"{candidate}.json"
        _secure_atomic_write_bytes(eml_path, msg_bytes)
        _secure_atomic_json(meta_path, meta)
        return candidate

    def merge_covered_virtual_flags(
        content_identity: Tuple[int, str],
        match_index: int,
        flags: str,
        internaldate: str,
    ) -> bool:
        metadata_entries = mergeable_metadata_paths_by_content.get(content_identity, [])
        if match_index < 0 or match_index >= len(metadata_entries):
            raise RuntimeError("covered virtual message has no matching mergeable metadata")
        virtual_internaldate = _normalized_legacy_internaldate(internaldate)
        if not virtual_internaldate:
            return False
        same_date_paths = [
            path
            for path, regular_internaldate in metadata_entries
            if _legacy_internaldates_equal(regular_internaldate, virtual_internaldate)
        ]
        if len(same_date_paths) != 1:
            return False
        meta_path = same_date_paths[0]
        if not _legacy_target_flag_set(flags):
            return True
        meta = json.loads(
            _read_file_no_symlink(
                meta_path,
                "legacy message metadata",
                reject_hard_links=True,
            ).decode("utf-8")
        )
        if not isinstance(meta, dict):
            raise RuntimeError(f"{meta_path}: message metadata is not an object")
        merged_flags = _merge_legacy_flag_strings(str(meta.get("flags") or ""), flags)
        if merged_flags == str(meta.get("flags") or ""):
            return True
        if meta_path.with_suffix(".eml") in pinned_recovery_artifacts_by_path:
            # The recovery snapshot is immutable.  Staging the virtual copy is
            # safer than mutating metadata bound to an unresolved/committed APPEND.
            return False
        meta["flags"] = merged_flags
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        _secure_atomic_json(meta_path, meta)
        return True

    with imap_connection(server, account) as imap:
        mailbox_details = _list_selectable_mailbox_details(imap)
        mailbox_entries = [(entry.name, entry.attributes) for entry in mailbox_details]
        mailbox_attrs_by_name = {entry.name: entry.attributes for entry in mailbox_details}
        mailbox_delimiter_by_name = {entry.name: entry.delimiter for entry in mailbox_details}
        mailboxes = [
            name
            for name, attrs in mailbox_entries
            if not _should_skip_legacy_source_view(name, attrs, mailbox_entries)
        ]
        mailboxes.sort(
            key=lambda name: (
                1
                if (
                    _is_legacy_all_source_view(mailbox_attrs_by_name.get(name, ()))
                    or _is_legacy_flagged_source_view(mailbox_attrs_by_name.get(name, ()))
                )
                else 0,
                _mailbox_sort_key(name),
            )
        )
        export_scope_only_virtual = bool(mailboxes) and all(
            _is_legacy_all_source_view(mailbox_attrs_by_name.get(name, ()))
            or _is_legacy_flagged_source_view(mailbox_attrs_by_name.get(name, ()))
            for name in mailboxes
        )

        # Detect sanitize_for_path collisions before writing any data.
        # Two distinct mailbox names that map to the same directory would
        # silently overwrite each other's messages.
        seen_paths: Dict[str, Tuple[str, str]] = {}  # filesystem key -> (original mailbox, sanitized path)
        for mb in mailboxes:
            path = sanitize_for_path(mb)
            reserved_issue = legacy_reserved_mailbox_path_issue(mb, path)
            if reserved_issue is not None:
                raise RuntimeError(f"Cannot export mailbox for account {account.email}: {reserved_issue}")
            key = sanitized_path_key(mb)
            previous = seen_paths.get(key)
            if previous is not None and previous[0] != mb:
                raise RuntimeError(
                    f"Mailbox name collision for account {account.email}: "
                    f"'{previous[0]}' -> '{previous[1]}' and '{mb}' -> '{path}' "
                    "alias on case-insensitive filesystems. "
                    f"Cannot export without data loss."
                )
            seen_paths[key] = (mb, path)

        for mailbox in mailboxes:
            _raise_if_stopped(stop_event, f"legacy export {account.email}")
            try:
                attrs = mailbox_attrs_by_name.get(mailbox, ())
                flagged_virtual_source = _is_legacy_flagged_source_view(attrs)
                virtual_source = _is_legacy_all_source_view(attrs) or flagged_virtual_source
                folder_path = sanitize_for_path(mailbox)
                folder_dir = account_dir / folder_path
                pinned_stems = set(pinned_stems_by_folder.get(folder_path, set()))
                uids, uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox)
                pinned_uidvalidities: set[str] = set()
                for pinned_path, pinned_artifact in pinned_recovery_artifacts_by_path.items():
                    if pinned_path.parent != folder_dir:
                        continue
                    pinned_mailbox = pinned_artifact.metadata.get("mailbox")
                    if pinned_mailbox != mailbox:
                        raise RuntimeError(
                            f"journal recovery artifact mailbox collision in {folder_dir}: "
                            f"source={mailbox!r} recovery={pinned_mailbox!r}"
                        )
                    pinned_uidvalidity = pinned_artifact.metadata.get("uidvalidity")
                    if isinstance(pinned_uidvalidity, str) and pinned_uidvalidity:
                        pinned_uidvalidities.add(pinned_uidvalidity)
                if pinned_uidvalidities and pinned_uidvalidities != {uidvalidity}:
                    raise RuntimeError(
                        f"UIDVALIDITY changed for mailbox {mailbox} while journal recovery "
                        f"artifacts remain pinned: recovery={sorted(pinned_uidvalidities)} "
                        f"source={uidvalidity}"
                    )
                logging.info("[export] %s: %s -> %d messages", account.email, mailbox, len(uids))
                if not uids:
                    if virtual_source and not export_scope_only_virtual and not pinned_stems:
                        continue
                    verify_legacy_mailbox_uid_set_stable(imap, mailbox, uids, uidvalidity)
                    ensure_private_dir(folder_dir)
                    delimiter = mailbox_delimiter_by_name.get(mailbox, "")
                    _secure_atomic_json(
                        folder_dir / ".mailbox.json",
                        _legacy_mailbox_metadata(
                            mailbox,
                            len(pinned_stems),
                            delimiter,
                            uidvalidity,
                        ),
                    )
                    _remove_stale_export_files(folder_dir, pinned_stems)
                    export_state_mailboxes.append(_legacy_export_state_mailbox_metadata(
                        mailbox,
                        folder_path,
                        len(pinned_stems),
                        delimiter,
                        uidvalidity,
                    ))
                    continue

                ensure_private_dir(folder_dir)
                written_stems: set[str] = set(pinned_stems)
                pending_virtual_content: Dict[Tuple[int, str], List[Tuple[int, bytes, str, str, str]]] = {}
                seen_virtual_content: Counter[Tuple[int, str]] = Counter()
                ambiguous_virtual_content: set[Tuple[int, str]] = set()
                exported_flags_by_uid: Dict[int, str] = {}

                batch_size = 200
                for i in range(0, len(uids), batch_size):
                    _raise_if_stopped(stop_event, f"legacy export {account.email}")
                    batch = uids[i : i + batch_size]
                    for uid in batch:
                        _raise_if_stopped(stop_event, f"legacy export {account.email}")
                        status, data = imap.uid("fetch", str(uid), "(UID FLAGS INTERNALDATE BODY.PEEK[])")
                        if status != "OK":
                            raise RuntimeError(f"fetch failed in {mailbox} for UID {uid}")
                        msg_bytes, flags, internaldate = _parse_fetch_response_for_uid(list(data or []), int(uid))
                        if msg_bytes is None:
                            raise RuntimeError(f"fetch returned no message bytes in {mailbox} for UID {uid}")
                        if flags is None:
                            raise RuntimeError(f"fetch returned no flags in {mailbox} for UID {uid}")
                        exported_flags_by_uid[int(uid)] = flags
                        with contextlib.suppress(Exception):
                            _ = BytesParser(policy=default_policy).parsebytes(msg_bytes)
                        digest = hashlib.sha256(msg_bytes).hexdigest()
                        content_identity = (len(msg_bytes), digest)
                        if virtual_source:
                            seen_virtual_content[content_identity] += 1
                            covered_content_count = exported_regular_content[content_identity]
                            if flagged_virtual_source:
                                covered_content_count = len(
                                    mergeable_metadata_paths_by_content.get(content_identity, [])
                                )
                            if content_identity in ambiguous_virtual_content:
                                pass
                            elif seen_virtual_content[content_identity] <= covered_content_count:
                                if flagged_virtual_source:
                                    covered = merge_covered_virtual_flags(
                                        content_identity,
                                        seen_virtual_content[content_identity] - 1,
                                        flags or "",
                                        internaldate or "",
                                    )
                                    if not covered:
                                        ambiguous_virtual_content.add(content_identity)
                                        for pending_uid, pending_bytes, pending_flags, pending_date, pending_digest in (
                                            pending_virtual_content.pop(content_identity, [])
                                        ):
                                            written_stems.add(
                                                write_legacy_message(
                                                    folder_dir,
                                                    mailbox,
                                                    pending_uid,
                                                    pending_bytes,
                                                    pending_flags,
                                                    pending_date,
                                                    uidvalidity,
                                                    pending_digest,
                                                )
                                            )
                                        written_stems.add(
                                            write_legacy_message(
                                                folder_dir,
                                                mailbox,
                                                int(uid),
                                                msg_bytes,
                                                flags or "",
                                                internaldate or "",
                                                uidvalidity,
                                                digest,
                                            )
                                        )
                                        continue
                                pending_virtual_content.setdefault(content_identity, []).append(
                                    (int(uid), msg_bytes, flags or "", internaldate or "", digest)
                                )
                                continue
                            elif covered_content_count:
                                ambiguous_virtual_content.add(content_identity)
                                for pending_uid, pending_bytes, pending_flags, pending_date, pending_digest in (
                                    pending_virtual_content.pop(content_identity, [])
                                ):
                                    written_stems.add(
                                        write_legacy_message(
                                            folder_dir,
                                            mailbox,
                                            pending_uid,
                                            pending_bytes,
                                            pending_flags,
                                            pending_date,
                                            uidvalidity,
                                            pending_digest,
                                        )
                                    )
                        else:
                            exported_regular_content[content_identity] += 1
                        written_stem = write_legacy_message(
                            folder_dir,
                            mailbox,
                            int(uid),
                            msg_bytes,
                            flags or "",
                            internaldate or "",
                            uidvalidity,
                            digest,
                        )
                        written_stems.add(written_stem)
                        if not flagged_virtual_source:
                            mergeable_metadata_paths_by_content.setdefault(content_identity, []).append(
                                (folder_dir / f"{written_stem}.json", internaldate or "")
                            )
                _remove_stale_export_files(folder_dir, written_stems)
                covered_virtual_source = virtual_source and bool(uids) and not written_stems
                if written_stems or not virtual_source or covered_virtual_source:
                    delimiter = mailbox_delimiter_by_name.get(mailbox, "")
                    covered_source_attributes = attrs if covered_virtual_source else ()
                    verify_legacy_mailbox_uid_set_stable(
                        imap,
                        mailbox,
                        uids,
                        uidvalidity,
                        initial_flags_by_uid=exported_flags_by_uid,
                    )
                    _secure_atomic_json(
                        folder_dir / ".mailbox.json",
                        _legacy_mailbox_metadata(
                            mailbox,
                            len(written_stems),
                            delimiter,
                            uidvalidity,
                            covered_virtual_source,
                            covered_source_attributes,
                        ),
                    )
                    export_state_mailboxes.append(_legacy_export_state_mailbox_metadata(
                        mailbox,
                        sanitize_for_path(mailbox),
                        len(written_stems),
                        delimiter,
                        uidvalidity,
                        covered_virtual_source,
                        covered_source_attributes,
                    ))
            except Exception as exc:
                logging.exception("[export] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                if _stop_requested(stop_event):
                    raise
                mailbox_errors.append(f"{mailbox}: {exc}")
                if not ignore_errors:
                    raise
    if mailbox_errors:
        raise RuntimeError(
            f"legacy export {account.email} failed for {len(mailbox_errors)} mailbox(es): "
            + "; ".join(mailbox_errors)
        )
    exported_state_paths = {
        str(item.get("path") or "") for item in export_state_mailboxes
    }
    for folder_path, pinned_stems in sorted(pinned_stems_by_folder.items()):
        if folder_path in exported_state_paths:
            continue
        folder_dir = account_dir / folder_path
        folder_artifacts = [
            artifact
            for path, artifact in pinned_recovery_artifacts_by_path.items()
            if path.parent == folder_dir
        ]
        recovery_mailboxes = {
            str(artifact.metadata.get("mailbox") or "")
            for artifact in folder_artifacts
        }
        if len(recovery_mailboxes) != 1 or "" in recovery_mailboxes:
            raise RuntimeError(
                f"journal recovery artifacts disagree on source mailbox in {folder_dir}"
            )
        recovery_mailbox = next(iter(recovery_mailboxes))
        if sanitize_for_path(recovery_mailbox) != folder_path:
            raise RuntimeError(
                f"journal recovery artifact mailbox does not match staged path: {folder_dir}"
            )
        recovery_hierarchies = {
            _legacy_hierarchy_metadata(
                artifact.metadata,
                recovery_mailbox,
                f"journal recovery artifact {folder_dir}",
            )
            for artifact in folder_artifacts
        }
        if len(recovery_hierarchies) != 1:
            raise RuntimeError(
                f"journal recovery artifacts disagree on source hierarchy in {folder_dir}"
            )
        recovery_delimiter, _recovery_segments = next(iter(recovery_hierarchies))
        recovery_uidvalidities = {
            _legacy_uidvalidity_metadata(
                artifact.metadata,
                f"journal recovery artifact {folder_dir}",
            )
            for artifact in folder_artifacts
        }
        if len(recovery_uidvalidities) != 1:
            raise RuntimeError(
                f"journal recovery artifacts disagree on UIDVALIDITY in {folder_dir}"
            )
        recovery_uidvalidity = next(iter(recovery_uidvalidities))
        _remove_stale_export_files(folder_dir, pinned_stems)
        marker = _legacy_mailbox_metadata(
            recovery_mailbox,
            len(pinned_stems),
            recovery_delimiter,
            recovery_uidvalidity,
        )
        _secure_atomic_json(folder_dir / ".mailbox.json", marker)
        export_state_mailboxes.append(
            _legacy_export_state_mailbox_metadata(
                recovery_mailbox,
                folder_path,
                len(pinned_stems),
                recovery_delimiter,
                recovery_uidvalidity,
            )
        )
        exported_state_paths.add(folder_path)
        logging.warning(
            "[export] %s: source mailbox %s is absent; retained %d exact journal recovery artifact(s)",
            account.email,
            recovery_mailbox,
            len(pinned_stems),
        )
    _remove_stale_mailbox_dirs(
        account_dir,
        {str(item.get("path") or "") for item in export_state_mailboxes},
    )
    _secure_atomic_json(
        state_path,
        {
            "schema_version": 1,
            "account": account.email,
            "source_server": source_endpoint,
            "source_server_sha256": source_endpoint_sha256,
            "complete": True,
            "completed_at": int(time.time()),
            "mailboxes": export_state_mailboxes,
        },
    )
    logging.info("[export] %s: completed", account.email)


def _validate_legacy_sidecar_integrity(meta_path: Path, meta: Dict[str, object]) -> Tuple[Optional[int], Optional[str]]:
    expected_size_raw = meta.get("rfc822_size")
    if type(expected_size_raw) is not int or expected_size_raw < 0:
        raise RuntimeError(f"{meta_path}: invalid rfc822_size metadata")
    expected_size = expected_size_raw
    expected_hash_raw = meta.get("content_sha256")
    if not isinstance(expected_hash_raw, str):
        raise RuntimeError(f"{meta_path}: invalid content_sha256 metadata")
    expected_hash = expected_hash_raw.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise RuntimeError(f"{meta_path}: invalid content_sha256 metadata")
    binding_issue = legacy_content_binding_issue(meta, required=True)
    if binding_issue:
        raise RuntimeError(f"{meta_path}: {binding_issue}")
    return expected_size, expected_hash


def _require_legacy_payload_integrity(eml_path: Path, data: bytes, expected_size: Optional[int], expected_hash: Optional[str]) -> None:
    if expected_size is not None and len(data) != expected_size:
        raise RuntimeError(f"{eml_path}: rfc822_size mismatch (metadata={expected_size} actual={len(data)})")
    if expected_hash is not None:
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError(f"{eml_path}: content_sha256 mismatch")


def _valid_legacy_flag_token(token: str) -> bool:
    if not token:
        return False
    if token == "\\" or "\\" in token[1:]:
        return False
    if any(ord(ch) <= 32 or ord(ch) >= 127 for ch in token):
        return False
    return not any(ch in '(){%*"]' for ch in token)


def _valid_legacy_internaldate(value: str) -> bool:
    return _parse_legacy_internaldate(value) is not None


def _validate_legacy_delivery_metadata(meta: Dict[str, object], label: object) -> Tuple[str, Optional[str]]:
    errors: List[str] = []
    flags_raw = meta.get("flags", "")
    flags = ""
    if "flags" in meta and not isinstance(flags_raw, str):
        errors.append("invalid flags metadata")
    elif isinstance(flags_raw, str):
        flags = flags_raw
        invalid_flags = [token for token in flags.split() if not _valid_legacy_flag_token(token)]
        if invalid_flags:
            errors.append("invalid flags metadata")

    internaldate_raw = meta.get("internaldate")
    internaldate: Optional[str] = None
    if "internaldate" in meta:
        if not isinstance(internaldate_raw, str):
            errors.append("invalid internaldate metadata")
        elif internaldate_raw != "":
            if _parse_legacy_internaldate(internaldate_raw) is None:
                errors.append("invalid internaldate metadata")
            else:
                internaldate = internaldate_raw
    if errors:
        raise RuntimeError(f"{label}: " + "; ".join(errors))
    return flags, internaldate


def _validate_legacy_uid_metadata(meta_path: Path, eml_path: Path, meta: Dict[str, object]) -> None:
    stem = eml_path.stem
    if not (stem.startswith("u") and stem[1:].isdigit()):
        return
    uid_in_name = int(stem[1:])
    uid_meta = meta.get("uid")
    if "uid" in meta and type(uid_meta) is not int:
        raise RuntimeError(f"{meta_path}: invalid uid metadata")
    if isinstance(uid_meta, int) and uid_meta != uid_in_name:
        raise RuntimeError(f"{meta_path}: uid mismatch (name={uid_in_name} meta={uid_meta})")


class _LegacyRecoveryArtifact(NamedTuple):
    data: bytes
    metadata: Dict[str, object]


def _latest_legacy_recovery_rows(
    rows: List[Dict[str, str]],
    *,
    target_id: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Return latest unresolved APPEND evidence for every journal target/key."""

    latest: Dict[Tuple[str, str], Dict[str, str]] = {}
    for row in rows:
        target = row.get("target", "")
        key = row.get("key", "")
        if not target or not key or (target_id is not None and target != target_id):
            continue
        latest[(target, key)] = row
    return [
        row
        for _journal_key, row in sorted(latest.items())
        if row.get("status") in {"pending", "committed"}
    ]


def _legacy_recovery_path(
    account_dir: Path,
    row: Mapping[str, str],
) -> Tuple[Optional[Path], Optional[str]]:
    raw_path = row.get("path", "")
    if not raw_path:
        return None, None
    path = Path(raw_path)
    if (
        path.is_absolute()
        or len(path.parts) != 2
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".eml"
        or path.as_posix() != raw_path
    ):
        return None, f"journal recovery row has invalid staged path: {raw_path!r}"
    return account_dir / path, None


def _legacy_recovery_candidate_paths(account_dir: Path) -> List[Path]:
    candidates: List[Path] = []
    if not account_dir.exists() or not account_dir.is_dir():
        return candidates
    for child in sorted(account_dir.iterdir()):
        _raise_if_symlink(child, "legacy mailbox path")
        if not child.is_dir():
            continue
        candidates.extend(sorted(child.glob("*.eml")))
    return candidates


def _read_legacy_recovery_artifact(
    account_dir: Path,
    eml_path: Path,
    row: Mapping[str, str],
    *,
    account_email: Optional[str],
) -> _LegacyRecoveryArtifact:
    status = row.get("status", "") or "<missing>"
    journal_key = row.get("key", "")
    target_mailbox = row.get("mailbox", "")
    label = f"journal {status} recovery evidence {journal_key or '<missing>'}"
    if not target_mailbox:
        raise RuntimeError(f"{label}: missing target mailbox")
    _raise_if_symlink(eml_path, "legacy recovery message file")
    if not eml_path.exists():
        raise RuntimeError(f"{label}: staged message file missing: {eml_path}")
    meta_path = eml_path.with_suffix(".json")
    _raise_if_symlink(meta_path, "legacy recovery message metadata")
    if not meta_path.exists():
        raise RuntimeError(f"{label}: staged message metadata missing: {meta_path}")
    try:
        metadata = json.loads(
            _read_file_no_symlink(
                meta_path,
                "legacy recovery message metadata",
                reject_hard_links=True,
            ).decode("utf-8")
        )
    except Exception as exc:
        raise RuntimeError(f"{label}: invalid staged message metadata {meta_path}: {exc}") from exc
    if not isinstance(metadata, dict):
        raise RuntimeError(f"{label}: staged message metadata is not an object: {meta_path}")
    _validate_legacy_uid_metadata(meta_path, eml_path, metadata)
    expected_size, expected_hash = _validate_legacy_sidecar_integrity(meta_path, metadata)
    flags, internaldate = _validate_legacy_delivery_metadata(metadata, meta_path)
    metadata_account = metadata.get("account")
    if not isinstance(metadata_account, str) or not metadata_account:
        raise RuntimeError(f"{label}: staged message metadata is missing account: {meta_path}")
    if account_email is not None and metadata_account != account_email:
        raise RuntimeError(
            f"{label}: staged account mismatch (journal account={account_email} metadata={metadata_account})"
        )
    source_mailbox = metadata.get("mailbox")
    if not isinstance(source_mailbox, str) or not source_mailbox:
        raise RuntimeError(f"{label}: staged message metadata is missing mailbox: {meta_path}")
    if sanitize_for_path(source_mailbox) != eml_path.parent.name:
        raise RuntimeError(
            f"{label}: staged mailbox path does not match metadata: {eml_path}"
        )
    data = _read_file_no_symlink(
        eml_path,
        "legacy recovery message file",
        reject_hard_links=True,
    )
    _require_legacy_payload_integrity(eml_path, data, expected_size, expected_hash)
    append_data = _imap_append_wire_bytes(data)
    valid_keys = {
        _legacy_import_key(account_dir, eml_path, target_mailbox, data),
        _legacy_import_key(account_dir, eml_path, target_mailbox, append_data),
    }
    if journal_key not in valid_keys:
        raise RuntimeError(f"{label}: key does not match staged path, mailbox, and payload")

    journal_size = row.get("rfc822_size", "")
    journal_digest = row.get("content_sha256", "").lower()
    if journal_size or journal_digest:
        content_variants = {
            (str(len(data)), hashlib.sha256(data).hexdigest()),
            (str(len(append_data)), hashlib.sha256(append_data).hexdigest()),
        }
        if (journal_size, journal_digest) not in content_variants:
            raise RuntimeError(f"{label}: content identity does not match staged payload")

    journal_binding = row.get(CONTENT_BINDING_FIELD, "")
    if journal_binding:
        metadata_binding = metadata.get(CONTENT_BINDING_FIELD)
        if (
            not _SHA256_HEX_RE.fullmatch(journal_binding.lower())
            or not isinstance(metadata_binding, str)
            or journal_binding.lower() != metadata_binding.lower()
        ):
            raise RuntimeError(f"{label}: content binding does not match staged metadata")
    if "flags" in row and row.get("flags", "") != flags:
        raise RuntimeError(f"{label}: flags do not match staged metadata")
    if "internaldate" in row and row.get("internaldate", "") != (internaldate or ""):
        raise RuntimeError(f"{label}: internaldate does not match staged metadata")
    return _LegacyRecoveryArtifact(data=data, metadata=metadata)


def _legacy_journal_recovery_artifacts(
    account_dir: Path,
    rows: List[Dict[str, str]],
    *,
    account_email: Optional[str] = None,
    target_id: Optional[str] = None,
) -> Tuple[Dict[Path, _LegacyRecoveryArtifact], List[str]]:
    """Resolve and validate exact artifacts pinned by latest journal evidence."""

    artifacts: Dict[Path, _LegacyRecoveryArtifact] = {}
    issues: List[str] = []
    candidates: Optional[List[Path]] = None
    for row in _latest_legacy_recovery_rows(rows, target_id=target_id):
        eml_path, path_issue = _legacy_recovery_path(account_dir, row)
        if path_issue:
            issues.append(path_issue)
            continue
        if eml_path is None:
            # Compatibility with early journals which did not persist `path`:
            # the key still binds a unique path, mailbox and payload.
            if candidates is None:
                try:
                    candidates = _legacy_recovery_candidate_paths(account_dir)
                except Exception as exc:
                    issues.append(f"cannot scan staged recovery artifacts: {exc}")
                    candidates = []
            matches: List[Path] = []
            target_mailbox = row.get("mailbox", "")
            journal_key = row.get("key", "")
            if not target_mailbox:
                issues.append(
                    f"journal {row.get('status') or '<missing>'} recovery evidence "
                    f"{journal_key or '<missing>'}: missing target mailbox"
                )
                continue
            for candidate in candidates:
                try:
                    data = _read_file_no_symlink(
                        candidate,
                        "legacy recovery message file",
                        reject_hard_links=True,
                    )
                except Exception:
                    continue
                append_data = _imap_append_wire_bytes(data)
                if journal_key in {
                    _legacy_import_key(account_dir, candidate, target_mailbox, data),
                    _legacy_import_key(account_dir, candidate, target_mailbox, append_data),
                }:
                    matches.append(candidate)
            if len(matches) != 1:
                issues.append(
                    f"journal {row.get('status') or '<missing>'} recovery evidence "
                    f"{journal_key or '<missing>'}: expected one matching staged artifact, found {len(matches)}"
                )
                continue
            eml_path = matches[0]
        try:
            artifact = _read_legacy_recovery_artifact(
                account_dir,
                eml_path,
                row,
                account_email=account_email,
            )
        except Exception as exc:
            issues.append(str(exc))
            continue
        previous = artifacts.get(eml_path)
        if previous is not None and previous != artifact:
            issues.append(f"conflicting journal recovery evidence for staged artifact: {eml_path}")
            continue
        artifacts[eml_path] = artifact
    return artifacts, list(dict.fromkeys(issues))


def legacy_journal_recovery_artifact_issues(
    account_dir: Path,
    rows: List[Dict[str, str]],
    *,
    account_email: Optional[str] = None,
    target_id: Optional[str] = None,
) -> List[str]:
    return _legacy_journal_recovery_artifacts(
        account_dir,
        rows,
        account_email=account_email,
        target_id=target_id,
    )[1]


def import_account(
    account: Account,
    server: ServerConfig,
    in_root: Path,
    ignore_errors: bool,
    *,
    create_folder: bool = True,
    imap_factory: Optional[Callable[[ServerConfig, Account], AbstractContextManager[imaplib.IMAP4]]] = None,
    stop_event: Optional[object] = None,
    da_context: Optional[Tuple[object, int]] = None,
    provision_context: Optional[Tuple[object, int, str]] = None,
    source_server: Optional[ServerConfig] = None,
    before_import: Optional[Callable[[], None]] = None,
    reset_before_import: Optional[Callable[[], None]] = None,
) -> None:
    """Import all messages for an account from `in_root/<email>/...`.

    If a provisioning context is provided and initial login fails, a one-time
    lazy POP account creation is attempted before retrying login.
    """
    with _legacy_import_lock(
        server,
        account,
        in_root,
        stop_event=stop_event,
    ):
        account_dir = in_root / sanitize_for_path(account.email)
        if reset_before_import is not None:
            reset_state = _begin_legacy_reset_state(account_dir, account, server)
            if reset_state["phase"] == "prepared":
                archive_path = archive_legacy_import_journal_for_reset(account_dir)
                if archive_path is not None:
                    logging.info(
                        "[import-reset] Archived stale import journal for %s: %s",
                        account.email,
                        archive_path,
                    )
                reset_state = _transition_legacy_reset_state(
                    account_dir,
                    account,
                    server,
                    reset_state,
                    "journal_archived",
                )
            _raise_if_stopped(stop_event, f"legacy reset {account.email}")
            if reset_state["phase"] == "journal_archived":
                reset_state = _transition_legacy_reset_state(
                    account_dir,
                    account,
                    server,
                    reset_state,
                    "reset_started",
                )
            reset_before_import()
            _clear_legacy_reset_state(account_dir, account, server, reset_state)
            _raise_if_stopped(stop_event, f"legacy reset {account.email}")
        else:
            _require_legacy_reset_gate_open(account_dir, account, server)
            if before_import is not None:
                before_import()
                _raise_if_stopped(stop_event, f"legacy pre-import {account.email}")
        _import_account_unlocked(
            account,
            server,
            in_root,
            ignore_errors,
            create_folder=create_folder,
            imap_factory=imap_factory,
            stop_event=stop_event,
            da_context=da_context,
            provision_context=provision_context,
            source_server=source_server,
        )


def run_legacy_target_action_under_import_lock(
    account: Account,
    server: ServerConfig,
    in_root: Path,
    action: Callable[[], None],
    *,
    stop_event: Optional[object] = None,
    allow_reset_resume: bool = False,
    allow_unrelated_local_target: bool = False,
) -> None:
    """Run one target-facing action behind the account's import/reset gate."""

    with _legacy_import_lock(
        server,
        account,
        in_root,
        stop_event=stop_event,
    ):
        account_dir = in_root / sanitize_for_path(account.email)
        _require_legacy_reset_gate_open(
            account_dir,
            account,
            server,
            allow_reset_resume=allow_reset_resume,
            allow_unrelated_local_target=allow_unrelated_local_target,
        )
        action()
        _raise_if_stopped(stop_event, f"legacy target action {account.email}")


def run_legacy_global_target_action_under_lock(
    account: Account,
    server: ServerConfig,
    action: Callable[[], None],
    *,
    stop_event: Optional[object] = None,
) -> None:
    """Run target work behind the global lock/gate without staged local state."""

    with _legacy_global_target_lock(
        server,
        account,
        stop_event=stop_event,
    ):
        _require_legacy_global_reset_gate_open(account, server)
        action()
        _raise_if_stopped(stop_event, f"legacy target action {account.email}")


def _import_account_unlocked(
    account: Account,
    server: ServerConfig,
    in_root: Path,
    ignore_errors: bool,
    *,
    create_folder: bool = True,
    imap_factory: Optional[Callable[[ServerConfig, Account], AbstractContextManager[imaplib.IMAP4]]] = None,
    stop_event: Optional[object] = None,
    da_context: Optional[Tuple[object, int]] = None,
    provision_context: Optional[Tuple[object, int, str]] = None,
    source_server: Optional[ServerConfig] = None,
) -> None:
    _raise_if_symlink(in_root, "legacy import root")
    account_dir = in_root / sanitize_for_path(account.email)
    _raise_if_symlink(account_dir, "legacy account directory")
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    provider_manifest = account_dir / "manifest.jsonl"
    if provider_manifest.exists() or provider_manifest.is_symlink():
        raise RuntimeError(f"{account.email}: provider manifest present in legacy account directory: {provider_manifest}")
    logging.info("[import] %s: starting", account.email)
    target_id = _legacy_import_target_id(server, account)
    journal_rows = _load_legacy_import_journal(account_dir)
    recovery_issues = legacy_journal_recovery_artifact_issues(
        account_dir,
        journal_rows,
        account_email=account.email,
        target_id=target_id,
    )
    if recovery_issues:
        raise RuntimeError(
            "invalid legacy import journal recovery evidence: "
            + "; ".join(recovery_issues)
        )
    committed_keys = _latest_legacy_committed_keys(journal_rows, target_id)
    pending_keys = _unresolved_legacy_pending_keys(journal_rows, target_id)
    committed_content_remaining = _legacy_journal_content_counts(journal_rows, target_id, "committed")
    pending_content_remaining = _legacy_journal_content_counts(journal_rows, target_id, "pending")

    def _completed_zero_message_export(
        staged_marker_paths: set[str],
        staged_markers: Dict[str, Dict[str, object]],
    ) -> bool:
        state_path = account_dir / "export-state.json"
        if not state_path.exists():
            return False
        try:
            state = json.loads(
                _read_file_no_symlink(
                    state_path,
                    "legacy export-state",
                    reject_hard_links=True,
                ).decode("utf-8")
            )
        except Exception:
            return False
        if state.get("complete") is not True:
            return False
        if state.get("account") not in {None, account.email}:
            return False
        mailboxes = state.get("mailboxes")
        if not isinstance(mailboxes, list) or not mailboxes:
            return False
        state_paths: set[str] = set()
        for entry in mailboxes:
            if not isinstance(entry, dict):
                return False
            path = str(entry.get("path") or "")
            mailbox = str(entry.get("mailbox") or "")
            if not path or not mailbox:
                return False
            message_count = entry.get("message_count")
            if type(message_count) is not int:
                return False
            if message_count != 0:
                return False
            marker_meta = staged_markers.get(path)
            if not isinstance(marker_meta, dict):
                return False
            if marker_meta.get("mailbox") != mailbox:
                return False
            if sanitize_for_path(mailbox) != path:
                return False
            marker_count = marker_meta.get("message_count")
            if type(marker_count) is not int:
                return False
            if marker_count != 0:
                return False
            state_paths.add(path)
        if state_paths != staged_marker_paths or state_paths != set(staged_markers):
            return False
        return True

    # Build worklist before opening IMAP connection
    per_folder: Dict[str, List[Tuple[Path, str, Optional[str], Optional[int], Optional[str]]]] = {}
    source_hierarchy_by_mailbox: Dict[str, Tuple[str, Tuple[str, ...]]] = {}
    staged_marker_paths: set[str] = set()
    staged_markers: Dict[str, Dict[str, object]] = {}
    folder_dirs: List[Path] = []
    for child in sorted(account_dir.iterdir()):
        _raise_if_symlink(child, "legacy mailbox path")
        if child.is_dir():
            folder_dirs.append(child)
    for folder_dir in folder_dirs:
        _raise_if_stopped(stop_event, f"legacy import {account.email}")
        mailbox_meta = folder_dir.name
        marker_mailbox_present = False
        marker_uidvalidity = ""
        folder_uidvalidity: Optional[str] = None
        marker = folder_dir / ".mailbox.json"
        _raise_if_symlink(marker, "legacy mailbox marker")
        eml_paths = sorted(folder_dir.glob("*.eml"))
        json_paths = sorted(path for path in folder_dir.glob("*.json") if path.name != ".mailbox.json")
        eml_stems = {path.stem for path in eml_paths}
        json_stems = {path.stem for path in json_paths}
        orphan_sidecars = json_stems - eml_stems
        if orphan_sidecars:
            raise RuntimeError(f"{folder_dir}: {len(orphan_sidecars)} metadata file(s) without .eml counterpart")
        if marker.exists():
            staged_marker_paths.add(folder_dir.name)
            try:
                marker_meta = json.loads(
                    _read_file_no_symlink(
                        marker,
                        "legacy mailbox marker",
                        reject_hard_links=True,
                    ).decode("utf-8")
                )
            except Exception as exc:
                raise RuntimeError(f"{marker}: failed to parse mailbox marker: {exc}") from exc
            if isinstance(marker_meta, dict):
                staged_markers[folder_dir.name] = marker_meta
                expected_count = marker_meta.get("message_count")
                if type(expected_count) is not int or expected_count < 0:
                    raise RuntimeError(f"{marker}: mailbox marker has invalid message_count")
                if expected_count != len(eml_paths):
                    raise RuntimeError(
                        f"{marker}: mailbox marker count mismatch (marker={expected_count} eml={len(eml_paths)})"
                    )
                marker_mailbox = marker_meta.get("mailbox")
                if not isinstance(marker_mailbox, str) or not marker_mailbox.strip():
                    raise RuntimeError(f"{marker}: mailbox marker missing mailbox")
                if sanitize_for_path(marker_mailbox) != folder_dir.name:
                    raise RuntimeError(f"{marker}: mailbox metadata mismatch (folder={folder_dir.name} meta={marker_mailbox})")
                marker_hierarchy = _legacy_hierarchy_metadata(marker_meta, marker_mailbox, str(marker))
                marker_uidvalidity = _legacy_uidvalidity_metadata(marker_meta, str(marker))
                if marker_uidvalidity:
                    folder_uidvalidity = marker_uidvalidity
                if marker_hierarchy[1]:
                    source_hierarchy_by_mailbox[marker_mailbox] = marker_hierarchy
                mailbox_meta = marker_mailbox
                marker_mailbox_present = True
            else:
                raise RuntimeError(f"{marker}: mailbox marker is not an object")
            if not _legacy_trusted_covered_by_regular_content(marker_meta, str(marker)):
                per_folder.setdefault(mailbox_meta, [])
        default_mailbox = mailbox_meta
        for eml_path in eml_paths:
            _raise_if_symlink(eml_path, "legacy message file")
            meta_path = eml_path.with_suffix(".json")
            flags = ""
            internaldate = None
            expected_size: Optional[int] = None
            expected_hash: Optional[str] = None
            mailbox_meta = default_mailbox
            _raise_if_symlink(meta_path, "legacy message metadata")
            if not meta_path.exists():
                raise RuntimeError(f"{eml_path}: missing message metadata")
            meta = json.loads(
                _read_file_no_symlink(
                    meta_path,
                    "legacy message metadata",
                    reject_hard_links=True,
                ).decode("utf-8")
            )
            if not isinstance(meta, dict):
                raise RuntimeError(f"{meta_path}: message metadata is not an object")
            _validate_legacy_uid_metadata(meta_path, eml_path, meta)
            message_uidvalidity = _legacy_uidvalidity_metadata(meta, str(meta_path))
            expected_size, expected_hash = _validate_legacy_sidecar_integrity(meta_path, meta)
            flags, internaldate = _validate_legacy_delivery_metadata(meta, meta_path)
            account_meta = meta.get("account")
            if not isinstance(account_meta, str) or not account_meta.strip():
                raise RuntimeError(f"{meta_path}: missing account metadata")
            if account_meta != account.email:
                raise RuntimeError(f"{meta_path}: account metadata mismatch (account={account.email} meta={account_meta})")
            mbox = meta.get("mailbox")
            if not isinstance(mbox, str) or not mbox.strip():
                raise RuntimeError(f"{meta_path}: missing mailbox metadata")
            if sanitize_for_path(mbox) != folder_dir.name:
                raise RuntimeError(f"{meta_path}: mailbox metadata mismatch (folder={folder_dir.name} meta={mbox})")
            message_hierarchy = _legacy_hierarchy_metadata(meta, mbox, str(meta_path))
            if marker_mailbox_present:
                if mbox != default_mailbox:
                    raise RuntimeError(f"{meta_path}: mailbox metadata mismatch (marker={default_mailbox} meta={mbox})")
                marker_hierarchy = source_hierarchy_by_mailbox.get(default_mailbox, ("", ()))
                if message_hierarchy != marker_hierarchy:
                    raise RuntimeError(f"{meta_path}: source_path_segments mismatch")
                if message_uidvalidity != marker_uidvalidity:
                    raise RuntimeError(f"{meta_path}: uidvalidity mismatch")
            elif mbox != folder_dir.name:
                raise RuntimeError(f"{meta_path}: missing mailbox marker for original mailbox {mbox}")
            if folder_uidvalidity is None:
                folder_uidvalidity = message_uidvalidity
            elif message_uidvalidity != folder_uidvalidity:
                raise RuntimeError(f"{meta_path}: uidvalidity mismatch")
            if message_hierarchy[1]:
                existing_hierarchy = source_hierarchy_by_mailbox.get(mbox)
                if existing_hierarchy is not None and existing_hierarchy != message_hierarchy:
                    raise RuntimeError(f"{meta_path}: source_path_segments mismatch")
                source_hierarchy_by_mailbox[mbox] = message_hierarchy
            data = _read_file_no_symlink(eml_path, "legacy message file", reject_hard_links=True)
            _require_legacy_payload_integrity(eml_path, data, expected_size, expected_hash)
            mailbox_meta = mbox
            per_folder.setdefault(mailbox_meta, []).append((eml_path, flags, internaldate, expected_size, expected_hash))
    if not per_folder:
        raise RuntimeError(f"Input account directory has no mailbox folders: {account_dir}")
    from .audit import _legacy_export_state_issues

    export_state_issues = _legacy_export_state_issues(
        account,
        account_dir,
        folder_dirs,
        require_state=True,
        expected_source_server=source_server,
        require_source_server_binding=True,
    )
    if export_state_issues:
        raise RuntimeError("invalid legacy export-state: " + "; ".join(export_state_issues))
    if not any(entries for entries in per_folder.values()):
        if not _completed_zero_message_export(staged_marker_paths, staged_markers):
            raise RuntimeError(f"Input account directory has no staged .eml files: {account_dir}")
    if pending_keys:
        raise RuntimeError(
            f"legacy import journal has {len(pending_keys)} pending append(s); "
            "target state is uncertain, inspect the mailbox before retrying"
        )
    if not any(entries for entries in per_folder.values()):
        logging.info("[import] %s: completed zero-message export; importing empty mailbox structure only", account.email)

    # Choose IMAP context manager (injected or default)
    def _imap_ctx() -> AbstractContextManager[imaplib.IMAP4]:
        if imap_factory is not None:
            return imap_factory(server, account)
        return imap_connection(server, account)

    # Try login; if it fails and DA context is provided, create mailbox and retry once
    def _try_login_only() -> None:
        with _imap_ctx():
            pass

    login_ok = False
    if provision_context is None and da_context is not None:
        provision_context = (da_context[0], da_context[1], "da")
    try:
        _try_login_only()
        login_ok = True
    except Exception as first_exc:
        if provision_context is not None:
            _raise_if_stopped(stop_event, f"legacy import {account.email}")
            client, quota_mb, provision_label = provision_context
            try:
                if "@" in account.email:
                    local, domain = account.email.split("@", 1)
                else:
                    raise ValueError("invalid email address for provisioning")
                # Create mailbox then retry login
                client.create_pop_account(domain, local, account.password, quota_mb=quota_mb)  # type: ignore[attr-defined]
                logging.info("[%s][lazy] Created mailbox: %s, retrying login", provision_label, account.email)
                _raise_if_stopped(stop_event, f"legacy import {account.email}")
                _try_login_only()
                login_ok = True
            except Exception as retry_exc:
                if _stop_requested(stop_event):
                    raise retry_exc
                # Propagate original login failure, preserving retry context
                raise first_exc from retry_exc
        else:
            raise

    if not login_ok:
        raise RuntimeError("login failed and no retry attempted")

    # Proceed with actual import work under a fresh connection
    folder_errors: List[str] = []
    used_remote_nums_by_folder: Dict[str, set[bytes]] = {}
    with _imap_ctx() as imap:
        target_delimiter = _legacy_target_hierarchy_delimiter(imap)
        target_mailbox_by_source = {
            source_mailbox: _legacy_target_mailbox_name(
                source_mailbox,
                source_hierarchy_by_mailbox.get(source_mailbox, ("", ()))[1],
                target_delimiter,
            )
            for source_mailbox in per_folder
        }
        target_collision_by_key: Dict[str, Tuple[str, str]] = {}
        for source_mailbox, target_mailbox in target_mailbox_by_source.items():
            collision_key = sanitized_path_key(target_mailbox)
            previous = target_collision_by_key.get(collision_key)
            if previous is not None and previous[0] != source_mailbox:
                raise RuntimeError(
                    f"legacy import target mailbox collision: "
                    f"{previous[0]!r} -> {previous[1]!r} and {source_mailbox!r} -> {target_mailbox!r}"
                )
            target_collision_by_key[collision_key] = (source_mailbox, target_mailbox)
        for folder, entries in per_folder.items():
            _raise_if_stopped(stop_event, f"legacy import {account.email}")
            mailbox = target_mailbox_by_source.get(folder, folder)
            try:
                status, _ = imap.select(quote_mailbox_name(mailbox))
                if status != "OK":
                    if create_folder:
                        try:
                            imap.create(quote_mailbox_name(mailbox))
                        except Exception as create_exc:
                            logging.warning("[import] %s: failed to create mailbox %s: %s", account.email, mailbox, create_exc)
                        status, _ = imap.select(quote_mailbox_name(mailbox))
                    if status != "OK":
                        raise RuntimeError(f"cannot select or create mailbox {mailbox}")
                subscribe_mailbox(imap, mailbox)
                logging.info("[import] %s: %s <- %d messages", account.email, mailbox, len(entries))
                for eml_path, flags, internaldate, expected_size, expected_hash in entries:
                    _raise_if_stopped(stop_event, f"legacy import {account.email}")
                    data = _read_file_no_symlink(eml_path, "legacy message file", reject_hard_links=True)
                    _require_legacy_payload_integrity(eml_path, data, expected_size, expected_hash)
                    append_data = _imap_append_wire_bytes(data)
                    flags_str = ""
                    if flags:
                        raw_tokens = [tok for tok in (flags.split()) if tok and tok.strip()]
                        # \RECENT is a read-only system flag; servers reject setting it on APPEND
                        filtered_tokens = [t for t in raw_tokens if t.strip().upper() != "\\RECENT"]
                        if filtered_tokens:
                            flags_str = "(" + " ".join(filtered_tokens) + ")"
                    # Build IMAP INTERNALDATE value. If missing, use current time (RFC3501 format).
                    if internaldate is not None:
                        date_time = _legacy_internaldate_for_append(internaldate)
                        if date_time is None:
                            raise RuntimeError(f"invalid internaldate metadata for {eml_path}")
                    else:
                        import imaplib as _imaplib
                        date_time = _imaplib.Time2Internaldate(time.time())
                    import_key = _legacy_import_key(account_dir, eml_path, mailbox, append_data)
                    legacy_raw_key = _legacy_import_key(account_dir, eml_path, mailbox, data)
                    content_identity = _legacy_import_content_identity(mailbox, append_data)
                    committed_key_present = import_key in committed_keys or legacy_raw_key in committed_keys
                    pending_key_present = import_key in pending_keys or legacy_raw_key in pending_keys
                    if pending_key_present or pending_content_remaining[content_identity] > 0:
                        raise RuntimeError(
                            f"legacy import journal has pending append for {eml_path}; "
                            "target state is uncertain, inspect the mailbox before retrying"
                        )
                    if committed_key_present:
                        used_remote_nums = used_remote_nums_by_folder.setdefault(mailbox, set())
                        if _legacy_remote_has_message(
                            imap,
                            mailbox,
                            data,
                            used_remote_nums,
                            flags,
                            internaldate or "",
                            restore_missing_flags=True,
                        ):
                            if committed_content_remaining[content_identity] > 0:
                                committed_content_remaining[content_identity] -= 1
                            logging.info("[import] %s: skipping verified committed %s", account.email, eml_path)
                            continue
                        logging.warning(
                            "[import] %s: committed journal row is stale for %s; re-appending",
                            account.email,
                            eml_path,
                        )
                        if committed_content_remaining[content_identity] > 0:
                            committed_content_remaining[content_identity] -= 1
                    elif committed_content_remaining[content_identity] > 0:
                        used_remote_nums = used_remote_nums_by_folder.setdefault(mailbox, set())
                        if _legacy_remote_has_message(
                            imap,
                            mailbox,
                            data,
                            used_remote_nums,
                            flags,
                            internaldate or "",
                            restore_missing_flags=True,
                        ):
                            committed_content_remaining[content_identity] -= 1
                            logging.info("[import] %s: skipping verified committed content %s", account.email, eml_path)
                            continue
                        logging.warning(
                            "[import] %s: committed content journal row is stale for %s; re-appending",
                            account.email,
                            eml_path,
                        )
                    rel_path = eml_path.relative_to(account_dir).as_posix()
                    recovery_meta_path = eml_path.with_suffix(".json")
                    recovery_meta = json.loads(
                        _read_file_no_symlink(
                            recovery_meta_path,
                            "legacy recovery message metadata",
                            reject_hard_links=True,
                        ).decode("utf-8")
                    )
                    if not isinstance(recovery_meta, dict):
                        raise RuntimeError(
                            f"{recovery_meta_path}: message metadata is not an object"
                        )
                    recovery_binding = recovery_meta.get(CONTENT_BINDING_FIELD)
                    if not isinstance(recovery_binding, str) or not _SHA256_HEX_RE.fullmatch(
                        recovery_binding.lower()
                    ):
                        raise RuntimeError(
                            f"{recovery_meta_path}: invalid {CONTENT_BINDING_FIELD} metadata"
                        )
                    recovery_evidence = {
                        "key": import_key,
                        "target": target_id,
                        "mailbox": mailbox,
                        "source_mailbox": folder,
                        "account": account.email,
                        "path": rel_path,
                        "rfc822_size": str(len(append_data)),
                        "content_sha256": hashlib.sha256(append_data).hexdigest(),
                        CONTENT_BINDING_FIELD: recovery_binding.lower(),
                        "flags": flags,
                        "internaldate": internaldate or "",
                    }
                    _append_legacy_import_journal(account_dir, {
                        **recovery_evidence,
                        "status": "pending",
                        "timestamp": str(int(time.time())),
                    })
                    try:
                        status, _ = imap.append(quote_mailbox_name(mailbox), flags_str, date_time, append_data)
                    except Exception as exc:
                        raise _LegacyAppendOutcomeUncertain(
                            f"append outcome is uncertain for {eml_path}; "
                            "target state is uncertain, inspect the mailbox before retrying"
                        ) from exc
                    if status != "OK":
                        _append_legacy_import_journal(account_dir, {
                            **recovery_evidence,
                            "status": "failed",
                            "timestamp": str(int(time.time())),
                        })
                        pending_keys.discard(import_key)
                        pending_keys.discard(legacy_raw_key)
                        raise RuntimeError(f"append failed for {eml_path}")
                    _append_legacy_import_journal(account_dir, {
                        **recovery_evidence,
                        "status": "committed",
                        "timestamp": str(int(time.time())),
                    })
                    pending_keys.discard(import_key)
                    pending_keys.discard(legacy_raw_key)
                    committed_keys.add(import_key)
            except _LegacyAppendOutcomeUncertain as exc:
                logging.exception("[import] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                raise
            except Exception as exc:
                logging.exception("[import] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                if _stop_requested(stop_event):
                    raise
                folder_errors.append(f"{mailbox}: {exc}")
                if not ignore_errors:
                    raise
    if folder_errors:
        raise RuntimeError(
            f"legacy import {account.email} failed for {len(folder_errors)} mailbox(es): "
            + "; ".join(folder_errors)
        )
    logging.info("[import] %s: completed", account.email)
