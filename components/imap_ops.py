import contextlib
import errno
import hashlib
import json
import logging
import os
import re
import ssl
import stat
import time
from collections import Counter
from contextlib import AbstractContextManager
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Mapping, NamedTuple, Optional, Tuple

import imaplib

from .models import Account, ServerConfig
from .content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_issue, legacy_content_binding_sha256
from .utils import decode_imap_utf7, encode_imap_utf7, quote_imap_search_value, sanitize_for_path, sanitized_path_key


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_HAS_DESCRIPTOR_RELATIVE_OPEN = os.open in os.supports_dir_fd
_HAS_DESCRIPTOR_RELATIVE_MKDIR = _HAS_DESCRIPTOR_RELATIVE_OPEN and os.mkdir in os.supports_dir_fd
LEGACY_ACCOUNT_RESERVED_PATHS = frozenset({"export-state.json", "import.journal.jsonl", "manifest.jsonl"})
_LEGACY_ACCOUNT_RESERVED_PATH_KEYS = frozenset(path.casefold() for path in LEGACY_ACCOUNT_RESERVED_PATHS)
_LEGACY_IMPORT_JOURNAL_STATUSES = {"pending", "committed", "failed"}
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_LEGACY_UIDVALIDITY_RE = re.compile(r"[1-9][0-9]*")
_IMAP_INTERNALDATE_RE = re.compile(
    r'^(?:[ 0][1-9]|[12][0-9]|3[01])-'
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-'
    r'\d{4} (?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d [+-]\d{4}$'
)


class _LegacyAppendOutcomeUncertain(RuntimeError):
    """Raised when APPEND may have reached the target but no outcome was confirmed."""


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
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, "directory")
        with contextlib.suppress(Exception):
            os.fchmod(dir_fd, PRIVATE_DIR_MODE)
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, "directory")
    finally:
        os.close(dir_fd)


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
            try:
                os.mkdir(part, PRIVATE_DIR_MODE, dir_fd=fd)
            except FileExistsError:
                pass
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked {label}: {path}") from exc
                if exc.errno != errno.EEXIST:
                    raise
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


def _read_file_no_symlink(path: Path, label: str, *, reject_hard_links: bool = False) -> bytes:
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
        return f.read()


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
            try:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy file")
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=parent_fd)
                raise
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name, dir_fd=parent_fd)
            raise
    finally:
        os.close(parent_fd)


def _secure_atomic_write_text(path: Path, payload: str) -> None:
    _secure_atomic_write_bytes(path, payload.encode("utf-8"))


def _secure_atomic_json(path: Path, payload: Dict[str, object]) -> None:
    _secure_atomic_write_text(path, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


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
    if not isinstance(value, str) or not _LEGACY_UIDVALIDITY_RE.fullmatch(value):
        raise RuntimeError(f"{label}: invalid uidvalidity metadata")
    return value


def selected_uidvalidity(imap: imaplib.IMAP4) -> str:
    with contextlib.suppress(Exception):
        _typ, data = imap.response("UIDVALIDITY")
        if data and data[0]:
            value = data[0].decode(errors="ignore") if isinstance(data[0], bytes) else str(data[0])
            value = value.strip()
            if _LEGACY_UIDVALIDITY_RE.fullmatch(value):
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
    if _is_legacy_flagged_source_view(attributes):
        return any(
            candidate_name != name and _is_legacy_all_source_view(candidate_attrs)
            for candidate_name, candidate_attrs in mailboxes
        )
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
    uids: List[int] = []
    if data and data[0]:
        for tok in data[0].split():
            try:
                uids.append(int(tok))
            except ValueError:
                continue
    uids.sort()
    return uids


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
    status, data = imap.uid("fetch", str(uid), "(FLAGS)")
    if status != "OK":
        raise RuntimeError(f"fetch flags failed in {mailbox} for UID {uid}")
    flags = _legacy_flags_from_fetch_response(list(data or []))
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
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
            return None
        _load_legacy_import_journal(account_dir, repair_trailing=False)
        _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
        stamp = int(time.time())
        for idx in range(1000):
            suffix = f"reset-{stamp}" if idx == 0 else f"reset-{stamp}-{idx}"
            archive_name = f"import.journal.{suffix}.jsonl"
            try:
                os.stat(archive_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                _raise_if_legacy_parent_replaced(parent_path, parent_fd, "legacy import journal")
                os.rename(name, archive_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
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
        "account": account.email,
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()


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
    normalized = value.strip()
    if len(normalized) >= 2 and normalized.startswith('"') and normalized.endswith('"'):
        normalized = normalized[1:-1]
    return normalized


def _message_id_header(data: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


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
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    message_id = _message_id_header(data)
    if message_id:
        status, search_data = imap.search(None, "HEADER", "Message-ID", quote_imap_search_value(message_id))
    else:
        status, search_data = imap.search(None, "ALL")
    if status != "OK" or not search_data or not search_data[0]:
        return False
    expected_hash = hashlib.sha256(data).hexdigest()
    expected_size = len(data)
    for num in search_data[0].split():
        if num in used_nums:
            continue
        status, fetched = imap.fetch(num, "(RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[])")
        if status != "OK":
            continue
        fetched_parts = list(fetched or [])
        for part in fetched or []:
            if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
                continue
            body = bytes(part[1])
            if len(body) == expected_size and hashlib.sha256(body).hexdigest() == expected_hash:
                expected_date = _normalized_legacy_internaldate(expected_internaldate)
                actual_date = _legacy_internaldate_from_fetch_response(fetched_parts)
                if expected_date and _normalized_legacy_internaldate(actual_date) != expected_date:
                    continue
                missing_flags = _legacy_missing_target_flags(
                    expected_flags,
                    _legacy_flags_from_fetch_response(fetched_parts),
                )
                if missing_flags:
                    if not restore_missing_flags:
                        continue
                    flags_arg = _legacy_flags_arg_from_tokens(missing_flags)
                    status, response = imap.store(num, "+FLAGS.SILENT", flags_arg)
                    if status != "OK":
                        raise RuntimeError(f"failed to restore legacy flags in {mailbox}: {response}")
                    status, refetched = imap.fetch(num, "(FLAGS)")
                    if status != "OK":
                        raise RuntimeError(f"failed to verify restored legacy flags in {mailbox}: {refetched}")
                    remaining = _legacy_missing_target_flags(
                        expected_flags,
                        _legacy_flags_from_fetch_response(list(refetched or [])),
                    )
                    if remaining:
                        raise RuntimeError(
                            f"remote flags missing after restore in {mailbox}: " + ", ".join(remaining)
                        )
                used_nums.add(num)
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


def _load_legacy_import_journal(account_dir: Path, *, repair_trailing: bool = True) -> List[Dict[str, str]]:
    path = _legacy_import_journal_path(account_dir)
    rows: List[Dict[str, str]] = []
    _raise_if_symlink(path, "legacy import journal")
    if path.is_dir():
        issue = legacy_reserved_mailbox_path_issue(path.name, path.name)
        raise RuntimeError(f"invalid legacy account layout: {issue}")
    if not path.exists():
        return rows
    try:
        raw = _read_file_no_symlink(path, "legacy import journal", reject_hard_links=True)
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            return rows
        raise
    lines = raw.decode("utf-8").splitlines()
    needs_rewrite = False
    for line_no, line in enumerate(lines, 1):
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
    except Exception:
        os.close(fd)
        raise
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
        json.dump(row, f, ensure_ascii=False, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def _fetch_response_uid(meta_str: str) -> Optional[int]:
    match = re.search(r"\bUID\s+(\d+)\b", meta_str, flags=re.IGNORECASE)
    if match is None:
        return None
    with contextlib.suppress(ValueError):
        return int(match.group(1))
    return None


def _fetch_response_uids(meta_str: str) -> List[int]:
    uids: List[int] = []
    for match in re.finditer(r"\bUID\s+(\d+)\b", meta_str, flags=re.IGNORECASE):
        with contextlib.suppress(ValueError):
            uids.append(int(match.group(1)))
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
        m_flags = re.search(r"FLAGS \((.*?)\)", meta_str, flags=re.IGNORECASE)
        if m_flags:
            flags = m_flags.group(1)
        m_int = re.search(r"INTERNALDATE \"([^\"]+)\"", meta_str, flags=re.IGNORECASE)
        if m_int:
            internaldate = m_int.group(1)
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
            _raise_if_legacy_parent_replaced(dir_path, dir_fd, "legacy mailbox")
    finally:
        os.close(dir_fd)


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
        for child_name in sorted(os.listdir(child_fd)):
            child_path = display_path / child_name
            try:
                child_entry_stat = os.stat(child_name, dir_fd=child_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(child_entry_stat.st_mode):
                _remove_legacy_dir_tree_at(child_fd, child_name, child_path, guard)
                continue
            guard()
            os.unlink(child_name, dir_fd=child_fd)
            guard()
    finally:
        os.close(child_fd)
    guard()
    os.rmdir(name, dir_fd=parent_fd)
    guard()


def _remove_stale_mailbox_dirs(account_dir: Path, expected_paths: set[str]) -> None:
    dir_fd, dir_path = _open_legacy_dir(account_dir, "legacy account")

    def guard() -> None:
        _raise_if_legacy_parent_replaced(dir_path, dir_fd, "legacy account")

    try:
        for name in sorted(os.listdir(dir_fd)):
            if name in {"export-state.json", "import.journal.jsonl"}:
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
    regular_metadata_paths_by_content: Dict[Tuple[int, str], List[Tuple[Path, str]]] = {}

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
        eml_path = folder_dir / f"{base}.eml"
        meta_path = folder_dir / f"{base}.json"
        _secure_atomic_write_bytes(eml_path, msg_bytes)
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
        _secure_atomic_json(meta_path, meta)
        return base

    def merge_covered_virtual_flags(
        content_identity: Tuple[int, str],
        match_index: int,
        flags: str,
        internaldate: str,
    ) -> bool:
        metadata_entries = regular_metadata_paths_by_content.get(content_identity, [])
        if match_index < 0 or match_index >= len(metadata_entries):
            raise RuntimeError("covered virtual message has no matching regular metadata")
        virtual_internaldate = _normalized_legacy_internaldate(internaldate)
        if not virtual_internaldate:
            return False
        same_date_paths = [
            path
            for path, regular_internaldate in metadata_entries
            if _normalized_legacy_internaldate(regular_internaldate) == virtual_internaldate
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
                folder_dir = account_dir / sanitize_for_path(mailbox)
                uids, uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox)
                logging.info("[export] %s: %s -> %d messages", account.email, mailbox, len(uids))
                if not uids:
                    if virtual_source and not export_scope_only_virtual:
                        continue
                    verify_legacy_mailbox_uid_set_stable(imap, mailbox, uids, uidvalidity)
                    ensure_private_dir(folder_dir)
                    delimiter = mailbox_delimiter_by_name.get(mailbox, "")
                    _secure_atomic_json(
                        folder_dir / ".mailbox.json",
                        _legacy_mailbox_metadata(mailbox, 0, delimiter, uidvalidity),
                    )
                    _remove_stale_export_files(folder_dir, set())
                    export_state_mailboxes.append(_legacy_export_state_mailbox_metadata(
                        mailbox,
                        sanitize_for_path(mailbox),
                        0,
                        delimiter,
                        uidvalidity,
                    ))
                    continue

                ensure_private_dir(folder_dir)
                written_stems: set[str] = set()
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
                            if content_identity in ambiguous_virtual_content:
                                pass
                            elif seen_virtual_content[content_identity] <= exported_regular_content[content_identity]:
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
                            elif exported_regular_content[content_identity]:
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
                        if not virtual_source:
                            regular_metadata_paths_by_content.setdefault(content_identity, []).append(
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
    return bool(_IMAP_INTERNALDATE_RE.fullmatch(value))


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
        elif internaldate_raw.strip():
            stripped = internaldate_raw.strip()
            parse_value = stripped[1:-1] if stripped.startswith('"') and stripped.endswith('"') else stripped
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in parse_value):
                errors.append("invalid internaldate metadata")
            elif _valid_legacy_internaldate(parse_value):
                internaldate = stripped
            else:
                errors.append("invalid internaldate metadata")
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
) -> None:
    """Import all messages for an account from `in_root/<email>/...`.

    If a provisioning context is provided and initial login fails, a one-time
    lazy POP account creation is attempted before retrying login.
    """
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
            client, quota_mb, provision_label = provision_context
            try:
                if "@" in account.email:
                    local, domain = account.email.split("@", 1)
                else:
                    raise ValueError("invalid email address for provisioning")
                # Create mailbox then retry login
                client.create_pop_account(domain, local, account.password, quota_mb=quota_mb)  # type: ignore[attr-defined]
                logging.info("[%s][lazy] Created mailbox: %s, retrying login", provision_label, account.email)
                _try_login_only()
                login_ok = True
            except Exception as retry_exc:
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
                    if isinstance(internaldate, str) and internaldate.strip():
                        dt_str = internaldate.strip()
                        if not (dt_str.startswith("\"") and dt_str.endswith("\"")):
                            dt_str = f'"{dt_str}"'
                        date_time = dt_str
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
                    _append_legacy_import_journal(account_dir, {
                        "key": import_key,
                        "status": "pending",
                        "target": target_id,
                        "mailbox": mailbox,
                        "path": rel_path,
                        "rfc822_size": str(len(append_data)),
                        "content_sha256": hashlib.sha256(append_data).hexdigest(),
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
                            "key": import_key,
                            "status": "failed",
                            "target": target_id,
                            "mailbox": mailbox,
                            "path": rel_path,
                            "rfc822_size": str(len(append_data)),
                            "content_sha256": hashlib.sha256(append_data).hexdigest(),
                            "timestamp": str(int(time.time())),
                        })
                        pending_keys.discard(import_key)
                        pending_keys.discard(legacy_raw_key)
                        raise RuntimeError(f"append failed for {eml_path}")
                    _append_legacy_import_journal(account_dir, {
                        "key": import_key,
                        "status": "committed",
                        "target": target_id,
                        "mailbox": mailbox,
                        "path": rel_path,
                        "rfc822_size": str(len(append_data)),
                        "content_sha256": hashlib.sha256(append_data).hexdigest(),
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
