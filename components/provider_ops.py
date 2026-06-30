from __future__ import annotations

import contextlib
import errno
import hashlib
import imaplib
import json
import logging
import os
import re
import socket
import ssl
import stat
import threading
import time
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .content_binding import (
    CONTENT_BINDING_FIELD,
    normalize_provider_mailbox_attributes,
    provider_content_binding_issue,
    provider_content_binding_matches,
    provider_content_binding_sha256,
)
from .executor import parallel_process_accounts
from .imap_ops import _imap_append_wire_bytes, _valid_legacy_flag_token, _valid_legacy_internaldate
from .models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig, auth_username_identity
from .secret_files import read_secret_file_no_links
from .utils import (
    decode_imap_utf7,
    encode_imap_utf7,
    parse_imap_uid_search_data,
    parse_imap_uid_token,
    quote_imap_search_value,
    sanitize_for_path,
)


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_HAS_DESCRIPTOR_RELATIVE_OPEN = os.open in os.supports_dir_fd
_HAS_DESCRIPTOR_RELATIVE_MKDIR = _HAS_DESCRIPTOR_RELATIVE_OPEN and os.mkdir in os.supports_dir_fd
_PROVIDER_UIDVALIDITY_RE = re.compile(r"[1-9][0-9]*")
_PROVIDER_UIDVALIDITY_MAX = 0xFFFFFFFF
_GMAIL_IDENTITY_ENDPOINT = ProviderEndpoint(
    provider="gmail",
    host="imap.gmail.com",
    auth=AuthConfig(method="xoauth2"),
)


@dataclass(frozen=True)
class MailboxInfo:
    name: str
    delimiter: str
    attributes: Tuple[str, ...]


class RateLimiter:
    def __init__(self, max_bytes_per_second: int = 0) -> None:
        self.max_bytes_per_second = int(max_bytes_per_second or 0)
        self._next_time = 0.0
        self._lock = threading.Lock()

    def wait_for(self, byte_count: int, *, stop_event: Optional[object] = None, label: str = "rate limiter") -> None:
        if self.max_bytes_per_second <= 0 or byte_count <= 0:
            return
        with self._lock:
            _raise_if_stopped(stop_event, label)
            now = time.monotonic()
            if now < self._next_time:
                delay = self._next_time - now
                wait = getattr(stop_event, "wait", None) if stop_event is not None else None
                if callable(wait):
                    if wait(delay):
                        raise RuntimeError(f"{label}: stop requested during throttle wait")
                else:
                    time.sleep(delay)
                now = time.monotonic()
                _raise_if_stopped(stop_event, label)
            self._next_time = now + (byte_count / float(self.max_bytes_per_second))


def build_xoauth2_payload(username: str, access_token: str) -> bytes:
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")


def xoauth2_authenticator(username: str, access_token: str) -> Callable[[bytes], bytes]:
    sent_initial_response = False

    def authenticate(_challenge: bytes) -> bytes:
        nonlocal sent_initial_response
        if sent_initial_response:
            return b""
        sent_initial_response = True
        return build_xoauth2_payload(username, access_token)

    return authenticate


def resolve_secret(auth: AuthConfig) -> str:
    value: Optional[str]
    if auth.env_var:
        value = os.environ.get(auth.env_var)
        if value is None:
            raise RuntimeError(f"environment variable {auth.env_var} is not set")
    elif auth.token_file:
        value = read_secret_file_no_links(auth.token_file, label="token file")
    elif auth.password_file:
        value = read_secret_file_no_links(auth.password_file, label="password file")
    elif auth.password is not None:
        value = auth.password
    else:
        raise RuntimeError(f"no secret configured for auth method {auth.method}")
    if value == "":
        raise RuntimeError(f"empty secret configured for auth method {auth.method}")
    return value


def effective_auth(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> Tuple[str, AuthConfig]:
    override = account.source_auth if role == "source" else account.target_auth
    auth = override or endpoint.auth
    fallback_email = account.source_email if role == "source" else account.target_email
    username = auth.username or endpoint.auth.username
    if not username and endpoint.provider == "icloud" and "@" in fallback_email:
        username = fallback_email.split("@", 1)[0]
    if not username:
        username = fallback_email
    return username, auth


def ensure_private_dir(path: Path) -> None:
    dir_fd, dir_path = _open_or_create_provider_dir(path, "directory")
    try:
        stat_result = os.fstat(dir_fd)
        if not stat.S_ISDIR(stat_result.st_mode):
            raise RuntimeError(f"provider directory path is not a directory: {path}")
        _raise_if_provider_parent_replaced(dir_path, dir_fd, "directory")
        with contextlib.suppress(Exception):
            os.fchmod(dir_fd, PRIVATE_DIR_MODE)
        _raise_if_provider_parent_replaced(dir_path, dir_fd, "directory")
    finally:
        os.close(dir_fd)


def _raise_if_provider_path_symlink(path: Path, label: str) -> None:
    if _provider_symlink_component(path) is not None:
        raise RuntimeError(f"refusing to use symlinked provider {label}: {path}")


def _provider_symlink_component(path: Path) -> Optional[Path]:
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


def _provider_normalized_absolute_path(path: Path) -> Path:
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


def _provider_parent_matches_fd(parent_path: Path, parent_fd: int) -> bool:
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


def _raise_if_provider_parent_replaced(parent_path: Path, parent_fd: int, label: str) -> None:
    if not _provider_parent_matches_fd(parent_path, parent_fd):
        raise RuntimeError(f"refusing to use replaced provider {label} directory: {parent_path}")


def _fsync_provider_directory_fd(dir_fd: int, path: Path, label: str) -> None:
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise RuntimeError(f"unable to fsync provider {label} directory for durability: {path}") from exc


def _unlink_provider_entry_and_fsync(parent_fd: int, name: str, parent_path: Path, label: str) -> bool:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return False
    _fsync_provider_directory_fd(parent_fd, parent_path, label)
    return True


def _provider_dir_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_or_create_provider_dir(path: Path, label: str) -> Tuple[int, Path]:
    if not _HAS_DESCRIPTOR_RELATIVE_MKDIR:
        raise RuntimeError("platform does not support descriptor-relative provider directory creation")
    absolute = _provider_normalized_absolute_path(path)
    flags = _provider_dir_open_flags()
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
                    raise RuntimeError(f"refusing to use symlinked provider {label}: {path}") from exc
                if exc.errno != errno.EEXIST:
                    raise
            if created:
                _fsync_provider_directory_fd(fd, current, label)
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked provider {label}: {path}") from exc
                if exc.errno == errno.ENOTDIR:
                    with contextlib.suppress(OSError):
                        component_stat = os.stat(part, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(component_stat.st_mode):
                            raise RuntimeError(f"refusing to use symlinked provider {label}: {path}") from exc
                    raise RuntimeError(f"provider {label} path component is not a directory: {current / part}") from exc
                raise
            try:
                stat_result = os.fstat(next_fd)
                if not stat.S_ISDIR(stat_result.st_mode):
                    raise RuntimeError(f"provider {label} path component is not a directory: {current / part}")
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            current = current / part
        _raise_if_provider_parent_replaced(absolute, fd, label)
        return fd, absolute
    except Exception:
        os.close(fd)
        raise


def _open_provider_parent_dir(path: Path, label: str) -> Tuple[int, str, Path]:
    if not _HAS_DESCRIPTOR_RELATIVE_OPEN:
        raise RuntimeError("platform does not support descriptor-relative provider file access")
    absolute = _provider_normalized_absolute_path(path)
    name = absolute.name
    if not name or name in {".", ".."}:
        raise RuntimeError(f"refusing to use invalid provider {label} path: {path}")
    parent_path = absolute.parent
    flags = _provider_dir_open_flags()
    fd = os.open(absolute.anchor, flags)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:-1]:
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked provider {label}: {path}") from exc
                if exc.errno == errno.ENOTDIR:
                    with contextlib.suppress(OSError):
                        component_stat = os.stat(part, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(component_stat.st_mode):
                            raise RuntimeError(f"refusing to use symlinked provider {label}: {path}") from exc
                    raise RuntimeError(f"provider {label} path component is not a directory: {current / part}") from exc
                raise
            try:
                stat_result = os.fstat(next_fd)
                if not stat.S_ISDIR(stat_result.st_mode):
                    raise RuntimeError(f"provider {label} path component is not a directory: {current / part}")
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            current = current / part
        _raise_if_provider_parent_replaced(parent_path, fd, label)
        return fd, name, parent_path
    except Exception:
        os.close(fd)
        raise


def _open_provider_dir(path: Path, label: str) -> Tuple[int, Path]:
    fd, _probe_name, dir_path = _open_provider_parent_dir(path / ".provider-dir-probe", label)
    return fd, dir_path


def _json_values_match(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if set(left) != set(right):
            return False
        return all(_json_values_match(left[key], right[key]) for key in left)
    if isinstance(left, list):
        if len(left) != len(right):
            return False
        return all(_json_values_match(left_item, right_item) for left_item, right_item in zip(left, right))
    return left == right


def _open_provider_private_file(path: Path, flags: int) -> int:
    parent_fd, name, parent_path = _open_provider_parent_dir(path, "file")
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise RuntimeError(f"refusing to use symlinked provider file: {path}") from exc
        if exc.errno == errno.ENXIO:
            raise RuntimeError(f"refusing to use non-regular provider file: {path}") from exc
        raise
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise RuntimeError(f"refusing to use non-regular provider file: {path}")
        if getattr(stat_result, "st_nlink", 1) > 1:
            raise RuntimeError(f"refusing to use hard-linked provider file: {path}")
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
        return fd
    except Exception:
        os.close(fd)
        raise
    finally:
        os.close(parent_fd)


def _read_provider_private_file(path: Path) -> str:
    fd = _open_provider_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        return f.read()


def _read_provider_artifact_bytes(path: Path, label: str) -> bytes:
    fd = _open_provider_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _is_provider_artifact_safety_error(exc: BaseException) -> bool:
    message = str(exc)
    return (
        "symlinked provider file" in message
        or "hard-linked provider file" in message
        or "non-regular provider file" in message
    )


def _read_provider_artifact_text(path: Path, label: str) -> str:
    return _read_provider_artifact_bytes(path, label).decode("utf-8")


def provider_endpoint_state(endpoint: ProviderEndpoint, *, username: Optional[str] = None) -> Dict[str, Any]:
    provider_hosts = {"gmail": "imap.gmail.com", "icloud": "imap.mail.me.com"}
    host = provider_hosts.get(endpoint.provider, endpoint.host)
    state: Dict[str, Any] = {
        "provider": endpoint.provider,
        "host": host.strip().lower().rstrip("."),
        "port": int(endpoint.port),
        "ssl": bool(endpoint.ssl),
        "starttls": bool(endpoint.starttls),
    }
    if username is not None:
        state["username"] = auth_username_identity(endpoint, str(username))
    return state


def _provider_endpoint_state_payload_digest(state: Dict[str, Any]) -> str:
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_provider_endpoint_state_dict(state: Dict[str, Any]) -> Dict[str, Any]:
    required = {"provider", "host", "port", "ssl", "starttls"}
    if not required.issubset(state):
        return dict(state)
    try:
        provider = str(state["provider"]).strip().lower()
        host = str(state["host"]).strip().lower().rstrip(".")
        port_raw = state["port"]
        use_ssl = state["ssl"]
        starttls = state["starttls"]
        if type(port_raw) is not int or type(use_ssl) is not bool or type(starttls) is not bool:
            return dict(state)
        port = port_raw
        endpoint = ProviderEndpoint(
            provider=provider,
            host=host,
            port=port,
            ssl=use_ssl,
            starttls=starttls,
        )
    except Exception:
        return dict(state)
    canonical: Dict[str, Any] = {
        "provider": provider,
        "host": host,
        "port": port,
        "ssl": use_ssl,
        "starttls": starttls,
    }
    if "username" in state:
        canonical["username"] = auth_username_identity(endpoint, str(state["username"]))
    return canonical


def _provider_endpoint_state_matches(actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    return _canonical_provider_endpoint_state_dict(actual) == expected


def _provider_endpoint_state_digest_matches(
    actual_endpoint: Any,
    actual_digest: Any,
    expected_digest: str,
) -> bool:
    if not isinstance(actual_digest, str):
        return False
    digest = actual_digest.lower()
    if isinstance(actual_endpoint, dict):
        canonical_digest = _provider_endpoint_state_payload_digest(
            _canonical_provider_endpoint_state_dict(actual_endpoint)
        )
        return digest == canonical_digest == expected_digest.lower()
    return False


def provider_endpoint_state_digest(endpoint: ProviderEndpoint, *, username: Optional[str] = None) -> str:
    return _provider_endpoint_state_payload_digest(provider_endpoint_state(endpoint, username=username))


def provider_account_endpoint_state(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> Dict[str, Any]:
    username, _auth = effective_auth(endpoint, account, role=role)
    return provider_endpoint_state(endpoint, username=username)


def provider_account_endpoint_state_digest(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> str:
    username, _auth = effective_auth(endpoint, account, role=role)
    return provider_endpoint_state_digest(endpoint, username=username)


def provider_target_journal_binding(config: ProviderMigrationConfig, account: MigrationAccount) -> Dict[str, Any]:
    return {
        "target_endpoint": provider_account_endpoint_state(config.target, account, role="target"),
        "target_endpoint_sha256": provider_account_endpoint_state_digest(config.target, account, role="target"),
    }


@contextlib.contextmanager
def imap_connection(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> Iterator[imaplib.IMAP4]:
    provider_hosts = {"gmail": "imap.gmail.com", "icloud": "imap.mail.me.com"}
    host = provider_hosts.get(endpoint.provider, endpoint.host)
    if endpoint.ssl:
        imap = imaplib.IMAP4_SSL(host=host, port=endpoint.port, ssl_context=ssl.create_default_context())
    else:
        imap = imaplib.IMAP4(host=host, port=endpoint.port)
    try:
        if (not endpoint.ssl) and endpoint.starttls:
            imap.starttls(ssl_context=ssl.create_default_context())
        username, auth = effective_auth(endpoint, account, role=role)
        secret = resolve_secret(auth)
        if auth.method == "xoauth2":
            imap.authenticate("XOAUTH2", xoauth2_authenticator(username, secret))
        else:
            imap.login(username, secret)
        yield imap
    finally:
        with contextlib.suppress(Exception):
            imap.logout()


def is_transient_imap_error(exc: BaseException) -> bool:
    if isinstance(exc, (imaplib.IMAP4.abort, socket.timeout, TimeoutError, ConnectionError)):
        return True
    text = str(exc).lower()
    return any(word in text for word in ("timeout", "throttle", "rate", "temporar", "disconnect", "try again"))


def with_retry(fn: Callable[[], Any], *, attempts: int, label: str, stop_event: Optional[object] = None) -> Any:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max(1, attempts) + 1):
        _raise_if_stopped(stop_event, label)
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            _raise_if_stopped(stop_event, label)
            if attempt >= attempts or not is_transient_imap_error(exc):
                raise
            delay = min(60.0, 2.0 ** (attempt - 1))
            logging.warning("%s failed transiently on attempt %d/%d: %s; retrying in %.1fs", label, attempt, attempts, exc, delay)
            wait = getattr(stop_event, "wait", None) if stop_event is not None else None
            if callable(wait):
                if wait(delay):
                    raise RuntimeError(f"{label}: stop requested before retry")
            else:
                time.sleep(delay)
            _raise_if_stopped(stop_event, label)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"{label} did not run")


def _provider_throttle_wait(
    limiter: RateLimiter,
    byte_count: int,
    *,
    stop_event: Optional[object],
    label: str,
) -> None:
    if isinstance(limiter, RateLimiter):
        limiter.wait_for(byte_count, stop_event=stop_event, label=label)
    else:
        limiter.wait_for(byte_count)
    _raise_if_stopped(stop_event, label)


def _read_imap_token(line: str, start: int) -> Tuple[Optional[str], int]:
    idx = start
    while idx < len(line) and line[idx].isspace():
        idx += 1
    if idx >= len(line):
        return None, idx
    if line[idx] == '"':
        idx += 1
        chars: List[str] = []
        escaped = False
        while idx < len(line):
            char = line[idx]
            idx += 1
            if escaped:
                chars.append(char)
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                return "".join(chars), idx
            chars.append(char)
        return None, idx
    end = idx
    while end < len(line) and not line[end].isspace():
        end += 1
    return line[idx:end], end


def _decode_imap_response_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def parse_list_line(raw: bytes) -> Optional[MailboxInfo]:
    line = _decode_imap_response_text(raw).strip()
    if not line.startswith("("):
        return None
    attrs_end = line.find(")")
    if attrs_end < 0:
        return None
    attrs = tuple(tok for tok in line[1:attrs_end].split() if tok)
    delimiter_raw, idx = _read_imap_token(line, attrs_end + 1)
    name_raw, _idx = _read_imap_token(line, idx)
    if delimiter_raw is None or name_raw is None:
        return None
    delimiter = "" if delimiter_raw.upper() == "NIL" else decode_imap_utf7(delimiter_raw)
    name = decode_imap_utf7(name_raw)
    return MailboxInfo(name=name, delimiter=delimiter, attributes=attrs)


def parse_list_entry(raw: Any) -> Optional[MailboxInfo]:
    if isinstance(raw, (bytes, bytearray)):
        return parse_list_line(bytes(raw))
    if not (isinstance(raw, tuple) and len(raw) == 2):
        return None
    header, literal = raw
    if not isinstance(header, (bytes, bytearray)) or not isinstance(literal, (bytes, bytearray)):
        return None
    line = _decode_imap_response_text(bytes(header)).strip()
    if not line.startswith("("):
        return None
    attrs_end = line.find(")")
    if attrs_end < 0:
        return None
    attrs = tuple(tok for tok in line[1:attrs_end].split() if tok)
    delimiter_raw, idx = _read_imap_token(line, attrs_end + 1)
    if delimiter_raw is None:
        return None
    rest = line[idx:].strip()
    if not re.fullmatch(r"\{\d+\}", rest):
        return None
    delimiter = "" if delimiter_raw.upper() == "NIL" else decode_imap_utf7(delimiter_raw)
    name = decode_imap_utf7(_decode_imap_response_text(bytes(literal)))
    return MailboxInfo(name=name, delimiter=delimiter, attributes=attrs)


def is_noselect(mailbox: MailboxInfo) -> bool:
    return any(attr.lower() in {"\\noselect", "\\nonexistent"} for attr in mailbox.attributes)


def is_virtual_source_mailbox(provider: str, mailbox: MailboxInfo) -> bool:
    provider_key = provider.lower()
    if provider_key == "icloud" and mailbox.name.lower() == "vip":
        return True
    if provider_key != "gmail":
        attr_lowers = {attr.lower() for attr in mailbox.attributes}
        if "\\all" in attr_lowers:
            return True
    return False


def _mailbox_attrs(mailbox: MailboxInfo) -> set[str]:
    return {attr.lower() for attr in mailbox.attributes}


def _is_non_gmail_all_mailbox(provider_key: str, mailbox: MailboxInfo) -> bool:
    return provider_key != "gmail" and "\\all" in _mailbox_attrs(mailbox)


def _is_non_gmail_flagged_mailbox(provider_key: str, mailbox: MailboxInfo) -> bool:
    return provider_key != "gmail" and "\\flagged" in _mailbox_attrs(mailbox)


def _is_icloud_vip_mailbox(provider_key: str, mailbox: MailboxInfo) -> bool:
    return provider_key == "icloud" and mailbox.name.lower() == "vip"


def should_skip_source_mailbox(provider: str, mailbox: MailboxInfo, mailboxes: List[MailboxInfo]) -> bool:
    provider_key = provider.lower()
    if is_noselect(mailbox):
        return True
    if _is_icloud_vip_mailbox(provider_key, mailbox):
        return True
    if provider_key == "gmail":
        return False
    if _is_non_gmail_all_mailbox(provider_key, mailbox):
        return False
    return False


def _source_mailbox_scan_order(provider_key: str, mailboxes: List[MailboxInfo]) -> List[MailboxInfo]:
    indexed = list(enumerate(mailboxes))
    indexed.sort(
        key=lambda item: (
            2
            if _is_non_gmail_flagged_mailbox(provider_key, item[1])
            else 1
            if _is_non_gmail_all_mailbox(provider_key, item[1])
            else 0,
            item[0],
        )
    )
    return [mailbox for _idx, mailbox in indexed]


def is_virtual_target_mailbox(provider: str, mailbox: MailboxInfo) -> bool:
    return provider.lower() == "icloud" and mailbox.name.lower() == "vip"


def mailbox_path_segments(mailbox_name: str, delimiter: str) -> List[str]:
    if delimiter and delimiter in mailbox_name:
        return [segment for segment in mailbox_name.split(delimiter) if segment]
    return [mailbox_name]


def target_hierarchy_delimiter(mailboxes: List[MailboxInfo]) -> str:
    for mailbox in mailboxes:
        if mailbox.delimiter:
            return mailbox.delimiter
    return ""


def translate_source_mailbox_for_target(
    row: Dict[str, Any],
    desired: str,
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> str:
    special_desired = {
        "archive",
        "sent",
        "drafts",
        "deleted messages",
        "trash",
        "junk",
        "spam",
        "important",
        "starred",
        "flagged",
        "inbox",
    }
    if desired.lower() in special_desired:
        return desired
    source_paths = row.get("source_mailbox_paths")
    if not isinstance(source_paths, dict):
        return desired
    raw_segments = source_paths.get(desired)
    if not isinstance(raw_segments, list) or not raw_segments:
        return desired
    segments = [str(segment) for segment in raw_segments if str(segment)]
    if len(segments) <= 1:
        return desired
    delimiter = target_hierarchy_delimiter(target_mailboxes)
    if not delimiter:
        return desired
    return delimiter.join(segments)


def gmail_all_mail_visible(mailboxes: List[MailboxInfo]) -> bool:
    return any(
        not is_noselect(mailbox)
        and any(attr.lower() == "\\all" for attr in mailbox.attributes)
        for mailbox in mailboxes
    )


def gmail_all_mail_names(mailboxes: List[MailboxInfo]) -> List[str]:
    return [
        mailbox.name
        for mailbox in mailboxes
        if not is_noselect(mailbox)
        and any(attr.lower() == "\\all" for attr in mailbox.attributes)
    ]


def gmail_all_mail_select_issues(
    imap: imaplib.IMAP4,
    mailboxes: List[MailboxInfo],
    *,
    role: str,
) -> List[str]:
    issues: List[str] = []
    for mailbox in gmail_all_mail_names(mailboxes):
        status, response = select_mailbox(imap, mailbox, readonly=True)
        if status != "OK":
            issues.append(f"Gmail {role} All Mail is not selectable via IMAP: {mailbox!r} ({response})")
    return issues


def gmail_source_readiness_issues(capabilities: List[str], mailboxes: List[MailboxInfo]) -> List[str]:
    issues: List[str] = []
    if "X-GM-EXT-1" not in capabilities:
        issues.append("Gmail source did not advertise X-GM-EXT-1")
    if not gmail_all_mail_visible(mailboxes):
        issues.append(
            "Gmail source All Mail is not visible via IMAP; enable All Mail/labels for IMAP or use OAuth/admin scope that exposes all mail before decommissioning"
        )
    return issues


def gmail_target_readiness_issues(capabilities: List[str], mailboxes: List[MailboxInfo]) -> List[str]:
    issues: List[str] = []
    if "X-GM-EXT-1" not in capabilities:
        issues.append("target Gmail IMAP server did not advertise X-GM-EXT-1")
    if not gmail_all_mail_visible(mailboxes):
        issues.append(
            "Gmail target All Mail is not visible via IMAP; enable All Mail/labels for IMAP or use OAuth/admin scope that exposes all mail before decommissioning proof"
        )
    return issues


def gmail_source_decommission_issues(endpoint: ProviderEndpoint) -> List[str]:
    if endpoint.provider != "gmail" or endpoint.gmail_full_visibility_verified:
        return []
    return [
        "Gmail source full IMAP visibility is not attested; before server decommissioning, "
        "set source.gmail_full_visibility_verified=true only after verifying Workspace "
        "gmail.imap_admin access or Gmail IMAP settings with no folder-size limit and required labels visible in IMAP"
    ]


def gmail_full_visibility_attested(endpoint: ProviderEndpoint, account: MigrationAccount) -> bool:
    if endpoint.provider != "gmail":
        return False
    return bool(account.gmail_full_visibility_verified or endpoint.gmail_full_visibility_verified)


def gmail_target_full_visibility_attested(endpoint: ProviderEndpoint, account: MigrationAccount) -> bool:
    if endpoint.provider != "gmail":
        return False
    return bool(account.target_gmail_full_visibility_verified or endpoint.gmail_full_visibility_verified)


def gmail_account_decommission_issues(endpoint: ProviderEndpoint, account: MigrationAccount) -> List[str]:
    if endpoint.provider != "gmail" or gmail_full_visibility_attested(endpoint, account):
        return []
    return gmail_source_decommission_issues(endpoint)


def gmail_target_decommission_issues(endpoint: ProviderEndpoint, account: MigrationAccount) -> List[str]:
    if endpoint.provider != "gmail" or gmail_target_full_visibility_attested(endpoint, account):
        return []
    return [
        "Gmail target full IMAP visibility is not attested; before server decommissioning, "
        "set target.gmail_full_visibility_verified=true for single-account configs or "
        "accounts[].target_gmail_full_visibility_verified=true for multi-account configs only after "
        "verifying the target is not hiding messages from IMAP"
    ]


def quote_mailbox_name(mailbox: str) -> str:
    if mailbox.upper() == "INBOX":
        return "INBOX"
    encoded = encode_imap_utf7(mailbox)
    escaped = encoded.replace("\\", "\\\\").replace('"', r"\"")
    return f'"{escaped}"'


def select_mailbox(imap: imaplib.IMAP4, mailbox: str, *, readonly: bool = False) -> Tuple[str, List[bytes]]:
    return imap.select(quote_mailbox_name(mailbox), readonly=readonly)


def create_mailbox(imap: imaplib.IMAP4, mailbox: str) -> Tuple[str, List[bytes]]:
    return imap.create(quote_mailbox_name(mailbox))


def subscribe_mailbox(imap: imaplib.IMAP4, mailbox: str) -> None:
    subscribe = getattr(imap, "subscribe", None)
    if not callable(subscribe):
        return
    try:
        result = subscribe(quote_mailbox_name(mailbox))
    except Exception as exc:
        logging.warning("[provider-import] failed to subscribe target mailbox %s: %s", mailbox, exc)
        return
    status = result[0] if isinstance(result, (tuple, list)) and result else result
    if isinstance(status, bytes):
        status = status.decode("ascii", errors="ignore")
    if isinstance(status, str) and status.upper() != "OK":
        logging.warning("[provider-import] failed to subscribe target mailbox %s: %s", mailbox, result)


def append_message(imap: imaplib.IMAP4, mailbox: str, flags: str, date_time: str, data: bytes) -> Tuple[str, List[bytes]]:
    return imap.append(quote_mailbox_name(mailbox), flags, date_time, data)


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


def list_mailboxes(imap: imaplib.IMAP4) -> List[MailboxInfo]:
    status, data = _list_mailboxes_with_special_use(imap)
    if status != "OK":
        raise RuntimeError("failed to list mailboxes")
    mailboxes: List[MailboxInfo] = []
    seen = set()
    for raw in data or []:
        info = parse_list_entry(raw)
        if info is None or info.name in seen:
            continue
        seen.add(info.name)
        mailboxes.append(info)
    mailboxes.sort(key=lambda m: (0 if m.name.upper() == "INBOX" else 1, m.name.lower()))
    return mailboxes


def get_capabilities(imap: imaplib.IMAP4) -> List[str]:
    status, data = imap.capability()
    if status != "OK":
        return []
    joined = b" ".join(part for part in (data or []) if isinstance(part, (bytes, bytearray)))
    return sorted({tok.decode(errors="ignore").upper() for tok in joined.split() if tok})


def _parse_parenthesized_words(raw: str, *, drop_literal_markers: bool = False) -> List[str]:
    words: List[str] = []
    for match in re.finditer(r'"((?:\\.|[^"])*)"|(\S+)', raw):
        quoted, atom = match.groups()
        if drop_literal_markers and quoted is None and re.fullmatch(r"\{\d+\}", str(atom or "").strip()):
            continue
        value = quoted if quoted is not None else atom
        value = value.replace(r"\"", '"').replace(r"\\", "\\")
        if value:
            words.append(decode_imap_utf7(value))
    return words


def _provider_fetch_atom_value_start(meta_str: str, atom: str) -> Optional[int]:
    atom_upper = atom.upper()
    atom_len = len(atom)
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
        if depth <= 1 and meta_str[idx : idx + atom_len].upper() == atom_upper:
            before = meta_str[idx - 1] if idx else ""
            after_idx = idx + atom_len
            after = meta_str[after_idx] if after_idx < len(meta_str) else ""
            if (not before or not (before.isalnum() or before in "_.-")) and after.isspace():
                value_idx = after_idx
                while value_idx < len(meta_str) and meta_str[value_idx].isspace():
                    value_idx += 1
                return value_idx
        idx += 1
    return None


_PROVIDER_FETCH_ITEM_ATOMS = (
    "BODY.PEEK[]",
    "RFC822.SIZE",
    "INTERNALDATE",
    "X-GM-LABELS",
    "X-GM-MSGID",
    "X-GM-THRID",
    "BODY[]",
    "FLAGS",
    "RFC822",
    "UID",
)


def _provider_fetch_item_atom_at(meta_str: str, idx: int) -> bool:
    before = meta_str[idx - 1] if idx else ""
    if before and (before.isalnum() or before in "_.-"):
        return False
    for atom in _PROVIDER_FETCH_ITEM_ATOMS:
        atom_len = len(atom)
        if meta_str[idx : idx + atom_len].upper() != atom:
            continue
        after_idx = idx + atom_len
        after = meta_str[after_idx] if after_idx < len(meta_str) else ""
        if not after or after.isspace() or after in "({":
            return True
    return False


def _extract_parenthesized_from(meta_str: str, start: int) -> str:
    if start >= len(meta_str) or meta_str[start] != "(":
        return ""
    depth = 0
    in_quote = False
    escaped = False
    chars: List[str] = []
    for idx in range(start, len(meta_str)):
        ch = meta_str[idx]
        if escaped:
            if depth > 0:
                chars.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quote:
            if depth > 0:
                chars.append(ch)
            escaped = True
            continue
        if ch == '"':
            if depth > 0:
                chars.append(ch)
            in_quote = not in_quote
            continue
        if not in_quote and ch == "(":
            depth += 1
            if depth > 1:
                chars.append(ch)
            continue
        if not in_quote and ch == ")":
            depth -= 1
            if depth == 0:
                return "".join(chars)
            chars.append(ch)
            continue
        if depth > 0:
            chars.append(ch)
    return ""


def _extract_parenthesized_after(meta_str: str, atom: str) -> str:
    start = _provider_fetch_atom_value_start(meta_str, atom)
    if start is None:
        return ""
    return _extract_parenthesized_from(meta_str, start)


def _provider_fetch_number_after(meta_str: str, atom: str) -> str:
    start = _provider_fetch_atom_value_start(meta_str, atom)
    if start is None:
        return ""
    idx = start
    while idx < len(meta_str) and meta_str[idx].isdigit():
        idx += 1
    if idx == start:
        return ""
    next_ch = meta_str[idx] if idx < len(meta_str) else ""
    if next_ch and (next_ch.isalnum() or next_ch in "_.-"):
        return ""
    return meta_str[start:idx]


def _provider_fetch_quoted_after(meta_str: str, atom: str) -> str:
    start = _provider_fetch_atom_value_start(meta_str, atom)
    if start is None or start >= len(meta_str) or meta_str[start] != '"':
        return ""
    chars: List[str] = []
    escaped = False
    for ch in meta_str[start + 1 :]:
        if escaped:
            chars.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return "".join(chars)
        else:
            chars.append(ch)
    return ""


def _provider_fetch_labels_has_literal_marker(meta_str: str) -> bool:
    start = _provider_fetch_atom_value_start(meta_str, "X-GM-LABELS")
    if start is None:
        return False
    tail = meta_str[start:]
    idx = 0
    while idx < len(tail) and tail[idx].isspace():
        idx += 1
    if re.match(r"\{\d+\}", tail[idx:]):
        return True
    if idx >= len(tail) or tail[idx] != "(":
        return False
    depth = 0
    in_quote = False
    escaped = False
    while idx < len(tail):
        ch = tail[idx]
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
            if depth == 0:
                return False
            idx += 1
            continue
        if depth >= 1 and re.match(r"\{\d+\}", tail[idx:]):
            return True
        idx += 1
    return False


def _trim_gmail_label_list_at_fetch_item(raw: str) -> str:
    in_quote = False
    escaped = False
    saw_literal_marker = False
    idx = 0
    while idx < len(raw):
        ch = raw[idx]
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
        literal_match = re.match(r"\{\d+\}", raw[idx:])
        if literal_match:
            saw_literal_marker = True
            idx += len(literal_match.group(0))
            continue
        if saw_literal_marker and _provider_fetch_item_atom_at(raw, idx):
            return raw[:idx].rstrip()
        idx += 1
    return raw


def _provider_fetch_label_value_end(meta_str: str, start: int) -> int:
    idx = start
    while idx < len(meta_str) and meta_str[idx].isspace():
        idx += 1
    if idx >= len(meta_str):
        return idx
    literal_match = re.match(r"\{\d+\}", meta_str[idx:])
    if literal_match:
        return idx + len(literal_match.group(0))
    if meta_str[idx] != "(":
        while idx < len(meta_str) and not meta_str[idx].isspace() and meta_str[idx] != ")":
            idx += 1
        return idx
    depth = 0
    in_quote = False
    escaped = False
    saw_literal_marker = False
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
            if depth == 0:
                return idx
            continue
        literal_match = re.match(r"\{\d+\}", meta_str[idx:])
        if depth >= 1 and literal_match:
            saw_literal_marker = True
            idx += len(literal_match.group(0))
            continue
        if depth == 1 and saw_literal_marker and _provider_fetch_item_atom_at(meta_str, idx):
            return idx
        idx += 1
    return idx


def _provider_fetch_meta_without_label_values(meta_str: str) -> str:
    start = _provider_fetch_atom_value_start(meta_str, "X-GM-LABELS")
    if start is None:
        return meta_str
    end = _provider_fetch_label_value_end(meta_str, start)
    return f"{meta_str[:start]}(){meta_str[end:]}"


_MAX_GMAIL_UINT64 = (1 << 64) - 1
_PROVIDER_FETCH_RESPONSE_START_RE = re.compile(r"^\s*\d+\s+\(")


def _provider_fetch_response_sequence_number(meta_text: str) -> Optional[int]:
    match = _PROVIDER_FETCH_RESPONSE_START_RE.match(meta_text)
    if not match:
        return None
    with contextlib.suppress(ValueError):
        return int(meta_text[: match.end() - 1].strip())
    return None


def _provider_imap_sequence_number(value: bytes) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise RuntimeError(f"invalid target IMAP sequence number {value!r}") from exc
    if number <= 0:
        raise RuntimeError(f"invalid target IMAP sequence number {value!r}")
    return number


def _provider_fetch_response_for_sequence(fetch_response: Iterable[Any], expected_sequence: bytes) -> List[Any]:
    expected_num = _provider_imap_sequence_number(expected_sequence)
    selected: List[Any] = []
    active_expected = False
    for part in fetch_response:
        meta = part[0] if isinstance(part, tuple) and part else part
        if isinstance(meta, (bytes, bytearray)):
            meta_text = bytes(meta).decode(errors="ignore")
        else:
            meta_text = str(meta or "")
        sequence_num = _provider_fetch_response_sequence_number(meta_text)
        if sequence_num is not None:
            active_expected = sequence_num == expected_num
            if active_expected:
                selected.append(part)
            continue
        if active_expected:
            selected.append(part)
    if not selected:
        raise RuntimeError(f"fetch response for sequence {expected_num} did not include matching data")
    return selected


def _provider_fetch_response_uids(meta_str: str) -> List[int]:
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


def _provider_fetch_part_meta_text(part: Any) -> str:
    meta = part[0] if isinstance(part, tuple) and part else part
    if isinstance(meta, (bytes, bytearray)):
        return bytes(meta).decode(errors="ignore")
    return str(meta or "")


def _provider_fetch_group_has_message_body(parts: List[Any]) -> bool:
    for part in parts:
        if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
            continue
        meta_text = _provider_fetch_part_meta_text(part)
        if re.search(r"(?:BODY(?:\.PEEK)?\[\]|(?<![\w.])RFC822(?![\w.]))", meta_text, flags=re.IGNORECASE):
            return True
    return False


def _provider_fetch_response_for_uid(fetch_response: Iterable[Any], expected_uid: int) -> List[Any]:
    selected: List[Any] = []
    current: List[Any] = []

    def finish_current() -> None:
        nonlocal current
        if not current:
            return
        uids: List[int] = []
        for part in current:
            uids.extend(_provider_fetch_response_uids(_provider_fetch_part_meta_text(part)))
        if uids:
            unique_uids = set(uids)
            if expected_uid in unique_uids:
                if len(unique_uids) > 1:
                    raise RuntimeError(f"fetch response mixed UID metadata for UID {expected_uid}")
                selected.extend(current)
            elif _provider_fetch_group_has_message_body(current):
                raise RuntimeError(f"fetch returned message bytes for unexpected UID {uids[0]}")
        elif _provider_fetch_group_has_message_body(current):
            raise RuntimeError(f"fetch response for UID {expected_uid} did not include UID metadata")
        current = []

    for part in fetch_response:
        meta_text = _provider_fetch_part_meta_text(part)
        if _PROVIDER_FETCH_RESPONSE_START_RE.match(meta_text):
            finish_current()
        current.append(part)
    finish_current()
    if not selected:
        raise RuntimeError(f"fetch response for UID {expected_uid} did not include UID metadata")
    return selected


def _valid_gmail_uint64(value: Optional[str]) -> str:
    if not value or not value.isdecimal():
        return ""
    try:
        number = int(value)
    except ValueError:
        return ""
    if number > _MAX_GMAIL_UINT64:
        return ""
    return value


def parse_provider_fetch_response(fetch_response: Iterable[Any], *, expected_uid: Optional[int] = None) -> Dict[str, Any]:
    expected_uid_int = int(expected_uid) if expected_uid is not None else None
    if expected_uid_int is not None:
        return parse_provider_fetch_response(_provider_fetch_response_for_uid(fetch_response, expected_uid_int))
    msg_bytes: Optional[bytes] = None
    meta_chunks: List[str] = []
    literal_labels: List[str] = []
    label_literal_context = False
    label_literal_matches_expected = True
    active_matches_expected: Optional[bool] = None
    seen_expected_uid = expected_uid_int is None
    pending_body: Optional[bytes] = None
    pending_body_meta_chunks: List[str] = []

    def finalize_pending_body() -> None:
        nonlocal msg_bytes, pending_body, pending_body_meta_chunks
        if pending_body is None:
            return
        meta_text = " ".join(pending_body_meta_chunks)
        uids = _provider_fetch_response_uids(meta_text)
        if expected_uid_int is not None:
            unique_uids = set(uids)
            if expected_uid_int not in unique_uids:
                if uids:
                    raise RuntimeError(f"fetch returned message bytes for unexpected UID {uids[0]}")
                raise RuntimeError(f"fetch response for UID {expected_uid_int} did not include UID metadata")
            if len(unique_uids) > 1:
                raise RuntimeError(f"fetch response mixed UID metadata for UID {expected_uid_int}")
        if msg_bytes is not None:
            raise RuntimeError("fetch returned multiple message bodies for one UID")
        msg_bytes = pending_body
        meta_chunks.extend(pending_body_meta_chunks)
        pending_body = None
        pending_body_meta_chunks = []

    def classify_meta(meta_text: str, *, is_body: bool = False) -> bool:
        nonlocal active_matches_expected, seen_expected_uid
        if expected_uid_int is None:
            return True
        uids = _provider_fetch_response_uids(meta_text)
        if uids:
            unique_uids = set(uids)
            if expected_uid_int in unique_uids:
                if len(unique_uids) > 1:
                    raise RuntimeError(f"fetch response mixed UID metadata for UID {expected_uid_int}")
                seen_expected_uid = True
                active_matches_expected = True
                return True
            active_matches_expected = False
            return False
        if is_body:
            raise RuntimeError(f"fetch response for UID {expected_uid_int} did not include UID metadata")
        return bool(active_matches_expected and label_literal_context)

    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            finalize_pending_body()
            meta, body = part
            meta_text = ""
            if isinstance(meta, (bytes, bytearray)):
                meta_text = bytes(meta).decode(errors="ignore")
            body_is_message = (
                isinstance(body, (bytes, bytearray))
                and re.search(r"(?:BODY(?:\.PEEK)?\[\]|(?<![\w.])RFC822(?![\w.]))", meta_text, flags=re.IGNORECASE)
            )
            if body_is_message and expected_uid_int is not None and not _provider_fetch_response_uids(meta_text):
                pending_body = bytes(body)
                pending_body_meta_chunks = [meta_text] if meta_text else []
                continue
            matches_expected = classify_meta(meta_text, is_body=bool(body_is_message))
            if meta_text and matches_expected:
                meta_chunks.append(meta_text)
            has_label_literal = _provider_fetch_labels_has_literal_marker(meta_text)
            if has_label_literal:
                label_literal_context = True
                label_literal_matches_expected = matches_expected
            is_label_literal = bool(
                has_label_literal
                or (label_literal_context and re.fullmatch(r"\s*\{\d+\}\s*", meta_text))
            )
            if body_is_message:
                if not matches_expected:
                    uids = _provider_fetch_response_uids(meta_text)
                    if uids:
                        raise RuntimeError(f"fetch returned message bytes for unexpected UID {uids[0]}")
                    raise RuntimeError(f"fetch response for UID {expected_uid_int} did not include UID metadata")
                if msg_bytes is not None:
                    raise RuntimeError("fetch returned multiple message bodies for one UID")
                msg_bytes = bytes(body)
            elif (
                matches_expected
                and label_literal_matches_expected
                and isinstance(body, (bytes, bytearray))
                and body
                and is_label_literal
            ):
                label = decode_imap_utf7(bytes(body).decode("ascii", errors="ignore").strip())
                if label:
                    literal_labels.append(label)
        elif isinstance(part, (bytes, bytearray)):
            meta_text = bytes(part).decode(errors="ignore")
            if pending_body is not None:
                if _PROVIDER_FETCH_RESPONSE_START_RE.match(meta_text):
                    finalize_pending_body()
                else:
                    pending_body_meta_chunks.append(meta_text)
                    if _provider_fetch_response_uids(meta_text):
                        final_meta = " ".join(pending_body_meta_chunks)
                        matches_expected = classify_meta(final_meta, is_body=True)
                        if not matches_expected:
                            uids = _provider_fetch_response_uids(final_meta)
                            if uids:
                                raise RuntimeError(f"fetch returned message bytes for unexpected UID {uids[0]}")
                            raise RuntimeError(f"fetch response for UID {expected_uid_int} did not include UID metadata")
                    continue
            matches_expected = classify_meta(meta_text)
            if matches_expected:
                meta_chunks.append(meta_text)
            if label_literal_context and ")" in meta_text:
                label_literal_context = False
                label_literal_matches_expected = True
                active_matches_expected = None
    finalize_pending_body()
    if not seen_expected_uid and expected_uid_int is not None:
        raise RuntimeError(f"fetch response for UID {expected_uid_int} did not include UID metadata")
    meta_str = " ".join(meta_chunks)
    meta_without_labels = _provider_fetch_meta_without_label_values(meta_str)

    size_raw = _provider_fetch_number_after(meta_without_labels, "RFC822.SIZE")
    labels_raw = _extract_parenthesized_after(meta_str, "X-GM-LABELS")
    if literal_labels and labels_raw:
        labels_raw = _trim_gmail_label_list_at_fetch_item(labels_raw)
    labels = _parse_parenthesized_words(labels_raw or "", drop_literal_markers=True)
    for label in literal_labels:
        if label not in labels:
            labels.append(label)
    gmail_msgid = _valid_gmail_uint64(_provider_fetch_number_after(meta_without_labels, "X-GM-MSGID"))
    gmail_thrid = _valid_gmail_uint64(_provider_fetch_number_after(meta_without_labels, "X-GM-THRID"))
    return {
        "message_bytes": msg_bytes,
        "flags": _extract_parenthesized_after(meta_without_labels, "FLAGS"),
        "internaldate": _provider_fetch_quoted_after(meta_without_labels, "INTERNALDATE"),
        "rfc822_size": int(size_raw) if size_raw else (len(msg_bytes) if msg_bytes is not None else 0),
        "gmail_msgid": gmail_msgid,
        "gmail_thrid": gmail_thrid,
        "gmail_labels": labels,
    }


def fetch_items(*, include_body: bool, gmail_extensions: bool) -> str:
    items = ["FLAGS", "INTERNALDATE", "RFC822.SIZE"]
    if include_body:
        items.insert(0, "BODY.PEEK[]")
    if gmail_extensions:
        items.extend(["X-GM-MSGID", "X-GM-THRID", "X-GM-LABELS"])
    return f"({' '.join(items)})"


def selected_uidvalidity(imap: imaplib.IMAP4) -> str:
    with contextlib.suppress(Exception):
        _typ, data = imap.response("UIDVALIDITY")
        if data and data[0]:
            value = data[0].decode(errors="ignore") if isinstance(data[0], bytes) else str(data[0])
            value = value.strip()
            if _PROVIDER_UIDVALIDITY_RE.fullmatch(value) and int(value) <= _PROVIDER_UIDVALIDITY_MAX:
                return value
    return ""


def require_selected_uidvalidity(imap: imaplib.IMAP4, mailbox: str) -> str:
    uidvalidity = selected_uidvalidity(imap)
    if not uidvalidity:
        raise RuntimeError(f"Selected mailbox {mailbox} did not provide valid UIDVALIDITY")
    return uidvalidity


def _parse_uid_search_data(data: Any) -> List[int]:
    return parse_imap_uid_search_data(data)


def fetch_all_uids_and_uidvalidity(imap: imaplib.IMAP4, mailbox: str) -> Tuple[List[int], str]:
    status, response = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        raise RuntimeError(f"failed to select mailbox {mailbox}: {response}")
    uidvalidity = require_selected_uidvalidity(imap, mailbox)
    status, data = imap.uid("search", "ALL")
    if status != "OK":
        raise RuntimeError(f"failed to search UIDs in {mailbox}")
    return _parse_uid_search_data(data), uidvalidity


def _message_id_header(msg_bytes: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(msg_bytes)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


def gmail_canonical_identity(gmail_msgid: object, *, source_account: str = "", scope_source: bool = False) -> str:
    msgid = str(gmail_msgid or "").strip()
    if not msgid:
        return ""
    if not scope_source:
        return f"gmail-{msgid}"
    source_identity = auth_username_identity(_GMAIL_IDENTITY_ENDPOINT, source_account)
    if not source_identity:
        raise ValueError("source_account is required when scoping Gmail canonical identity")
    source_digest = hashlib.sha256(source_identity.encode("utf-8")).hexdigest()[:16]
    return f"gmail-{source_digest}-{msgid}"


def canonical_identity(
    parsed: Dict[str, Any],
    msg_bytes: bytes,
    *,
    source_account: str = "",
    mailbox: str = "",
    uidvalidity: str = "",
    uid: Optional[int] = None,
    collapse_fallback: bool = False,
    use_gmail_msgid: bool = True,
    scope_gmail_source: bool = False,
) -> Tuple[str, str, str]:
    sha256 = hashlib.sha256(msg_bytes).hexdigest()
    gmail_msgid = str(parsed.get("gmail_msgid") or "") if use_gmail_msgid else ""
    if gmail_msgid:
        return (
            gmail_canonical_identity(gmail_msgid, source_account=source_account, scope_source=scope_gmail_source),
            sha256,
            _message_id_header(msg_bytes),
        )
    size = int(parsed.get("rfc822_size") or len(msg_bytes))
    message_id = _message_id_header(msg_bytes)
    if collapse_fallback or not mailbox or uid is None:
        seed = json.dumps(
            {
                "message_id": message_id,
                "sha256": sha256,
                "size": size,
                "source_account": source_account,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return f"fallback-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}", sha256, message_id
    seed = json.dumps(
        {
            "mailbox": mailbox,
            "sha256": sha256,
            "size": size,
            "source_account": source_account,
            "uid": uid,
            "uidvalidity": uidvalidity,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"physical-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}", sha256, message_id


def _source_tokens(source_mailboxes: Iterable[str], gmail_labels: Iterable[str]) -> List[str]:
    tokens: List[str] = []
    for value in list(source_mailboxes) + list(gmail_labels):
        if value:
            tokens.append(str(value))
    return tokens


def resolve_primary_mailbox(
    source_mailboxes: Iterable[str],
    gmail_labels: Iterable[str],
    folder_map: Dict[str, str],
    *,
    source_provider: str = "gmail",
) -> str:
    source_tokens = [str(value) for value in source_mailboxes if value]
    label_tokens = [str(value) for value in gmail_labels if value]
    tokens = _source_tokens(source_tokens, label_tokens)
    provider = (source_provider or "imap").lower()
    if provider == "imap":
        physical_tokens = [token for token in source_tokens if not token.startswith("\\")]
        attribute_lowers = {token.lower() for token in source_tokens if token.startswith("\\")}
        for token in physical_tokens:
            if token in folder_map:
                return folder_map[token]
        for token in source_tokens:
            if token in folder_map:
                return folder_map[token]

        def mapped_attribute(default: str, *names: str) -> str:
            for name in names:
                if name in folder_map:
                    return folder_map[name]
            return default

        if "\\sent" in attribute_lowers:
            return mapped_attribute("Sent", "\\Sent", "Sent")
        if "\\drafts" in attribute_lowers:
            return mapped_attribute("Drafts", "\\Drafts", "Drafts")
        if "\\trash" in attribute_lowers:
            return mapped_attribute("Deleted Messages", "\\Trash", "Trash")
        if "\\junk" in attribute_lowers:
            return mapped_attribute("Junk", "\\Junk", "Junk")
        if "\\all" in attribute_lowers:
            return mapped_attribute("Archive", "\\All", "All Mail")
        if "\\archive" in attribute_lowers:
            return mapped_attribute("Archive", "\\Archive", "Archive")
        for token in physical_tokens:
            if token.upper() == "INBOX":
                return folder_map.get(token, folder_map.get("INBOX", "INBOX"))
            return token
    lowered = {token.lower(): token for token in tokens}
    gmail_label_lowers = {token.lower() for token in label_tokens}

    def has_any(*names: str) -> bool:
        return any(name.lower() in lowered for name in names)

    def mapped(default: str, *names: str) -> str:
        name_lowers = {name.lower() for name in names}
        for token in tokens:
            if token.lower() in name_lowers and token in folder_map:
                return folder_map[token]
        for name in names:
            if name in folder_map:
                return folder_map[name]
        return default

    if has_any("[gmail]/sent mail", "[googlemail]/sent mail", "sent", "\\sent"):
        return mapped("Sent", "[Gmail]/Sent Mail", "[GoogleMail]/Sent Mail", "Sent", "\\Sent")
    if has_any("[gmail]/drafts", "[googlemail]/drafts", "drafts", "\\drafts"):
        return mapped("Drafts", "[Gmail]/Drafts", "[GoogleMail]/Drafts", "Drafts", "\\Drafts")
    if has_any("[gmail]/trash", "[googlemail]/trash", "trash", "bin", "\\trash"):
        return mapped("Deleted Messages", "[Gmail]/Trash", "[GoogleMail]/Trash", "Trash", "Bin", "\\Trash")
    if has_any("[gmail]/spam", "[googlemail]/spam", "spam", "junk", "\\junk"):
        return mapped("Junk", "[Gmail]/Spam", "[GoogleMail]/Spam", "Spam", "Junk", "\\Junk")
    if has_any("inbox", "\\inbox"):
        return mapped("INBOX", "INBOX", "\\Inbox", "\\INBOX")
    if has_any("\\archive"):
        return mapped("Archive", "Archive", "\\Archive")
    for token in tokens:
        lower = token.lower()
        if (
            token.upper() == "INBOX"
            or token.startswith("\\")
            or lower in {"all mail"}
            or (lower in {"important", "starred"} and lower in gmail_label_lowers)
            or lower.startswith("[gmail]/")
            or lower.startswith("[googlemail]/")
        ):
            continue
        return folder_map.get(token, token)
    if has_any("[gmail]/all mail", "[googlemail]/all mail", "all mail", "\\all"):
        return mapped("Archive", "[Gmail]/All Mail", "[GoogleMail]/All Mail", "All Mail", "\\All")
    return "Archive"


def _safe_identity(identity: str) -> str:
    safe = sanitize_for_path(identity)
    if len(safe) <= 180:
        return safe
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    prefix_len = 180 - len(digest) - 1
    return f"{safe[:prefix_len]}-{digest}"


def _atomic_json(path: Path, payload: Dict[str, Any]) -> None:
    _atomic_bytes(path, (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))


def _atomic_bytes(path: Path, payload: bytes) -> None:
    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_provider_parent_dir(path, "file")
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
                raise RuntimeError(f"refusing to use unsafe provider temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked provider temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(f"refusing to use non-regular provider temporary file: {path.with_name(tmp_name)}") from exc
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
                _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            except Exception:
                _unlink_provider_entry_and_fsync(parent_fd, name, parent_path, "file")
                raise
            _fsync_provider_directory_fd(parent_fd, parent_path, "file")
            try:
                _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            except Exception:
                _unlink_provider_entry_and_fsync(parent_fd, name, parent_path, "file")
                raise
        except Exception:
            if tmp_name:
                _unlink_provider_entry_and_fsync(parent_fd, tmp_name, parent_path, "file")
            raise
    finally:
        os.close(parent_fd)


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_provider_parent_dir(path, "file")
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
                raise RuntimeError(f"refusing to use unsafe provider temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked provider temporary file: {path.with_name(tmp_name)}") from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(f"refusing to use non-regular provider temporary file: {path.with_name(tmp_name)}") from exc
            raise
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
                for row in rows:
                    json.dump(row, f, ensure_ascii=False, sort_keys=True)
                    f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            tmp_name = ""
            try:
                _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            except Exception:
                _unlink_provider_entry_and_fsync(parent_fd, name, parent_path, "file")
                raise
            _fsync_provider_directory_fd(parent_fd, parent_path, "file")
            try:
                _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            except Exception:
                _unlink_provider_entry_and_fsync(parent_fd, name, parent_path, "file")
                raise
        except Exception:
            if tmp_name:
                _unlink_provider_entry_and_fsync(parent_fd, tmp_name, parent_path, "file")
            raise
    finally:
        os.close(parent_fd)


def account_export_dir(root: Path, account: MigrationAccount) -> Path:
    return root / sanitize_for_path(account.source_email)


def load_manifest(account_dir: Path) -> List[Dict[str, Any]]:
    manifest = account_dir / "manifest.jsonl"
    _raise_if_provider_path_symlink(manifest, "file")
    if not manifest.exists():
        raise RuntimeError(f"manifest not found: {manifest}")
    rows: List[Dict[str, Any]] = []
    for line_no, line in enumerate(_read_provider_private_file(manifest).splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise RuntimeError(f"invalid manifest row {line_no}: {manifest}")
        rows.append(row)
    return rows


def provider_manifest_digest(rows: List[Dict[str, Any]]) -> str:
    canonical_rows = sorted(rows, key=lambda row: str(row.get("canonical_id") or ""))
    payload = json.dumps(canonical_rows, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def journal_target_key(
    identity: str,
    target_mailbox: str,
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> Tuple[str, str]:
    mailbox_key = target_mailbox
    if (target_provider or "imap").lower() == "gmail":
        system_key = _gmail_target_system_key(target_mailbox, target_mailboxes)
        if system_key:
            mailbox_key = f"gmail-system:{system_key}"
    return identity, mailbox_key


def _non_empty_json_string(row: Dict[str, Any], key: str) -> Optional[str]:
    value = row.get(key)
    if not isinstance(value, str) or value == "":
        return None
    return value


def journal_row_target_key(
    row: Dict[str, Any],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> Tuple[str, str]:
    identity = _non_empty_json_string(row, "canonical_id") or ""
    target_mailbox = _non_empty_json_string(row, "target_mailbox") or ""
    return journal_target_key(
        identity,
        target_mailbox,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    )


def latest_committed_journal_rows(
    rows: List[Dict[str, Any]],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    latest = {
        key: row
        for key, row in latest_journal_rows(
            rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        ).items()
        if row.get("status") == "committed"
    }
    if (target_provider or "imap").lower() != "gmail":
        return latest

    row_positions = {id(row): index for index, row in enumerate(rows)}
    latest_by_msgid: Dict[Tuple[str, str], Tuple[Tuple[str, str], Dict[str, Any]]] = {}
    for key, row in latest.items():
        identity = key[0]
        target_gmail_msgid = row.get("target_gmail_msgid")
        if not identity or not is_valid_gmail_msgid(target_gmail_msgid):
            continue
        msgid_key = (identity, str(target_gmail_msgid))
        previous = latest_by_msgid.get(msgid_key)
        if previous is None or row_positions.get(id(row), -1) > row_positions.get(id(previous[1]), -1):
            latest_by_msgid[msgid_key] = (key, row)
    if not latest_by_msgid:
        return latest

    retained_msgid_keys = {key for key, _row in latest_by_msgid.values()}
    superseded_keys = {
        key
        for key, row in latest.items()
        if is_valid_gmail_msgid(row.get("target_gmail_msgid"))
        and (key[0], str(row.get("target_gmail_msgid"))) in latest_by_msgid
        and key not in retained_msgid_keys
    }
    if not superseded_keys:
        return latest
    return {
        key: row
        for key, row in latest.items()
        if key not in superseded_keys
    }


def latest_journal_rows(
    rows: List[Dict[str, Any]],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    latest: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        identity = _non_empty_json_string(row, "canonical_id") or ""
        target_mailbox = _non_empty_json_string(row, "target_mailbox") or ""
        if not identity or not target_mailbox:
            continue
        key = journal_target_key(
            identity,
            target_mailbox,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        if row.get("status") in {"pending", "committed", "failed"}:
            latest[key] = row
    return latest


def provider_export_state_issues(
    account_dir: Path,
    *,
    account: Optional[MigrationAccount] = None,
    manifest_rows: Optional[List[Dict[str, Any]]] = None,
    source_provider: Optional[str] = None,
    target_provider: Optional[str] = None,
    source_endpoint: Optional[ProviderEndpoint] = None,
    target_endpoint: Optional[ProviderEndpoint] = None,
) -> List[str]:
    state_path = account_dir / "export-state.json"
    try:
        state = json.loads(_read_provider_private_file(state_path))
    except Exception as exc:
        return [f"export-state missing or invalid: {exc}"]
    issues: List[str] = []
    if not isinstance(state, dict):
        issues.append(f"export-state is not complete: {state_path}")
        return issues
    issues.extend(
        provider_export_state_contract_issues(
            state,
            account=account,
            source_provider=source_provider,
            target_provider=target_provider,
            source_endpoint=source_endpoint,
            target_endpoint=target_endpoint,
        )
    )
    if state.get("complete") is not True:
        issues.append(f"export-state is not complete: {state_path}")
        return issues
    if manifest_rows is not None:
        effective_source_provider = str(source_provider or state.get("source_provider") or "").lower()
        if not effective_source_provider:
            providers = {str(row.get("source_provider") or "").lower() for row in manifest_rows}
            if len(providers) == 1:
                effective_source_provider = next(iter(providers))
        if effective_source_provider == "gmail" and state.get("gmail_full_visibility_verified") is not True:
            issues.append("export-state Gmail full visibility attestation is missing or false")
        expected_count = len(manifest_rows)
        actual_count = state.get("canonical_messages")
        if type(actual_count) is not int or actual_count != expected_count:
            issues.append(
                f"export-state canonical_messages does not match manifest row count: "
                f"{actual_count if actual_count is not None else '<missing>'} != {expected_count}"
            )
        expected_digest = provider_manifest_digest(manifest_rows)
        actual_digest = state.get("manifest_sha256")
        if not isinstance(actual_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", actual_digest):
            issues.append("export-state manifest_sha256 is missing or invalid")
        elif actual_digest.lower() != expected_digest:
            issues.append(
                f"export-state manifest_sha256 does not match manifest: "
                f"{actual_digest.lower()} != {expected_digest}"
            )
    return issues


def provider_export_state_contract_issues(
    state: Dict[str, Any],
    *,
    account: Optional[MigrationAccount] = None,
    source_provider: Optional[str] = None,
    target_provider: Optional[str] = None,
    source_endpoint: Optional[ProviderEndpoint] = None,
    target_endpoint: Optional[ProviderEndpoint] = None,
) -> List[str]:
    issues: List[str] = []
    if account is not None:
        source_account = state.get("source_account")
        target_account = state.get("target_account")
        if source_account != account.source_email:
            issues.append(
                f"export-state source_account does not match config source_email "
                f"{account.source_email}: {source_account or '<missing>'}"
            )
        if target_account != account.target_email:
            issues.append(
                f"export-state target_account does not match config target_email "
                f"{account.target_email}: {target_account or '<missing>'}"
            )
    if source_provider is not None:
        state_source_provider = str(state.get("source_provider") or "").lower()
        if state_source_provider != source_provider.lower():
            issues.append(
                f"export-state source_provider does not match config source.provider "
                f"{source_provider}: {state_source_provider or '<missing>'}"
            )
    if source_endpoint is not None:
        expected_source_endpoint = (
            provider_account_endpoint_state(source_endpoint, account, role="source")
            if account is not None
            else provider_endpoint_state(source_endpoint)
        )
        state_source_endpoint = state.get("source_endpoint")
        if not isinstance(state_source_endpoint, dict):
            issues.append("export-state source_endpoint is missing; rerun provider export with current version")
        elif not _provider_endpoint_state_matches(state_source_endpoint, expected_source_endpoint):
            issues.append(
                "export-state source_endpoint does not match config source endpoint: "
                f"{state_source_endpoint} != {expected_source_endpoint}"
            )
        expected_source_endpoint_sha = (
            provider_account_endpoint_state_digest(source_endpoint, account, role="source")
            if account is not None
            else provider_endpoint_state_digest(source_endpoint)
        )
        if not _provider_endpoint_state_digest_matches(
            state_source_endpoint,
            state.get("source_endpoint_sha256"),
            expected_source_endpoint_sha,
        ):
            issues.append("export-state source_endpoint_sha256 does not match config source endpoint")
    if target_provider is not None:
        state_target_provider = str(state.get("target_provider") or "").lower()
        if state_target_provider != target_provider.lower():
            issues.append(
                f"export-state target_provider does not match config target.provider "
                f"{target_provider}: {state_target_provider or '<missing>'}"
            )
    if target_endpoint is not None:
        expected_target_endpoint = (
            provider_account_endpoint_state(target_endpoint, account, role="target")
            if account is not None
            else provider_endpoint_state(target_endpoint)
        )
        state_target_endpoint = state.get("target_endpoint")
        if not isinstance(state_target_endpoint, dict):
            issues.append("export-state target_endpoint is missing; rerun provider export with current version")
        elif not _provider_endpoint_state_matches(state_target_endpoint, expected_target_endpoint):
            issues.append(
                "export-state target_endpoint does not match config target endpoint: "
                f"{state_target_endpoint} != {expected_target_endpoint}"
            )
        expected_target_endpoint_sha = (
            provider_account_endpoint_state_digest(target_endpoint, account, role="target")
            if account is not None
            else provider_endpoint_state_digest(target_endpoint)
        )
        if not _provider_endpoint_state_digest_matches(
            state_target_endpoint,
            state.get("target_endpoint_sha256"),
            expected_target_endpoint_sha,
        ):
            issues.append("export-state target_endpoint_sha256 does not match config target endpoint")
    return issues


def require_complete_export_state(
    account_dir: Path,
    *,
    account: Optional[MigrationAccount] = None,
    manifest_rows: Optional[List[Dict[str, Any]]] = None,
    source_provider: Optional[str] = None,
    target_provider: Optional[str] = None,
    source_endpoint: Optional[ProviderEndpoint] = None,
    target_endpoint: Optional[ProviderEndpoint] = None,
) -> None:
    issues = provider_export_state_issues(
        account_dir,
        account=account,
        manifest_rows=manifest_rows,
        source_provider=source_provider,
        target_provider=target_provider,
        source_endpoint=source_endpoint,
        target_endpoint=target_endpoint,
    )
    if issues:
        raise RuntimeError("; ".join(issues))


def manifest_identity_issues(rows: List[Dict[str, Any]]) -> Tuple[List[str], Dict[str, int]]:
    counts: Dict[str, int] = {}
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        identity = str(row.get("canonical_id") or "")
        if not identity:
            issues.append(f"manifest row {idx} missing canonical_id")
            continue
        counts[identity] = counts.get(identity, 0) + 1
    for identity, count in sorted(counts.items()):
        if count > 1:
            issues.append(f"duplicate manifest identity: {identity} ({count} rows)")
    return issues, counts


def manifest_schema_issues(rows: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        identity_raw = row.get("canonical_id")
        identity = identity_raw if isinstance(identity_raw, str) and identity_raw.strip() else f"row {idx}"
        if not isinstance(identity_raw, str) or not identity_raw.strip():
            issues.append(f"{identity}: missing canonical_id")
        primary_mailbox = row.get("primary_mailbox")
        if not isinstance(primary_mailbox, str) or not primary_mailbox.strip():
            issues.append(f"{identity}: missing or invalid primary_mailbox")
        message_id_header = row.get("message_id_header")
        if message_id_header is not None and (
            not isinstance(message_id_header, str)
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in message_id_header)
        ):
            issues.append(f"{identity}: invalid message_id_header")
        for field in ("source_mailboxes", "gmail_labels"):
            value = row.get(field)
            if value is None:
                continue
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                issues.append(f"{identity}: invalid {field}")
        source_mailboxes = row.get("source_mailboxes")
        source_mailbox_names = (
            set(source_mailboxes)
            if isinstance(source_mailboxes, list) and all(isinstance(item, str) and item for item in source_mailboxes)
            else None
        )
        for field in ("source_mailbox_paths", "source_mailbox_attributes"):
            value = row.get(field)
            if value is None:
                continue
            if source_mailbox_names is None:
                issues.append(f"{identity}: invalid {field}: missing source_mailboxes")
                continue
            if not isinstance(value, dict):
                issues.append(f"{identity}: invalid {field}")
                continue
            for map_key, map_value in value.items():
                if (
                    not isinstance(map_key, str)
                    or not map_key
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in map_key)
                ):
                    issues.append(f"{identity}: invalid {field}")
                    break
                if map_key not in source_mailbox_names:
                    issues.append(f"{identity}: invalid {field}: unknown source mailbox {map_key!r}")
                    break
                if not isinstance(map_value, list):
                    issues.append(f"{identity}: invalid {field}")
                    break
                if field == "source_mailbox_paths" and not map_value:
                    issues.append(f"{identity}: invalid {field}")
                    break
                if any(
                    not isinstance(item, str)
                    or (field == "source_mailbox_paths" and not item)
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in item)
                    for item in map_value
                ):
                    issues.append(f"{identity}: invalid {field}")
                    break
    return issues


def require_manifest_schema(rows: List[Dict[str, Any]]) -> None:
    issues = manifest_schema_issues(rows)
    if issues:
        raise RuntimeError("invalid manifest schema: " + "; ".join(issues))


def require_unique_manifest_identities(rows: List[Dict[str, Any]]) -> None:
    issues, _counts = manifest_identity_issues(rows)
    if issues:
        raise RuntimeError("invalid manifest identities: " + "; ".join(issues))


def manifest_account_issues(rows: List[Dict[str, Any]], account: MigrationAccount) -> List[str]:
    source_mismatches = [
        str(row.get("canonical_id") or f"row {idx}")
        for idx, row in enumerate(rows, 1)
        if str(row.get("source_account") or "") != account.source_email
    ]
    target_mismatches = [
        str(row.get("canonical_id") or f"row {idx}")
        for idx, row in enumerate(rows, 1)
        if str(row.get("target_account") or "") != account.target_email
    ]
    issues: List[str] = []
    if source_mismatches:
        issues.append(
            f"manifest source_account does not match config source_email {account.source_email}: "
            + ", ".join(source_mismatches)
        )
    if target_mismatches:
        issues.append(
            f"manifest target_account does not match config target_email {account.target_email}: "
            + ", ".join(target_mismatches)
        )
    return issues


def manifest_source_provider_issues(rows: List[Dict[str, Any]], source_provider: str) -> List[str]:
    expected = source_provider.strip().lower()
    mismatches = [
        str(row.get("canonical_id") or f"row {idx}")
        for idx, row in enumerate(rows, 1)
        if str(row.get("source_provider") or "").lower() != expected
    ]
    if not mismatches:
        return []
    return [
        f"manifest source_provider does not match config source.provider {expected}: "
        + ", ".join(mismatches)
    ]


def require_manifest_source_provider(rows: List[Dict[str, Any]], source_provider: str) -> None:
    issues = manifest_source_provider_issues(rows, source_provider)
    if issues:
        raise RuntimeError("; ".join(issues))


def require_manifest_accounts(rows: List[Dict[str, Any]], account: MigrationAccount) -> None:
    issues = manifest_account_issues(rows, account)
    if issues:
        raise RuntimeError("; ".join(issues))


def manifest_integrity_issues(rows: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        identity = str(row.get("canonical_id") or f"row {idx}")
        expected_hash = row.get("content_sha256")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
            issues.append(f"{identity}: missing or invalid content_sha256")
        expected_size = row.get("rfc822_size")
        if type(expected_size) is not int or expected_size < 0:
            issues.append(f"{identity}: missing or invalid rfc822_size")
        binding_issue = provider_content_binding_issue(row)
        if binding_issue:
            issues.append(f"{identity}: {binding_issue}")
    return issues


def provider_delivery_metadata_issues(rows: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        identity = str(row.get("canonical_id") or f"row {idx}")
        flags_raw = row.get("flags", "")
        if "flags" in row and not isinstance(flags_raw, str):
            issues.append(f"{identity}: invalid flags metadata")
        elif isinstance(flags_raw, str):
            invalid_flags = [token for token in flags_raw.split() if not _valid_legacy_flag_token(token)]
            if invalid_flags:
                issues.append(f"{identity}: invalid flags metadata")

        internaldate_raw = row.get("internaldate")
        if "internaldate" in row:
            if not isinstance(internaldate_raw, str):
                issues.append(f"{identity}: invalid internaldate metadata")
            elif internaldate_raw.strip():
                stripped = internaldate_raw.strip()
                parse_value = stripped[1:-1] if stripped.startswith('"') and stripped.endswith('"') else stripped
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in parse_value):
                    issues.append(f"{identity}: invalid internaldate metadata")
                elif not _valid_legacy_internaldate(parse_value):
                    issues.append(f"{identity}: invalid internaldate metadata")
    return issues


def require_manifest_integrity_metadata(rows: List[Dict[str, Any]]) -> None:
    issues = manifest_integrity_issues(rows)
    if issues:
        raise RuntimeError("invalid manifest integrity metadata: " + "; ".join(issues))


def require_provider_delivery_metadata(rows: List[Dict[str, Any]]) -> None:
    issues = provider_delivery_metadata_issues(rows)
    if issues:
        raise RuntimeError("invalid provider delivery metadata: " + "; ".join(issues))


def require_manifest_payload_matches(row: Dict[str, Any], data: bytes) -> None:
    identity = str(row.get("canonical_id") or "<missing>")
    expected_size = row.get("rfc822_size")
    if type(expected_size) is not int or expected_size < 0:
        raise RuntimeError(f"{identity}: missing or invalid rfc822_size")
    if len(data) != expected_size:
        raise RuntimeError(f"{identity}: rfc822_size mismatch (manifest={expected_size} actual={len(data)})")
    expected_hash = row.get("content_sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
        raise RuntimeError(f"{identity}: missing or invalid content_sha256")
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash.lower() != expected_hash.lower():
        raise RuntimeError(f"{identity}: content_sha256 mismatch")
    binding_issue = provider_content_binding_issue(row)
    if binding_issue:
        raise RuntimeError(f"{identity}: {binding_issue}")


def provider_payload_content_identities(data: bytes) -> set[Tuple[int, str]]:
    identities: set[Tuple[int, str]] = set()
    for payload in (data, _imap_append_wire_bytes(data)):
        identities.add((len(payload), hashlib.sha256(payload).hexdigest()))
    return identities


def manifest_payload_content_identities(account_dir: Path, rows: List[Dict[str, Any]]) -> Dict[str, set[Tuple[int, str]]]:
    identities_by_id: Dict[str, set[Tuple[int, str]]] = {}
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        if not identity:
            continue
        try:
            data = _read_provider_artifact_bytes(_manifest_path(account_dir, row, "eml_path"), "provider message artifact")
            require_manifest_payload_matches(row, data)
        except Exception:
            continue
        identities_by_id[identity] = provider_payload_content_identities(data)
    return identities_by_id


def merge_group_payload_content_identities(
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
) -> Dict[str, set[Tuple[int, str]]]:
    identities_by_id: Dict[str, set[Tuple[int, str]]] = {}
    for _group_account, account_dir, manifest_rows, _journal_rows in stages:
        identities_by_id.update(manifest_payload_content_identities(account_dir, manifest_rows))
    return identities_by_id


def metadata_manifest_issues(account_dir: Path, rows: List[Dict[str, Any]], *, require_present: bool = True) -> List[str]:
    issues: List[str] = []
    for row in rows:
        identity = str(row.get("canonical_id") or "<missing>")
        try:
            meta_path = _manifest_path(account_dir, row, "metadata_path")
        except Exception as exc:
            if require_present:
                issues.append(f"{identity}: invalid metadata_path: {exc}")
            continue
        if not meta_path.exists():
            if require_present:
                issues.append(f"{identity}: missing metadata_path")
            continue
        try:
            metadata = json.loads(_read_provider_artifact_text(meta_path, "provider metadata artifact"))
        except Exception as exc:
            issues.append(f"{identity}: failed to read metadata json: {exc}")
            continue
        if not isinstance(metadata, dict):
            issues.append(f"{identity}: metadata json is not an object")
            continue
        keys = sorted(set(metadata) | set(row))
        for key in keys:
            if key not in metadata:
                issues.append(f"{identity}: metadata {key} missing from metadata")
            elif key not in row:
                issues.append(f"{identity}: metadata {key} absent from manifest")
            elif not _json_values_match(metadata[key], row[key]):
                issues.append(f"{identity}: metadata {key} differs from manifest")
    return issues


def manifest_payload_issues(account_dir: Path, rows: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    for row in rows:
        identity = str(row.get("canonical_id") or "<missing>")
        try:
            eml_path = _manifest_path(account_dir, row, "eml_path")
        except Exception as exc:
            issues.append(f"{identity}: invalid eml_path: {exc}")
            continue
        if not eml_path.exists():
            issues.append(f"{identity}: missing eml_path")
            continue
        try:
            data = _read_provider_artifact_bytes(eml_path, "provider message artifact")
        except Exception as exc:
            issues.append(f"{identity}: failed to read eml: {exc}")
            continue
        try:
            require_manifest_payload_matches(row, data)
        except Exception as exc:
            issues.append(str(exc))
    return issues


def _manifest_relative_paths(account_dir: Path, rows: List[Dict[str, Any]], key: str) -> set[str]:
    root = account_dir.resolve()
    paths: set[str] = set()
    for row in rows:
        try:
            paths.add(_manifest_path(account_dir, row, key).relative_to(root).as_posix())
        except Exception:
            continue
    return paths


def _provider_artifact_orphan_issues(account_dir: Path, rows: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    expected_messages = _manifest_relative_paths(account_dir, rows, "eml_path")
    expected_metadata = _manifest_relative_paths(account_dir, rows, "metadata_path")
    for root_name, suffix, expected, label in (
        ("messages", "*.eml", expected_messages, "message"),
        ("metadata", "*.json", expected_metadata, "metadata"),
    ):
        root = account_dir / root_name
        if root.is_symlink():
            issues.append(f"symlinked provider {label} artifact directory: {root_name}")
            continue
        if not root.exists():
            continue
        reported_symlinks: set[str] = set()
        for path in sorted(root.rglob("*")):
            if not path.is_symlink():
                continue
            rel_path = path.relative_to(account_dir).as_posix()
            reported_symlinks.add(rel_path)
            issues.append(f"symlinked provider {label} artifact directory: {rel_path}")
        for path in sorted(root.rglob(suffix)):
            rel_path = path.relative_to(account_dir).as_posix()
            if rel_path in reported_symlinks:
                continue
            if path.is_symlink():
                issues.append(f"symlinked provider {label} artifact: {rel_path}")
                continue
            if not path.is_file():
                if rel_path not in expected:
                    issues.append(f"unmanifested non-regular provider {label} artifact: {rel_path}")
                else:
                    issues.append(f"non-regular provider {label} artifact: {rel_path}")
                continue
            if rel_path not in expected:
                issues.append(f"unmanifested provider {label} artifact: {rel_path}")
    return issues


def provider_mixed_legacy_layout_issues(account_dir: Path) -> List[str]:
    issues: List[str] = []
    provider_dirs = {"messages", "metadata"}
    for path in sorted(account_dir.iterdir()):
        if path.is_symlink():
            issues.append(f"symlinked provider account entry: {path.name}")
            continue
        if path.name in provider_dirs or not path.is_dir():
            continue
        marker = path / ".mailbox.json"
        has_marker = marker.exists() or marker.is_symlink()
        has_messages = any(candidate.is_file() for candidate in path.glob("*.eml"))
        if has_marker or has_messages:
            issues.append(f"legacy mailbox directory present in provider account layout: {path.name}")
    return issues


def _prune_provider_artifact_orphans(account_dir: Path, rows: List[Dict[str, Any]]) -> None:
    _raise_if_provider_path_symlink(account_dir, "account directory")
    expected_messages = _manifest_relative_paths(account_dir, rows, "eml_path")
    expected_metadata = _manifest_relative_paths(account_dir, rows, "metadata_path")
    for root_name, file_suffix, expected in (
        ("messages", ".eml", expected_messages),
        ("metadata", ".json", expected_metadata),
    ):
        root = account_dir / root_name
        _raise_if_provider_path_symlink(root, "artifact directory")
        if not root.exists():
            continue
        root_fd, root_path = _open_provider_dir(root, "artifact directory")

        def guard() -> None:
            _raise_if_provider_parent_replaced(root_path, root_fd, "artifact directory")

        try:
            _prune_provider_artifact_orphans_at(
                root_fd,
                account_dir,
                root_name,
                (),
                file_suffix,
                expected,
                guard,
            )
        finally:
            os.close(root_fd)


def _prune_provider_artifact_orphans_at(
    parent_fd: int,
    account_dir: Path,
    root_name: str,
    relative_parts: Tuple[str, ...],
    file_suffix: str,
    expected: set[str],
    guard: Callable[[], None],
    current_guard: Optional[Callable[[], None]] = None,
) -> None:
    parent_path = account_dir / root_name
    for part in relative_parts:
        parent_path /= part

    def ensure_current() -> None:
        guard()
        if current_guard is not None:
            current_guard()

    for name in sorted(os.listdir(parent_fd)):
        child_parts = relative_parts + (name,)
        rel_path = "/".join((root_name, *child_parts))
        display_path = account_dir / rel_path
        try:
            stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(stat_result.st_mode):
            raise RuntimeError(f"refusing to prune symlinked provider artifact: {display_path}")
        if stat.S_ISDIR(stat_result.st_mode):
            child_fd = os.open(name, _provider_dir_open_flags(), dir_fd=parent_fd)
            try:
                child_stat = os.fstat(child_fd)
                if not stat.S_ISDIR(child_stat.st_mode):
                    raise RuntimeError(f"refusing to prune non-directory provider artifact path: {display_path}")
                if child_stat.st_dev != stat_result.st_dev or child_stat.st_ino != stat_result.st_ino:
                    raise RuntimeError(f"refusing to prune replaced provider artifact directory: {display_path}")

                def child_guard() -> None:
                    ensure_current()
                    try:
                        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError as exc:
                        raise RuntimeError(f"refusing to prune replaced provider artifact directory: {display_path}") from exc
                    pinned = os.fstat(child_fd)
                    if (
                        not stat.S_ISDIR(current.st_mode)
                        or current.st_dev != pinned.st_dev
                        or current.st_ino != pinned.st_ino
                    ):
                        raise RuntimeError(f"refusing to prune replaced provider artifact directory: {display_path}")

                child_guard()
                _prune_provider_artifact_orphans_at(
                    child_fd,
                    account_dir,
                    root_name,
                    child_parts,
                    file_suffix,
                    expected,
                    guard,
                    child_guard,
                )
                child_guard()
            finally:
                os.close(child_fd)
            continue
        if not name.endswith(file_suffix):
            continue
        if not stat.S_ISREG(stat_result.st_mode):
            if rel_path not in expected:
                raise RuntimeError(f"refusing to prune non-regular provider artifact: {display_path}")
            continue
        if rel_path not in expected:
            ensure_current()
            os.unlink(name, dir_fd=parent_fd)
            _fsync_provider_directory_fd(parent_fd, parent_path, "artifact directory")
            ensure_current()


def journal_row_issues(rows: List[Dict[str, Any]], account: MigrationAccount) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            issues.append(f"journal row {idx} is not an object")
            continue
        raw_status = row.get("status")
        status = raw_status if isinstance(raw_status, str) else ""
        if status not in {"pending", "committed", "failed"}:
            if raw_status in (None, ""):
                shown_status = "<missing>"
            elif isinstance(raw_status, str):
                shown_status = raw_status
            else:
                shown_status = f"non-string {type(raw_status).__name__}"
            issues.append(f"journal row {idx} has invalid status: {shown_status}")
            continue
        identity = _non_empty_json_string(row, "canonical_id") or ""
        target_mailbox = _non_empty_json_string(row, "target_mailbox") or ""
        target_account = _non_empty_json_string(row, "target_account") or ""
        label = identity or f"row {idx}"
        if not identity:
            if row.get("canonical_id") in (None, ""):
                issues.append(f"journal row {idx} missing canonical_id")
            else:
                issues.append(f"journal row {idx} has non-string canonical_id")
        if not target_mailbox:
            if row.get("target_mailbox") in (None, ""):
                issues.append(f"journal {label} missing target_mailbox")
            else:
                issues.append(f"journal {label} has non-string target_mailbox")
        if not target_account and row.get("target_account") not in (None, ""):
            issues.append(f"journal {label} has non-string target_account")
        if target_account != account.target_email:
            issues.append(
                f"journal {label} target_account does not match config target_email "
                f"{account.target_email}: {target_account or '<missing>'}"
            )
    return issues


def _target_mailbox_matches_expected(
    target_mailbox: str,
    expected_target: str,
    *,
    target_provider: str,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> bool:
    if target_mailbox == expected_target:
        return True
    if (target_provider or "").lower() == "gmail":
        expected_key = (
            _gmail_target_system_key(expected_target, target_mailboxes)
            or _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(expected_target.strip().lower(), "")
        )
        target_key = _gmail_target_system_key(target_mailbox, target_mailboxes)
        if expected_key and target_key:
            return expected_key == target_key
    return False


_GENERIC_IMAP_OFFLINE_SPECIAL_USE_TARGETS = {
    "archive",
    "deleted messages",
    "drafts",
    "junk",
    "sent",
}

_GENERIC_IMAP_OFFLINE_TARGET_SYSTEM_KEYS = {
    "all mail": "archive",
    "archive": "archive",
    "deleted messages": "trash",
    "trash": "trash",
    "bin": "trash",
    "drafts": "drafts",
    "inbox": "inbox",
    "junk": "junk",
    "spam": "junk",
    "sent": "sent",
    "sent mail": "sent",
    "sent messages": "sent",
}


def _generic_imap_offline_target_requires_live_special_use(target_mailbox: str, expected_target: str) -> bool:
    expected_key = _GENERIC_IMAP_OFFLINE_TARGET_SYSTEM_KEYS.get(expected_target.strip().lower(), "")
    target_key = _GENERIC_IMAP_OFFLINE_TARGET_SYSTEM_KEYS.get(target_mailbox.strip().lower(), "")
    if target_key:
        return target_key == expected_key and target_mailbox != expected_target
    return bool(
        target_mailbox
        and target_mailbox != expected_target
        and expected_target.strip().lower() in _GENERIC_IMAP_OFFLINE_SPECIAL_USE_TARGETS
    )


def _gmail_offline_target_requires_live_special_use(target_mailbox: str, expected_target: str) -> bool:
    expected_key = _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(expected_target.strip().lower(), "")
    target_key = _gmail_target_system_key(target_mailbox)
    return bool(target_mailbox and target_mailbox != expected_target and expected_key and not target_key)


def committed_journal_target_mailbox_issues(
    rows: List[Dict[str, Any]],
    expected_target_by_id: Dict[str, str],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
    defer_generic_special_use: bool = False,
    defer_gmail_special_use: bool = False,
    defer_unknown_hierarchy_delimiter_ids: Optional[set[str]] = None,
) -> List[str]:
    issues: List[str] = []
    provider = (target_provider or "imap").lower()
    for row in latest_committed_journal_rows(
        rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    ).values():
        identity = str(row.get("canonical_id") or "")
        if not identity:
            continue
        expected_target = expected_target_by_id.get(identity)
        if not expected_target:
            continue
        target_mailbox = str(row.get("target_mailbox") or "")
        if not _target_mailbox_matches_expected(
            target_mailbox,
            expected_target,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        ):
            if defer_unknown_hierarchy_delimiter_ids and identity in defer_unknown_hierarchy_delimiter_ids:
                continue
            if (
                defer_generic_special_use
                and provider in {"imap", "icloud"}
                and _generic_imap_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            if (
                defer_gmail_special_use
                and provider == "gmail"
                and _gmail_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            issues.append(
                f"journal committed identity in wrong target mailbox: {identity} "
                f"expected {expected_target!r} got {target_mailbox!r}"
            )
    return issues


def pending_journal_target_mailbox_issues(
    rows: List[Dict[str, Any]],
    expected_target_by_id: Dict[str, str],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
    defer_generic_special_use: bool = False,
    defer_gmail_special_use: bool = False,
    defer_unknown_hierarchy_delimiter_ids: Optional[set[str]] = None,
) -> List[str]:
    issues: List[str] = []
    provider = (target_provider or "imap").lower()
    for row in latest_journal_rows(rows, target_provider=target_provider).values():
        if row.get("status") != "pending":
            continue
        identity = str(row.get("canonical_id") or "")
        if not identity:
            continue
        expected_target = expected_target_by_id.get(identity)
        if not expected_target:
            continue
        target_mailbox = str(row.get("target_mailbox") or "")
        if not _target_mailbox_matches_expected(
            target_mailbox,
            expected_target,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        ):
            if defer_unknown_hierarchy_delimiter_ids and identity in defer_unknown_hierarchy_delimiter_ids:
                continue
            if (
                defer_generic_special_use
                and provider in {"imap", "icloud"}
                and _generic_imap_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            if (
                defer_gmail_special_use
                and provider == "gmail"
                and _gmail_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            issues.append(
                f"journal pending identity in wrong target mailbox: {identity} "
                f"expected {expected_target!r} got {target_mailbox!r}"
            )
    return issues


def offline_target_mailboxes_for_rows(
    rows: List[Dict[str, Any]],
    *,
    target_provider: str,
) -> Dict[str, str]:
    provider = (target_provider or "imap").lower()

    def offline_default_target(mailbox: str) -> str:
        lower = mailbox.strip().lower()
        if provider == "icloud":
            return {
                "deleted messages": "Trash",
                "trash": "Trash",
                "junk": "Junk",
                "spam": "Junk",
            }.get(lower, mailbox)
        return mailbox

    expected: Dict[str, str] = {}
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        if not identity:
            continue
        desired = str(row.get("primary_mailbox") or "Archive")
        translated = translate_source_mailbox_for_target(
            row,
            desired,
            [],
            target_provider=target_provider,
        )
        expected[identity] = offline_default_target(translated)
    return expected


def offline_hierarchy_delimiter_dependent_ids(rows: List[Dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        if not identity:
            continue
        desired = str(row.get("primary_mailbox") or "Archive")
        source_paths = row.get("source_mailbox_paths")
        if not isinstance(source_paths, dict):
            continue
        raw_segments = source_paths.get(desired)
        if not isinstance(raw_segments, list):
            continue
        segments = [str(segment) for segment in raw_segments if str(segment)]
        if len(segments) > 1:
            ids.add(identity)
    return ids


def offline_journal_target_mailbox_issues(
    journal_rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    *,
    target_provider: str,
) -> List[str]:
    expected = offline_target_mailboxes_for_rows(manifest_rows, target_provider=target_provider)
    hierarchy_delimiter_dependent_ids = offline_hierarchy_delimiter_dependent_ids(manifest_rows)
    issues = committed_journal_target_mailbox_issues(
        journal_rows,
        expected,
        target_provider=target_provider,
        defer_generic_special_use=True,
        defer_gmail_special_use=True,
        defer_unknown_hierarchy_delimiter_ids=hierarchy_delimiter_dependent_ids,
    )
    issues.extend(
        pending_journal_target_mailbox_issues(
            journal_rows,
            expected,
            target_provider=target_provider,
            defer_generic_special_use=True,
            defer_gmail_special_use=True,
            defer_unknown_hierarchy_delimiter_ids=hierarchy_delimiter_dependent_ids,
        )
    )
    return issues


def committed_journal_manifest_content_issues(
    rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[str]:
    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    issues: List[str] = []
    for (identity, target_mailbox), journal_row in latest_committed_journal_rows(
        rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    ).items():
        manifest_row = manifest_by_id.get(identity)
        label = f"{identity} in {target_mailbox or '<missing>'}"
        if manifest_row is None:
            issues.append(f"journal committed identity not in manifest: {identity}")
            continue
        journal_content_sha256 = journal_row.get("content_sha256")
        journal_size = journal_row.get("rfc822_size")
        journal_binding = journal_row.get(CONTENT_BINDING_FIELD)
        if not isinstance(journal_content_sha256, str) or journal_content_sha256 != manifest_row.get("content_sha256"):
            issues.append(f"journal committed content_sha256 does not match manifest: {label}")
        if type(journal_size) is not int or journal_size != manifest_row.get("rfc822_size"):
            issues.append(f"journal committed rfc822_size does not match manifest: {label}")
        if not isinstance(journal_binding, str) or not provider_content_binding_matches(manifest_row, journal_binding):
            issues.append(f"journal committed {CONTENT_BINDING_FIELD} does not match manifest: {label}")
    return issues


def journal_target_endpoint_issues(
    rows: List[Dict[str, Any]],
    *,
    config: ProviderMigrationConfig,
    account: MigrationAccount,
) -> List[str]:
    expected_binding = provider_target_journal_binding(config, account)
    expected_endpoint = expected_binding["target_endpoint"]
    expected_digest = expected_binding["target_endpoint_sha256"]
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            continue
        label = str(row.get("canonical_id") or f"row {idx}")
        target_endpoint = row.get("target_endpoint")
        if not isinstance(target_endpoint, dict):
            issues.append(f"journal {label} target_endpoint missing; rerun provider import with current version")
        elif not _provider_endpoint_state_matches(target_endpoint, expected_endpoint):
            issues.append(
                f"journal {label} target_endpoint does not match config target endpoint: "
                f"{target_endpoint} != {expected_endpoint}"
            )
        if not _provider_endpoint_state_digest_matches(
            target_endpoint,
            row.get("target_endpoint_sha256"),
            expected_digest,
        ):
            issues.append(f"journal {label} target_endpoint_sha256 does not match config target endpoint")
    return issues


def is_valid_gmail_msgid(value: Any) -> bool:
    text = str(value or "")
    if not re.fullmatch(r"\d+", text):
        return False
    try:
        return 0 <= int(text) <= (2**64 - 1)
    except ValueError:
        return False


def invalid_journal_target_gmail_msgid_issues(
    rows: List[Dict[str, Any]],
    *,
    manifest_ids: Optional[set[str]] = None,
) -> List[str]:
    issues: List[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "committed":
            continue
        identity = str(row.get("canonical_id") or "")
        if not identity or (manifest_ids is not None and identity not in manifest_ids):
            continue
        target_gmail_msgid = row.get("target_gmail_msgid")
        if target_gmail_msgid in (None, ""):
            continue
        if not is_valid_gmail_msgid(target_gmail_msgid):
            issues.append(
                f"journal committed Gmail target row has invalid target_gmail_msgid: "
                f"{identity} -> {target_gmail_msgid!r}"
            )
    return issues


def require_valid_import_journal(rows: List[Dict[str, Any]], account: MigrationAccount) -> None:
    issues = journal_row_issues(rows, account)
    if issues:
        raise RuntimeError("invalid import journal: " + "; ".join(issues))


def duplicate_journal_target_gmail_msgid_issues(
    rows: List[Dict[str, Any]],
    *,
    manifest_ids: Optional[set[str]] = None,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[str]:
    by_msgid: Dict[str, set[str]] = {}
    by_identity: Dict[str, set[str]] = {}
    latest_rows = latest_committed_journal_rows(
        rows,
        target_provider="gmail",
        target_mailboxes=target_mailboxes,
    )
    for (identity, _target_mailbox), row in latest_rows.items():
        if manifest_ids is not None and identity not in manifest_ids:
            continue
        target_gmail_msgid = str(row.get("target_gmail_msgid") or "")
        if not target_gmail_msgid:
            continue
        by_msgid.setdefault(target_gmail_msgid, set()).add(identity)
    for row in rows:
        if row.get("status") != "committed":
            continue
        identity = str(row.get("canonical_id") or "")
        if not identity or (manifest_ids is not None and identity not in manifest_ids):
            continue
        target_gmail_msgid = str(row.get("target_gmail_msgid") or "")
        if not target_gmail_msgid:
            continue
        by_identity.setdefault(identity, set()).add(target_gmail_msgid)
    issues: List[str] = []
    for target_gmail_msgid, identities in sorted(by_msgid.items()):
        if len(identities) > 1:
            issues.append(
                f"journal target_gmail_msgid {target_gmail_msgid} is committed to multiple manifest identities: "
                + ", ".join(sorted(identities))
            )
    for identity, target_gmail_msgids in sorted(by_identity.items()):
        if len(target_gmail_msgids) > 1:
            issues.append(
                f"journal manifest identity {identity} is committed to multiple target_gmail_msgid values: "
                + ", ".join(sorted(target_gmail_msgids))
            )
    return issues


def missing_journal_target_gmail_msgid_issues(
    rows: List[Dict[str, Any]],
    *,
    manifest_ids: set[str],
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[str]:
    issues: List[str] = []
    for (identity, target_mailbox), row in latest_committed_journal_rows(
        rows,
        target_provider="gmail",
        target_mailboxes=target_mailboxes,
    ).items():
        if identity not in manifest_ids:
            continue
        if row.get("target_gmail_msgid"):
            continue
        issues.append(
            f"journal committed Gmail target row missing target_gmail_msgid: "
            f"{identity} in {target_mailbox or '<missing>'}"
        )
    return issues


def repair_missing_journal_target_gmail_msgids(
    imap: imaplib.IMAP4,
    account_dir: Path,
    account: MigrationAccount,
    rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    target_mailbox_by_identity: Dict[str, str],
    target_binding: Dict[str, Any],
    expected_content_identities_by_id: Optional[Dict[str, set[Tuple[int, str]]]] = None,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[Dict[str, Any]]:
    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    repaired_rows = list(rows)
    issues: List[str] = []
    for (identity, _target_mailbox_key), journal_row in latest_committed_journal_rows(
        repaired_rows,
        target_provider="gmail",
        target_mailboxes=target_mailboxes,
    ).items():
        if not identity or identity not in manifest_by_id or journal_row.get("target_gmail_msgid"):
            continue
        target_mailbox = str(journal_row.get("target_mailbox") or "")
        expected_target_mailbox = target_mailbox_by_identity.get(identity)
        if expected_target_mailbox and not _target_mailbox_matches_expected(
            target_mailbox,
            expected_target_mailbox,
            target_provider="gmail",
            target_mailboxes=target_mailboxes,
        ):
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and is in wrong target mailbox: "
                f"{identity} expected {expected_target_mailbox!r} got {target_mailbox!r}"
            )
            continue
        search_mailbox = expected_target_mailbox or target_mailbox
        manifest_row = manifest_by_id[identity]
        matches: Dict[str, bytes] = {}
        for num in target_matching_message_nums(
            imap,
            search_mailbox,
            manifest_row,
            create_if_missing=False,
            expected_content_identities=(
                expected_content_identities_by_id.get(identity)
                if expected_content_identities_by_id
                else None
            ),
        ):
            gmail_msgid = _target_gmail_msgid(imap, num)
            if gmail_msgid:
                matches.setdefault(gmail_msgid, num)
        if not matches:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and target message was not found: "
                f"{identity} in {search_mailbox or '<missing>'}"
            )
            continue
        if len(matches) > 1:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and matched multiple target Gmail messages: "
                f"{identity} in {search_mailbox}: " + ", ".join(sorted(matches))
            )
            continue
        target_gmail_msgid = next(iter(matches))
        repaired = _journal_row(
            manifest_row,
            search_mailbox,
            "committed",
            "verified",
            target_binding=target_binding,
            target_gmail_msgid=target_gmail_msgid,
        )
        append_journal(account_dir, account, repaired)
        repaired_rows.append(repaired)
    if issues:
        raise RuntimeError("invalid import journal: " + "; ".join(issues))
    return repaired_rows


def duplicate_journal_target_gmail_msgid_entries(
    rows: List[Dict[str, Any]],
    *,
    manifest_ids: set[str],
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[Dict[str, Any]]:
    by_msgid: Dict[str, set[str]] = {}
    by_identity: Dict[str, set[str]] = {}
    latest_rows = latest_committed_journal_rows(
        rows,
        target_provider="gmail",
        target_mailboxes=target_mailboxes,
    )
    for (identity, _target_mailbox), row in latest_rows.items():
        if identity not in manifest_ids:
            continue
        target_gmail_msgid = str(row.get("target_gmail_msgid") or "")
        if not target_gmail_msgid:
            continue
        by_msgid.setdefault(target_gmail_msgid, set()).add(identity)
    for row in rows:
        if row.get("status") != "committed":
            continue
        identity = str(row.get("canonical_id") or "")
        if identity not in manifest_ids:
            continue
        target_gmail_msgid = str(row.get("target_gmail_msgid") or "")
        if not target_gmail_msgid:
            continue
        by_identity.setdefault(identity, set()).add(target_gmail_msgid)
    entries = [
        {
            "canonical_id": ",".join(sorted(identities)),
            "count": len(identities),
            "source": "journal-target-gmail-msgid",
            "target_gmail_msgid": target_gmail_msgid,
        }
        for target_gmail_msgid, identities in sorted(by_msgid.items())
        if len(identities) > 1
    ]
    entries.extend(
        {
            "canonical_id": identity,
            "count": len(target_gmail_msgids),
            "source": "journal-target-gmail-msgid",
            "target_gmail_msgids": sorted(target_gmail_msgids),
        }
        for identity, target_gmail_msgids in sorted(by_identity.items())
        if len(target_gmail_msgids) > 1
    )
    return entries


def _journal_path(account_dir: Path, account: MigrationAccount) -> Path:
    return account_dir / f"import-{sanitize_for_path(account.target_email)}.journal.jsonl"


def load_import_journal(
    account_dir: Path,
    account: MigrationAccount,
    *,
    repair_trailing: bool = False,
) -> List[Dict[str, Any]]:
    path = _journal_path(account_dir, account)
    rows: List[Dict[str, Any]] = []
    _raise_if_provider_path_symlink(path, "file")
    if not path.exists():
        return rows
    raw = _read_provider_artifact_bytes(path, "file")
    trailing_row_unterminated = bool(raw) and not raw.endswith(b"\n")
    lines = raw.splitlines()
    needs_rewrite = False
    for line_no, raw_line in enumerate(lines, 1):
        if trailing_row_unterminated and line_no == len(lines):
            if repair_trailing:
                logging.warning("[provider-import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise ValueError(f"{path}: journal row {line_no} is not newline-terminated")
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            if repair_trailing and line_no == len(lines):
                logging.warning("[provider-import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            if repair_trailing and line_no == len(lines):
                logging.warning("[provider-import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise
        if not isinstance(row, dict):
            raise ValueError(f"{path}: journal row {line_no} is not an object")
        rows.append(row)
    if needs_rewrite:
        _write_jsonl(path, rows)
    return rows


def append_journal(account_dir: Path, account: MigrationAccount, row: Dict[str, Any]) -> None:
    path = _journal_path(account_dir, account)
    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_provider_parent_dir(path, "file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = -1
    try:
        try:
            fd = os.open(name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked provider file: {path}") from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(f"refusing to use non-regular provider file: {path}") from exc
            raise
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise RuntimeError(f"refusing to use non-regular provider file: {path}")
        if getattr(stat_result, "st_nlink", 1) > 1:
            raise RuntimeError(f"refusing to use hard-linked provider file: {path}")
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
        file_obj = os.fdopen(fd, "a", encoding="utf-8")
        fd = -1
        with file_obj as f:
            os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
            json.dump(row, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
        try:
            visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise RuntimeError(f"provider import journal changed during append: {path}") from exc
        if (
            visible_stat.st_dev != stat_result.st_dev
            or visible_stat.st_ino != stat_result.st_ino
            or stat.S_ISLNK(visible_stat.st_mode)
            or not stat.S_ISREG(visible_stat.st_mode)
            or getattr(visible_stat, "st_nlink", 1) > 1
        ):
            raise RuntimeError(f"provider import journal changed during append: {path}")
        _fsync_provider_directory_fd(parent_fd, parent_path, "file")
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def _manifest_path(account_dir: Path, row: Dict[str, Any], key: str) -> Path:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: missing {key}")
    rel_path = Path(value)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: unsafe {key}: {value!r}")
    if key == "eml_path" and (
        len(rel_path.parts) < 2
        or rel_path.parts[0] != "messages"
        or rel_path.suffix != ".eml"
    ):
        raise RuntimeError(
            f"manifest row {row.get('canonical_id') or '<unknown>'}: "
            f"invalid eml_path layout, expected messages/*.eml: {value!r}"
        )
    if key == "metadata_path" and (
        len(rel_path.parts) < 2
        or rel_path.parts[0] != "metadata"
        or rel_path.suffix != ".json"
    ):
        raise RuntimeError(
            f"manifest row {row.get('canonical_id') or '<unknown>'}: "
            f"invalid metadata_path layout, expected metadata/*.json: {value!r}"
        )
    root = account_dir.resolve()
    candidate = account_dir / rel_path
    current = account_dir
    for part in rel_path.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: symlinked {key}: {value!r}")
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: unsafe {key}: {value!r}") from exc
    return candidate


def _finalize_export_record(record: Dict[str, Any], folder_map: Dict[str, str]) -> None:
    source_mailbox_attributes = record.get("source_mailbox_attributes")

    def source_mailbox_sort_key(value: object) -> Tuple[int, str]:
        name = str(value)
        attrs = source_mailbox_attributes.get(name, []) if isinstance(source_mailbox_attributes, dict) else []
        attr_lowers = {str(attr).lower() for attr in attrs if str(attr)}
        return (1 if "\\flagged" in attr_lowers else 0, name)

    record["source_mailboxes"] = sorted(
        (str(value) for value in record.get("source_mailboxes", [])),
        key=source_mailbox_sort_key,
    )
    record["gmail_labels"] = sorted(str(value) for value in record.get("gmail_labels", []))
    if isinstance(source_mailbox_attributes, dict):
        record["source_mailbox_attributes"] = normalize_provider_mailbox_attributes(source_mailbox_attributes)
    source_attributes = [
        attr
        for attrs in record.get("source_mailbox_attributes", {}).values()
        for attr in attrs
    ]
    record["primary_mailbox"] = resolve_primary_mailbox(
        list(record["source_mailboxes"]) + source_attributes,
        record["gmail_labels"],
        folder_map,
        source_provider=str(record.get("source_provider") or "imap"),
    )


def persist_export_records(account_dir: Path, records: Dict[str, Dict[str, Any]], folder_map: Dict[str, str]) -> None:
    for record in records.values():
        _finalize_export_record(record, folder_map)
        record[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(record)
        _atomic_json(account_dir / str(record["metadata_path"]), record)
    _write_jsonl(account_dir / "manifest.jsonl", sorted(records.values(), key=lambda row: str(row["canonical_id"])))


def _existing_record_for_rescan(row: Dict[str, Any]) -> Dict[str, Any]:
    record = dict(row)
    record["source_mailboxes"] = []
    record["source_mailbox_attributes"] = {}
    record["source_mailbox_delimiters"] = {}
    record["source_mailbox_paths"] = {}
    record["gmail_labels"] = []
    record["uid_by_mailbox"] = {}
    record["uidvalidity_by_mailbox"] = {}
    record["primary_mailbox"] = ""
    return record


def _refresh_export_delivery_metadata(record: Dict[str, Any], parsed: Dict[str, Any]) -> None:
    record["flags"] = parsed.get("flags") or ""
    record["internaldate"] = parsed.get("internaldate") or ""


def _provider_export_flag_set(flags: object) -> set[str]:
    return {
        str(token).upper()
        for token in str(flags or "").split()
        if str(token).strip() and str(token).upper() != "\\RECENT"
    }


_ProviderVirtualDeliveryKey = Tuple[Tuple[str, ...], str]


def _provider_virtual_delivery_key(parsed: Dict[str, Any]) -> _ProviderVirtualDeliveryKey:
    return (
        tuple(sorted(_provider_export_flag_set(parsed.get("flags")))),
        _normalized_provider_internaldate(parsed.get("internaldate")),
    )


def _uncovered_provider_virtual_items(
    pending_items: List[Any],
    *,
    remaining_ordinary: int,
    ordinary_delivery_remaining: Dict[_ProviderVirtualDeliveryKey, int],
    delivery_key: Callable[[Any], _ProviderVirtualDeliveryKey],
) -> Tuple[List[Any], int]:
    if remaining_ordinary <= 0 or not pending_items:
        return pending_items, 0
    kept: List[Any] = []
    consumed = 0
    for item in pending_items:
        key = delivery_key(item)
        key_remaining = ordinary_delivery_remaining.get(key, 0)
        if consumed < remaining_ordinary and key_remaining > 0:
            ordinary_delivery_remaining[key] = key_remaining - 1
            consumed += 1
        else:
            kept.append(item)
    return kept, consumed


def _merge_provider_export_flag_strings(existing_flags: object, additional_flags: object) -> str:
    merged: List[str] = []
    seen: set[str] = set()
    for flags in (existing_flags, additional_flags):
        for token in str(flags or "").split():
            if not token or token.upper() == "\\RECENT":
                continue
            canonical = token.upper() if token.startswith("\\") else token
            if canonical in seen:
                continue
            seen.add(canonical)
            merged.append(token)
    return " ".join(merged)


def _provider_export_gmail_label_set(labels: object) -> set[str]:
    if not isinstance(labels, list):
        return set()
    return {_gmail_label_key(str(label)) for label in labels if str(label).strip()}


def provider_export_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    out_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
) -> None:
    _raise_if_provider_path_symlink(out_root, "export root")
    account_dir = account_export_dir(out_root, account)
    _raise_if_provider_path_symlink(account_dir, "account directory")
    _raise_if_provider_path_symlink(account_dir / "export-state.json", "file")
    if account_dir.exists():
        mixed_layout_issues = provider_mixed_legacy_layout_issues(account_dir)
        if mixed_layout_issues:
            raise RuntimeError("; ".join(mixed_layout_issues))
    messages: Dict[str, Dict[str, Any]] = {}
    manifest_path = account_dir / "manifest.jsonl"
    preserve_complete_state_until_ready = False
    trusted_payload_identities: set[str] = set()
    active_identities: set[str] = set()
    previous_rows_by_identity: Dict[str, Dict[str, Any]] = {}
    previous_uidvalidities_by_mailbox: Dict[str, set[str]] = {}
    ordinary_content_remaining_for_all: Dict[Tuple[int, str], int] = {}
    ordinary_delivery_remaining_for_all: Dict[Tuple[int, str], Dict[_ProviderVirtualDeliveryKey, int]] = {}
    mergeable_provider_records_by_content: Dict[Tuple[int, str], List[Tuple[str, str]]] = {}
    scanned_uidvalidity_by_mailbox: Dict[str, str] = {}
    exported_delivery_by_mailbox_uid: Dict[str, Dict[int, Dict[str, Any]]] = {}
    if manifest_path.exists():
        existing_rows = load_manifest(account_dir)
        require_unique_manifest_identities(existing_rows)
        require_manifest_accounts(existing_rows, account)
        require_manifest_source_provider(existing_rows, config.source.provider)
        for row in existing_rows:
            _manifest_path(account_dir, row, "eml_path")
            _manifest_path(account_dir, row, "metadata_path")
        messages = {
            str(row["canonical_id"]): _existing_record_for_rescan(row)
            for row in existing_rows
            if row.get("canonical_id")
        }
        previous_rows_by_identity = {
            str(row["canonical_id"]): dict(row)
            for row in existing_rows
            if row.get("canonical_id")
        }
        try:
            existing_state = json.loads(_read_provider_private_file(account_dir / "export-state.json"))
        except Exception as exc:
            raise RuntimeError(f"export-state missing or invalid for existing manifest: {exc}") from exc
        if not isinstance(existing_state, dict):
            raise RuntimeError("export-state is invalid for existing manifest")
        state_contract_issues = provider_export_state_contract_issues(
            existing_state,
            account=account,
            source_provider=config.source.provider,
            target_provider=config.target.provider,
            source_endpoint=config.source,
            target_endpoint=config.target,
        )
        if state_contract_issues:
            raise RuntimeError("; ".join(state_contract_issues))
        for row in existing_rows:
            uidvalidities = row.get("uidvalidity_by_mailbox")
            if not isinstance(uidvalidities, dict):
                continue
            for mailbox_name, value in uidvalidities.items():
                if value:
                    previous_uidvalidities_by_mailbox.setdefault(str(mailbox_name), set()).add(str(value))
        state_uidvalidities = existing_state.get("scanned_uidvalidity_by_mailbox")
        if isinstance(state_uidvalidities, dict):
            for mailbox_name, value in state_uidvalidities.items():
                if value:
                    previous_uidvalidities_by_mailbox.setdefault(str(mailbox_name), set()).add(str(value))
        if isinstance(existing_state, dict) and existing_state.get("complete") is True:
            state_issues = provider_export_state_issues(
                account_dir,
                account=account,
                manifest_rows=existing_rows,
                source_provider=config.source.provider,
                target_provider=config.target.provider,
                source_endpoint=config.source,
                target_endpoint=config.target,
            )
            if state_issues:
                raise RuntimeError("; ".join(state_issues))
            preserve_complete_state_until_ready = True
            trusted_payload_identities.update(messages)

    def write_in_progress_state() -> None:
        _atomic_json(
            account_dir / "export-state.json",
            {
                "source_account": account.source_email,
                "target_account": account.target_email,
                "source_provider": config.source.provider,
                "target_provider": config.target.provider,
                "source_endpoint": provider_account_endpoint_state(config.source, account, role="source"),
                "source_endpoint_sha256": provider_account_endpoint_state_digest(config.source, account, role="source"),
                "target_endpoint": provider_account_endpoint_state(config.target, account, role="target"),
                "target_endpoint_sha256": provider_account_endpoint_state_digest(config.target, account, role="target"),
                "gmail_full_visibility_verified": gmail_full_visibility_attested(config.source, account)
                if config.source.provider == "gmail"
                else None,
                "complete": False,
                "started_at": _utc_now(),
            },
        )

    if not preserve_complete_state_until_ready:
        write_in_progress_state()
    limiter = limiter or RateLimiter(config.limits.throttle.max_bytes_per_second)
    scope_gmail_source_identity = provider_account_merge_enabled(config)

    def update_membership(identity: str, mailbox: MailboxInfo, uid: int, uidvalidity: str, parsed: Dict[str, Any]) -> None:
        record = messages[identity]
        record.setdefault("source_mailboxes", [])
        record.setdefault("source_mailbox_attributes", {})
        record.setdefault("source_mailbox_delimiters", {})
        record.setdefault("source_mailbox_paths", {})
        record.setdefault("gmail_labels", [])
        record.setdefault("uid_by_mailbox", {})
        record.setdefault("uidvalidity_by_mailbox", {})
        _append_unique(record["source_mailboxes"], mailbox.name)
        record["source_mailbox_attributes"][mailbox.name] = list(mailbox.attributes)
        record["source_mailbox_delimiters"][mailbox.name] = mailbox.delimiter
        record["source_mailbox_paths"][mailbox.name] = mailbox_path_segments(mailbox.name, mailbox.delimiter)
        if use_gmail_metadata:
            for label in parsed.get("gmail_labels") or []:
                _append_unique(record["gmail_labels"], str(label))
        record["uid_by_mailbox"][mailbox.name] = int(uid)
        record["uidvalidity_by_mailbox"][mailbox.name] = uidvalidity
        active_identities.add(identity)

    def active_export_records() -> Dict[str, Dict[str, Any]]:
        return {
            identity: messages[identity]
            for identity in sorted(active_identities)
            if identity in messages
        }

    def remember_provider_mergeable_record(identity: str, content_identity: Tuple[int, str]) -> None:
        record = messages.get(identity)
        if not record:
            return
        entries = mergeable_provider_records_by_content.setdefault(content_identity, [])
        if any(existing_identity == identity for existing_identity, _internaldate in entries):
            return
        entries.append((identity, str(record.get("internaldate") or "")))

    def merge_covered_provider_flagged_flags(
        content_identity: Tuple[int, str],
        flags: str,
        internaldate: str,
        mailbox: MailboxInfo,
        uid: int,
        uidvalidity: str,
        parsed: Dict[str, Any],
    ) -> bool:
        flagged_internaldate = _normalized_provider_internaldate(internaldate)
        if not flagged_internaldate:
            return False
        same_date_identities = [
            identity
            for identity, candidate_internaldate in mergeable_provider_records_by_content.get(content_identity, [])
            if _normalized_provider_internaldate(candidate_internaldate) == flagged_internaldate
        ]
        if len(same_date_identities) != 1:
            return False
        target_identity = same_date_identities[0]
        record = messages[target_identity]
        merged_flags = _merge_provider_export_flag_strings(record.get("flags"), flags)
        if merged_flags != str(record.get("flags") or ""):
            record["flags"] = merged_flags
        update_membership(target_identity, mailbox, uid, uidvalidity, parsed)
        persist_export_records(account_dir, active_export_records(), config.migration.folder_map)
        previous_rows_by_identity[target_identity] = dict(messages[target_identity])
        trusted_payload_identities.add(target_identity)
        return True

    def record_export_delivery_snapshot(mailbox_name: str, uid: int, parsed: Dict[str, Any]) -> None:
        exported_delivery_by_mailbox_uid.setdefault(mailbox_name, {})[int(uid)] = {
            "flags": parsed.get("flags") or "",
            "gmail_labels": list(parsed.get("gmail_labels") or []),
        }

    def verify_export_delivery_stable(
        imap: imaplib.IMAP4,
        mailbox_name: str,
        uids: List[int],
        *,
        gmail_extensions: bool,
    ) -> None:
        expected_by_uid = exported_delivery_by_mailbox_uid.get(mailbox_name, {})
        if sorted(expected_by_uid) != [int(uid) for uid in uids]:
            raise RuntimeError(f"internal delivery snapshot mismatch during export of {mailbox_name}")
        for uid in uids:
            status, data = imap.uid(
                "fetch",
                str(uid),
                fetch_items(include_body=False, gmail_extensions=gmail_extensions),
            )
            if status != "OK":
                raise RuntimeError(f"failed final metadata fetch in {mailbox_name} for UID {uid}: {data}")
            parsed = parse_provider_fetch_response(data or [], expected_uid=int(uid))
            expected = expected_by_uid[int(uid)]
            if _provider_export_flag_set(parsed.get("flags")) != _provider_export_flag_set(expected.get("flags")):
                raise RuntimeError(f"FLAGS changed during export of {mailbox_name} for UID {uid}")
            if (
                gmail_extensions
                and _provider_export_gmail_label_set(parsed.get("gmail_labels"))
                != _provider_export_gmail_label_set(expected.get("gmail_labels"))
            ):
                raise RuntimeError(f"Gmail labels changed during export of {mailbox_name} for UID {uid}")

    def persist_fetched_message(
        identity: str,
        sha256: str,
        message_id: str,
        parsed: Dict[str, Any],
        msg_bytes: bytes,
        mailbox: MailboxInfo,
        uid: int,
        uidvalidity: str,
    ) -> None:
        safe_id = _safe_identity(identity)
        if identity not in messages:
            eml_rel = f"messages/{safe_id}.eml"
            meta_rel = f"metadata/{safe_id}.json"
            _atomic_bytes(account_dir / eml_rel, msg_bytes)
            messages[identity] = {
                "canonical_id": identity,
                "source_provider": config.source.provider,
                "source_account": account.source_email,
                "target_account": account.target_email,
                "source_mailboxes": [],
                "source_mailbox_attributes": {},
                "primary_mailbox": "",
                "gmail_msgid": (parsed.get("gmail_msgid") or "") if use_gmail_metadata else "",
                "gmail_thrid": (parsed.get("gmail_thrid") or "") if use_gmail_metadata else "",
                "gmail_labels": [],
                "message_id_header": message_id,
                "content_sha256": sha256,
                "rfc822_size": int(parsed.get("rfc822_size") or len(msg_bytes)),
                "uid_by_mailbox": {},
                "uidvalidity_by_mailbox": {},
                "flags": parsed.get("flags") or "",
                "internaldate": parsed.get("internaldate") or "",
                "exported_at": _utc_now(),
                "eml_path": eml_rel,
                "metadata_path": meta_rel,
            }
        else:
            record = messages[identity]
            eml_rel = str(record.get("eml_path") or f"messages/{safe_id}.eml")
            meta_rel = str(record.get("metadata_path") or f"metadata/{safe_id}.json")
            record["eml_path"] = eml_rel
            record["metadata_path"] = meta_rel
            eml_path = _manifest_path(account_dir, record, "eml_path")
            write_payload = not eml_path.exists()
            if not write_payload:
                try:
                    existing_payload = _read_provider_artifact_bytes(eml_path, "provider message artifact")
                    require_manifest_payload_matches(
                        previous_rows_by_identity.get(identity, record),
                        existing_payload,
                    )
                except Exception as exc:
                    if _is_provider_artifact_safety_error(exc):
                        raise
                    logging.warning(
                        "[provider-export] %s: replacing invalid existing payload for %s: %s",
                        account.source_email,
                        identity,
                        exc,
                    )
                    write_payload = True
                else:
                    write_payload = existing_payload != msg_bytes
            if write_payload:
                _atomic_bytes(eml_path, msg_bytes)
            record.setdefault("source_provider", config.source.provider)
            record.setdefault("source_account", account.source_email)
            record["target_account"] = account.target_email
            record.setdefault("gmail_msgid", parsed.get("gmail_msgid") or "")
            record.setdefault("gmail_thrid", parsed.get("gmail_thrid") or "")
            record["message_id_header"] = message_id
            record["content_sha256"] = sha256
            record["rfc822_size"] = int(parsed.get("rfc822_size") or len(msg_bytes))
            _refresh_export_delivery_metadata(record, parsed)
            record.setdefault("exported_at", _utc_now())
        trusted_payload_identities.add(identity)
        update_membership(identity, mailbox, uid, uidvalidity, parsed)
        persist_export_records(account_dir, active_export_records(), config.migration.folder_map)
        previous_rows_by_identity[identity] = dict(messages[identity])

    with imap_connection(config.source, account, role="source") as imap:
        capabilities = get_capabilities(imap)
        use_gmail_metadata = config.source.provider == "gmail"
        gmail_extensions = use_gmail_metadata and "X-GM-EXT-1" in capabilities
        mailboxes = list_mailboxes(imap)
        _atomic_json(
            account_dir / "source-summary.json",
            {
                "source_account": account.source_email,
                "source_provider": config.source.provider,
                "capabilities": capabilities,
                "mailboxes": [m.__dict__ for m in mailboxes],
                "exported_at": _utc_now(),
            },
        )
        if config.source.provider == "gmail":
            gmail_issues = gmail_source_readiness_issues(capabilities, mailboxes)
            gmail_issues.extend(gmail_all_mail_select_issues(imap, mailboxes, role="source"))
            gmail_issues.extend(gmail_account_decommission_issues(config.source, account))
            if gmail_issues:
                raise RuntimeError(f"Gmail source is not export-ready for {account.source_email}: {'; '.join(gmail_issues)}")
        if preserve_complete_state_until_ready:
            write_in_progress_state()
        provider_key = config.source.provider.lower()
        for mailbox in _source_mailbox_scan_order(provider_key, mailboxes):
            if is_noselect(mailbox):
                logging.info("[provider-export] %s: skipping non-selectable mailbox %s", account.source_email, mailbox.name)
                continue
            if should_skip_source_mailbox(config.source.provider, mailbox, mailboxes):
                logging.info("[provider-export] %s: skipping virtual source mailbox %s", account.source_email, mailbox.name)
                continue
            _raise_if_stopped(stop_event, f"provider export {account.source_email}")
            uids, uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox.name)
            scanned_uidvalidity_by_mailbox[mailbox.name] = uidvalidity
            previous_uidvalidities = previous_uidvalidities_by_mailbox.get(mailbox.name, set())
            if previous_uidvalidities and uidvalidity not in previous_uidvalidities:
                raise RuntimeError(
                    f"UIDVALIDITY changed since previous export for {mailbox.name}: "
                    f"previous={sorted(previous_uidvalidities)} current={uidvalidity}; "
                    "start a new export directory to avoid duplicate physical identities"
                )
            logging.info("[provider-export] %s: %s -> %d messages", account.source_email, mailbox.name, len(uids))
            pending_all_messages_by_content: Dict[
                Tuple[int, str],
                List[Tuple[str, str, str, Dict[str, Any], bytes, MailboxInfo, int, str]],
            ] = {}
            for uid in uids:
                _raise_if_stopped(stop_event, f"provider export {account.source_email}")
                status, meta_data = imap.uid(
                    "fetch",
                    str(uid),
                    fetch_items(include_body=False, gmail_extensions=gmail_extensions),
                )
                if status != "OK":
                    raise RuntimeError(f"metadata fetch failed in {mailbox.name} for UID {uid}: {meta_data}")
                pre_parsed = parse_provider_fetch_response(meta_data or [], expected_uid=int(uid))
                identity_hint = (
                    gmail_canonical_identity(
                        pre_parsed.get("gmail_msgid"),
                        source_account=account.source_email,
                        scope_source=scope_gmail_source_identity,
                    )
                    if use_gmail_metadata and pre_parsed.get("gmail_msgid")
                    else ""
                )
                if identity_hint and identity_hint in messages and identity_hint in trusted_payload_identities:
                    try:
                        existing_eml_path = _manifest_path(account_dir, messages[identity_hint], "eml_path")
                    except Exception:
                        logging.warning("[provider-export] %s: existing manifest row for %s has invalid eml_path; refetching body", account.source_email, identity_hint)
                    else:
                        if existing_eml_path.exists():
                            try:
                                require_manifest_payload_matches(
                                    previous_rows_by_identity.get(identity_hint, messages[identity_hint]),
                                    _read_provider_artifact_bytes(existing_eml_path, "provider message artifact"),
                                )
                            except Exception as exc:
                                if _is_provider_artifact_safety_error(exc):
                                    raise
                                logging.warning(
                                    "[provider-export] %s: existing payload for %s is invalid; refetching body: %s",
                                    account.source_email,
                                    identity_hint,
                                    exc,
                                )
                            else:
                                _refresh_export_delivery_metadata(messages[identity_hint], pre_parsed)
                                update_membership(identity_hint, mailbox, uid, uidvalidity, pre_parsed)
                                record_export_delivery_snapshot(mailbox.name, int(uid), pre_parsed)
                                persist_export_records(account_dir, active_export_records(), config.migration.folder_map)
                                previous_rows_by_identity[identity_hint] = dict(messages[identity_hint])
                                continue
                _provider_throttle_wait(
                    limiter,
                    int(pre_parsed.get("rfc822_size") or 0),
                    stop_event=stop_event,
                    label=f"provider export {account.source_email}",
                )
                status, data = imap.uid(
                    "fetch",
                    str(uid),
                    fetch_items(include_body=True, gmail_extensions=gmail_extensions),
                )
                if status != "OK":
                    raise RuntimeError(f"fetch failed in {mailbox.name} for UID {uid}: {data}")
                parsed = parse_provider_fetch_response(data or [], expected_uid=int(uid))
                for key, value in pre_parsed.items():
                    if key != "message_bytes" and not parsed.get(key):
                        parsed[key] = value
                record_export_delivery_snapshot(mailbox.name, int(uid), parsed)
                if config.source.provider == "gmail" and not parsed.get("gmail_msgid"):
                    raise RuntimeError(
                        f"Gmail source fetch for {account.source_email} UID {uid} in {mailbox.name} "
                        "did not return X-GM-MSGID"
                    )
                msg_bytes = parsed.get("message_bytes")
                if not isinstance(msg_bytes, bytes):
                    raise RuntimeError(f"body fetch returned no message bytes in {mailbox.name} for UID {uid}")
                identity, sha256, message_id = canonical_identity(
                    parsed,
                    msg_bytes,
                    source_account=account.source_email,
                    mailbox=mailbox.name,
                    uidvalidity=uidvalidity,
                    uid=uid,
                    collapse_fallback=config.source.provider == "gmail",
                    use_gmail_msgid=use_gmail_metadata,
                    scope_gmail_source=scope_gmail_source_identity,
                )
                size = int(parsed.get("rfc822_size") or len(msg_bytes))
                content_identity = (size, sha256)
                non_gmail_all_source = _is_non_gmail_all_mailbox(provider_key, mailbox)
                non_gmail_flagged_source = _is_non_gmail_flagged_mailbox(provider_key, mailbox)
                if non_gmail_all_source:
                    remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                    if remaining_ordinary > 0:
                        pending_all_messages_by_content.setdefault(content_identity, []).append(
                            (identity, sha256, message_id, parsed, msg_bytes, mailbox, uid, uidvalidity)
                        )
                        continue
                if non_gmail_flagged_source and merge_covered_provider_flagged_flags(
                    content_identity,
                    str(parsed.get("flags") or ""),
                    str(parsed.get("internaldate") or ""),
                    mailbox,
                    uid,
                    uidvalidity,
                    parsed,
                ):
                    continue
                persist_fetched_message(identity, sha256, message_id, parsed, msg_bytes, mailbox, uid, uidvalidity)
                if provider_key != "gmail" and not non_gmail_all_source and not non_gmail_flagged_source:
                    ordinary_content_remaining_for_all[content_identity] = (
                        ordinary_content_remaining_for_all.get(content_identity, 0) + 1
                    )
                    delivery_key = _provider_virtual_delivery_key(parsed)
                    delivery_remaining = ordinary_delivery_remaining_for_all.setdefault(content_identity, {})
                    delivery_remaining[delivery_key] = delivery_remaining.get(delivery_key, 0) + 1
                if not non_gmail_flagged_source:
                    remember_provider_mergeable_record(identity, content_identity)
            for content_identity, pending_messages in pending_all_messages_by_content.items():
                remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                pending_messages, consumed_ordinary = _uncovered_provider_virtual_items(
                    pending_messages,
                    remaining_ordinary=remaining_ordinary,
                    ordinary_delivery_remaining=ordinary_delivery_remaining_for_all.get(content_identity, {}),
                    delivery_key=lambda item: _provider_virtual_delivery_key(item[3]),
                )
                ordinary_content_remaining_for_all[content_identity] = remaining_ordinary - consumed_ordinary
                if not pending_messages:
                    continue
                for (
                    identity,
                    sha256,
                    message_id,
                    parsed,
                    msg_bytes,
                    pending_mailbox,
                    pending_uid,
                    pending_uidvalidity,
                ) in pending_messages:
                    persist_fetched_message(
                        identity,
                        sha256,
                        message_id,
                        parsed,
                        msg_bytes,
                        pending_mailbox,
                        pending_uid,
                        pending_uidvalidity,
                    )
                    remember_provider_mergeable_record(identity, content_identity)
            status, response = select_mailbox(imap, mailbox.name, readonly=True)
            if status != "OK":
                raise RuntimeError(f"failed to reselect mailbox {mailbox.name} after export: {response}")
            final_uidvalidity = require_selected_uidvalidity(imap, mailbox.name)
            if final_uidvalidity != uidvalidity:
                raise RuntimeError(
                    f"UIDVALIDITY changed during export of {mailbox.name}: "
                    f"{uidvalidity} -> {final_uidvalidity}; restart this mailbox"
                )
            status, final_data = imap.uid("search", "ALL")
            if status != "OK":
                raise RuntimeError(f"failed final UID search in {mailbox.name}: {final_data}")
            final_uids = _parse_uid_search_data(final_data)
            if final_uids != uids:
                raise RuntimeError(
                    f"UID set changed during export of {mailbox.name}: "
                    f"initial={len(uids)} final={len(final_uids)}; rerun export after mailbox quiesces"
                )
            verify_export_delivery_stable(
                imap,
                mailbox.name,
                uids,
                gmail_extensions=gmail_extensions,
            )

    final_records = active_export_records()
    persist_export_records(account_dir, final_records, config.migration.folder_map)
    _prune_provider_artifact_orphans(account_dir, list(final_records.values()))
    final_manifest_rows = load_manifest(account_dir)
    _atomic_json(
        account_dir / "export-state.json",
        {
            "source_account": account.source_email,
            "target_account": account.target_email,
            "source_provider": config.source.provider,
            "target_provider": config.target.provider,
            "source_endpoint": provider_account_endpoint_state(config.source, account, role="source"),
            "source_endpoint_sha256": provider_account_endpoint_state_digest(config.source, account, role="source"),
            "target_endpoint": provider_account_endpoint_state(config.target, account, role="target"),
            "target_endpoint_sha256": provider_account_endpoint_state_digest(config.target, account, role="target"),
            "gmail_full_visibility_verified": gmail_full_visibility_attested(config.source, account)
            if config.source.provider == "gmail"
            else None,
            "complete": True,
            "canonical_messages": len(final_manifest_rows),
            "manifest_sha256": provider_manifest_digest(final_manifest_rows),
            "scanned_uidvalidity_by_mailbox": scanned_uidvalidity_by_mailbox,
            "completed_at": _utc_now(),
        },
    )
    logging.info("[provider-export] %s: completed with %d canonical messages", account.source_email, len(final_records))


def provider_export_all(
    config: ProviderMigrationConfig,
    out_root: Path,
    *,
    max_workers: int,
    ignore_errors: bool,
    stop_event: Optional[object] = None,
) -> None:
    max_workers = _require_max_workers(max_workers)
    root_fd, root_path = _open_or_create_provider_dir(out_root, "export root")
    try:
        _raise_if_provider_parent_replaced(root_path, root_fd, "export root")
    finally:
        os.close(root_fd)
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider export {acc.source_email}")
        with_retry(
            lambda: provider_export_account(config, acc, out_root, stop_event=stop_event, limiter=limiter),
            attempts=config.limits.retry_max_attempts,
            label=f"provider export {acc.source_email}",
            stop_event=stop_event,
        )

    parallel_process_accounts(
        "provider-export",
        worker,
        config.accounts,
        max_workers,
        stop_on_error=not ignore_errors,
        stop_event=stop_event,
    )


def _target_mailbox_lookup_key(name: str, target_provider: str = "imap") -> str:
    provider = (target_provider or "imap").lower()
    stripped = str(name)
    if provider == "gmail":
        return stripped.lower()
    if stripped.upper() == "INBOX":
        return "INBOX"
    return stripped


def _target_mailboxes_by_name(mailboxes: List[MailboxInfo], *, target_provider: str = "imap") -> Dict[str, MailboxInfo]:
    return {_target_mailbox_lookup_key(m.name, target_provider): m for m in mailboxes}


def resolve_target_mailbox(desired: str, mailboxes: List[MailboxInfo], *, target_provider: str = "imap") -> str:
    provider = (target_provider or "imap").lower()
    by_name = _target_mailboxes_by_name(mailboxes, target_provider=provider)
    desired_name = str(desired)
    desired_key = _target_mailbox_lookup_key(desired, provider)
    special_key_by_name = {
        "Sent": "sent",
        "Drafts": "drafts",
        "Deleted Messages": "deleted messages",
        "Trash": "trash",
        "Junk": "junk",
        "Spam": "spam",
        "Archive": "archive",
        "Important": "important",
        "Starred": "starred",
        "Flagged": "starred",
    }
    special_key = special_key_by_name.get(desired_name)
    if desired_key in by_name and not special_key:
        return by_name[desired_key].name
    attr_map = {
        "sent": ("\\Sent",),
        "drafts": ("\\Drafts",),
        "deleted messages": ("\\Trash",),
        "trash": ("\\Trash",),
        "junk": ("\\Junk",),
        "spam": ("\\Junk",),
        "important": ("\\Important",),
        "starred": ("\\Flagged",),
    }
    if provider == "gmail":
        attr_map["archive"] = ("\\All", "\\Archive")
    else:
        attr_map["archive"] = ("\\Archive",)
    attrs = attr_map.get(special_key or "")
    if attrs:
        for mailbox in mailboxes:
            if any(a.lower() in {attr.lower() for attr in attrs} for a in mailbox.attributes):
                return mailbox.name
    gmail_candidates = {
        "sent": ["[Gmail]/Sent Mail", "[GoogleMail]/Sent Mail", "Sent", "Sent Messages"],
        "drafts": ["[Gmail]/Drafts", "[GoogleMail]/Drafts", "Drafts"],
        "deleted messages": ["[Gmail]/Trash", "[GoogleMail]/Trash", "Trash", "Deleted Messages"],
        "trash": ["[Gmail]/Trash", "[GoogleMail]/Trash", "Trash", "Deleted Messages"],
        "junk": ["[Gmail]/Spam", "[GoogleMail]/Spam", "Junk", "Spam"],
        "spam": ["[Gmail]/Spam", "[GoogleMail]/Spam", "Spam", "Junk"],
        "archive": ["[Gmail]/All Mail", "[GoogleMail]/All Mail", "All Mail", "Archive"],
        "important": ["[Gmail]/Important", "[GoogleMail]/Important", "Important"],
        "starred": ["[Gmail]/Starred", "[GoogleMail]/Starred", "Starred"],
    }
    generic_candidates = {
        "sent": ["Sent", "Sent Messages"],
        "drafts": ["Drafts"],
        "deleted messages": ["Deleted Messages", "Trash"],
        "trash": ["Trash", "Deleted Messages"],
        "junk": ["Junk", "Spam"],
        "spam": ["Spam", "Junk"],
        "archive": ["Archive"],
        "important": ["Important"],
        "starred": ["Starred"],
    }
    candidates = {
        **(gmail_candidates if provider == "gmail" else generic_candidates),
    }.get(special_key or "", [desired])
    for candidate in candidates:
        candidate_key = _target_mailbox_lookup_key(candidate, provider)
        if candidate_key in by_name:
            return by_name[candidate_key].name
    return desired


def ensure_mailbox(imap: imaplib.IMAP4, mailbox: str) -> None:
    status, _ = select_mailbox(imap, mailbox)
    if status == "OK":
        subscribe_mailbox(imap, mailbox)
        return
    try:
        create_mailbox(imap, mailbox)
    except Exception as exc:
        logging.warning("[provider-import] failed to create target mailbox %s: %s", mailbox, exc)
    status, _ = select_mailbox(imap, mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select or create target mailbox {mailbox}")
    subscribe_mailbox(imap, mailbox)


def _flags_for_append(flags: str) -> str:
    portable = {"\\ANSWERED", "\\FLAGGED", "\\DELETED", "\\SEEN", "\\DRAFT"}
    tokens = [tok for tok in flags.split() if tok.strip()]
    filtered = [tok for tok in tokens if tok.strip().upper() in portable]
    return f"({' '.join(filtered)})" if filtered else ""


def target_permanent_flags(imap: imaplib.IMAP4) -> Optional[set[str]]:
    response = getattr(imap, "response", None)
    if not callable(response):
        return None
    try:
        _status, data = response("PERMANENTFLAGS")
    except Exception:
        return None
    values: List[str] = []
    for part in data or []:
        if part is None:
            continue
        if isinstance(part, (bytes, bytearray)):
            values.append(bytes(part).decode("ascii", errors="ignore"))
        else:
            values.append(str(part))
    raw = " ".join(values).strip()
    if not raw:
        return None
    match = re.search(r"\((.*?)\)", raw)
    if match:
        raw = match.group(1)
    return {token.upper() for token in _parse_parenthesized_words(raw)}


def _flags_for_provider_append(
    flags: str,
    *,
    target_provider: str,
    permanent_flags: Optional[set[str]] = None,
) -> str:
    filtered = _provider_flag_tokens(
        flags,
        target_provider=target_provider,
        permanent_flags=permanent_flags,
    )
    return f"({' '.join(filtered)})" if filtered else ""


def _provider_flag_tokens(
    flags: str,
    *,
    target_provider: str,
    permanent_flags: Optional[set[str]] = None,
) -> List[str]:
    portable = {"\\ANSWERED", "\\FLAGGED", "\\SEEN", "\\DRAFT"}
    if target_provider != "gmail":
        portable.add("\\DELETED")
    tokens = [tok for tok in flags.split() if tok.strip()]
    invalid_tokens = [token for token in tokens if not _valid_legacy_flag_token(token)]
    if invalid_tokens:
        raise RuntimeError(
            "invalid provider flags: "
            + ", ".join(sorted(set(invalid_tokens), key=str.upper))
        )
    filtered: List[str] = []
    unsupported: List[str] = []
    missing_permanent_flags = permanent_flags is None
    wildcard = permanent_flags is not None and "\\*" in permanent_flags
    for token in tokens:
        token = token.strip()
        upper = token.upper()
        if upper == "\\RECENT":
            continue
        if target_provider == "gmail" and upper in {"\\DELETED", "\\IMPORTANT"}:
            continue
        if upper in portable:
            if permanent_flags is None or upper in permanent_flags:
                filtered.append(token)
            else:
                unsupported.append(token)
            continue
        if not token.startswith("\\") or (permanent_flags is not None and upper in permanent_flags):
            if missing_permanent_flags and target_provider != "gmail":
                filtered.append(token)
            elif wildcard or upper in (permanent_flags or set()):
                filtered.append(token)
            else:
                unsupported.append(token)
            continue
        unsupported.append(token)
    if unsupported:
        raise RuntimeError(
            "target does not support exported IMAP flag/keyword(s): "
            + ", ".join(sorted(set(unsupported), key=str.upper))
        )
    return filtered


def required_provider_flag_set(
    flags: str,
    *,
    target_provider: str,
    permanent_flags: Optional[set[str]],
) -> set[str]:
    del permanent_flags
    return {
        token.upper()
        for token in _provider_flag_tokens(
            flags,
            target_provider=target_provider,
            permanent_flags=None,
        )
    }


def target_message_flag_set(imap: imaplib.IMAP4, num: bytes) -> set[str]:
    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID FLAGS)")
        if status != "OK":
            raise RuntimeError(f"failed to fetch target flags for message {num!r}")
        parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        return {token.upper() for token in str(parsed.get("flags") or "").split()}
    status, fetched = imap.fetch(num, "(FLAGS)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch target flags for message {num!r}")
    parsed = parse_provider_fetch_response(_provider_fetch_response_for_sequence(fetched or [], num))
    return {token.upper() for token in str(parsed.get("flags") or "").split()}


def _normalized_provider_internaldate(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if len(normalized) >= 2 and normalized.startswith('"') and normalized.endswith('"'):
        normalized = normalized[1:-1]
    return normalized


def target_message_internaldate(imap: imaplib.IMAP4, num: bytes) -> str:
    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID INTERNALDATE)")
        if status != "OK":
            raise RuntimeError(f"failed to fetch target INTERNALDATE for message {num!r}")
        parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        return _normalized_provider_internaldate(parsed.get("internaldate"))
    status, fetched = imap.fetch(num, "(INTERNALDATE)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch target INTERNALDATE for message {num!r}")
    parsed = parse_provider_fetch_response(_provider_fetch_response_for_sequence(fetched or [], num))
    return _normalized_provider_internaldate(parsed.get("internaldate"))


def append_target_internaldate_failure(
    failures: List[str],
    *,
    identity: str,
    target_mailbox: str,
    row: Dict[str, Any],
    actual_internaldate: str,
) -> None:
    expected_internaldate = _normalized_provider_internaldate(row.get("internaldate"))
    if not expected_internaldate:
        return
    if actual_internaldate != expected_internaldate:
        failures.append(
            f"target INTERNALDATE mismatch for {identity} in {target_mailbox}: "
            f"expected {expected_internaldate!r} got {(actual_internaldate or '<missing>')!r}"
        )


def _target_internaldate_matches_row(imap: imaplib.IMAP4, num: bytes, row: Dict[str, Any]) -> bool:
    expected_internaldate = _normalized_provider_internaldate(row.get("internaldate"))
    if not expected_internaldate:
        return True
    return target_message_internaldate(imap, num) == expected_internaldate


def restore_imap_flags(
    imap: imaplib.IMAP4,
    target_mailbox: str,
    row: Dict[str, Any],
    *,
    target_num: bytes,
    target_provider: str,
) -> None:
    status, _ = select_mailbox(imap, target_mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select target mailbox {target_mailbox!r} to restore IMAP flags")
    flags = _flags_for_provider_append(
        str(row.get("flags") or ""),
        target_provider=target_provider,
        permanent_flags=target_permanent_flags(imap),
    )
    if not flags:
        return
    status, response = imap.store(target_num, "+FLAGS.SILENT", flags)
    if status != "OK":
        raise RuntimeError(f"failed to restore IMAP flags for {row.get('canonical_id')}: {response}")


def _internaldate_for_append(internaldate: str) -> str:
    if internaldate.strip():
        value = internaldate.strip()
        parse_value = value[1:-1] if value.startswith('"') and value.endswith('"') else value
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in parse_value) or not _valid_legacy_internaldate(parse_value):
            raise RuntimeError("invalid provider internaldate")
        return value if value.startswith('"') and value.endswith('"') else f'"{value}"'
    return imaplib.Time2Internaldate(time.time())


def _quote_gmail_label(label: str) -> str:
    if label.startswith("\\") and _gmail_system_key_for_label(label):
        return label
    encoded = encode_imap_utf7(label)
    escaped = encoded.replace("\\", "\\\\").replace('"', r"\"")
    return f'"{escaped}"'


_GMAIL_LABEL_SYSTEM_KEYS = {
    "\\inbox": "inbox",
    "[gmail]/inbox": "inbox",
    "[googlemail]/inbox": "inbox",
    "\\sent": "sent",
    "[gmail]/sent mail": "sent",
    "[googlemail]/sent mail": "sent",
    "\\drafts": "drafts",
    "[gmail]/drafts": "drafts",
    "[googlemail]/drafts": "drafts",
    "\\trash": "trash",
    "[gmail]/trash": "trash",
    "[googlemail]/trash": "trash",
    "\\junk": "spam",
    "\\spam": "spam",
    "[gmail]/spam": "spam",
    "[googlemail]/spam": "spam",
    "\\all": "all",
    "\\allmail": "all",
    "[gmail]/all mail": "all",
    "[googlemail]/all mail": "all",
}

_GMAIL_TARGET_NAME_SYSTEM_KEYS = {
    "inbox": "inbox",
    "[gmail]/all mail": "all",
    "[googlemail]/all mail": "all",
    "all mail": "all",
    "[gmail]/sent mail": "sent",
    "[googlemail]/sent mail": "sent",
    "[gmail]/drafts": "drafts",
    "[googlemail]/drafts": "drafts",
    "[gmail]/trash": "trash",
    "[googlemail]/trash": "trash",
    "[gmail]/spam": "spam",
    "[googlemail]/spam": "spam",
    "[gmail]/important": "important",
    "[googlemail]/important": "important",
    "important": "important",
    "[gmail]/starred": "starred",
    "[googlemail]/starred": "starred",
    "starred": "starred",
}

_GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS = {
    "inbox": "inbox",
    "archive": "all",
    "all mail": "all",
    "[gmail]/all mail": "all",
    "[googlemail]/all mail": "all",
    "\\all": "all",
    "\\allmail": "all",
    "sent": "sent",
    "[gmail]/sent mail": "sent",
    "[googlemail]/sent mail": "sent",
    "\\sent": "sent",
    "drafts": "drafts",
    "[gmail]/drafts": "drafts",
    "[googlemail]/drafts": "drafts",
    "\\drafts": "drafts",
    "deleted messages": "trash",
    "trash": "trash",
    "[gmail]/trash": "trash",
    "[googlemail]/trash": "trash",
    "\\trash": "trash",
    "junk": "spam",
    "spam": "spam",
    "[gmail]/spam": "spam",
    "[googlemail]/spam": "spam",
    "\\junk": "spam",
    "\\spam": "spam",
    "important": "important",
    "[gmail]/important": "important",
    "[googlemail]/important": "important",
    "\\important": "important",
    "starred": "starred",
    "flagged": "starred",
    "[gmail]/starred": "starred",
    "[googlemail]/starred": "starred",
    "\\starred": "starred",
    "\\flagged": "starred",
}


def _gmail_system_key_for_label(label: str) -> str:
    return _GMAIL_LABEL_SYSTEM_KEYS.get(str(label).strip().lower(), "")


def _gmail_system_key_for_mailbox(mailbox: MailboxInfo) -> str:
    attr_lowers = {attr.lower() for attr in mailbox.attributes}
    attr_keys = {
        "\\all": "all",
        "\\archive": "all",
        "\\sent": "sent",
        "\\drafts": "drafts",
        "\\trash": "trash",
        "\\junk": "spam",
        "\\inbox": "inbox",
        "\\important": "important",
        "\\flagged": "starred",
    }
    for attr, key in attr_keys.items():
        if attr in attr_lowers:
            return key
    return _GMAIL_TARGET_NAME_SYSTEM_KEYS.get(mailbox.name.strip().lower(), "")


def _gmail_system_mailboxes_by_key(mailboxes: List[MailboxInfo]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for mailbox in mailboxes:
        key = _gmail_system_key_for_mailbox(mailbox)
        if key:
            result.setdefault(key, []).append(mailbox.name)
    return result


def _gmail_target_system_key(target_mailbox: str, target_mailboxes: Optional[List[MailboxInfo]] = None) -> str:
    if target_mailboxes is not None:
        for mailbox in target_mailboxes:
            if mailbox.name == target_mailbox:
                key = _gmail_system_key_for_mailbox(mailbox)
                if key:
                    return key
    return _GMAIL_TARGET_NAME_SYSTEM_KEYS.get(str(target_mailbox).strip().lower(), "")


def gmail_target_system_mailbox_issues(
    rows: List[Dict[str, Any]],
    target_mailboxes: List[MailboxInfo],
) -> List[str]:
    available = set(_gmail_system_mailboxes_by_key(target_mailboxes))
    issues: List[str] = []
    for row in rows:
        desired = str(row.get("primary_mailbox") or "Archive")
        required = _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(desired.strip().lower(), "")
        if required and required not in available:
            issues.append(
                f"Gmail target missing required {required} system mailbox for "
                f"{row.get('canonical_id') or '<unknown>'} primary_mailbox {desired!r}"
            )
    return issues


def _gmail_label_key(label: str) -> str:
    lower = str(label).strip().lower()
    system_key = _gmail_system_key_for_label(lower)
    if system_key:
        return system_key
    if lower in {"\\important", "important", "[gmail]/important", "[googlemail]/important"}:
        return "important"
    if lower in {"\\starred", "\\flagged", "starred", "[gmail]/starred", "[googlemail]/starred"}:
        return "starred"
    return f"label:{lower}"


def row_has_gmail_important(row: Dict[str, Any]) -> bool:
    labels = {_gmail_label_key(str(label)) for label in (row.get("gmail_labels") or [])}
    flags = {_gmail_label_key(token) for token in str(row.get("flags") or "").split()}
    return "important" in labels or "important" in flags


def row_has_gmail_starred(row: Dict[str, Any]) -> bool:
    labels = {_gmail_label_key(str(label)) for label in (row.get("gmail_labels") or [])}
    flags = {_gmail_label_key(token) for token in str(row.get("flags") or "").split()}
    return "starred" in labels or "starred" in flags


def gmail_labels_for_restore(
    row: Dict[str, Any],
    target_mailbox: str,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
    desired_target_mailbox: Optional[str] = None,
) -> List[str]:
    system_restore_labels = {
        "\\inbox": ("inbox", "\\Inbox"),
        "[gmail]/inbox": ("inbox", "\\Inbox"),
        "[googlemail]/inbox": ("inbox", "\\Inbox"),
        "\\trash": ("trash", "\\Trash"),
        "[gmail]/trash": ("trash", "\\Trash"),
        "[googlemail]/trash": ("trash", "\\Trash"),
        "\\junk": ("spam", "\\Junk"),
        "\\spam": ("spam", "\\Junk"),
        "[gmail]/spam": ("spam", "\\Junk"),
        "[googlemail]/spam": ("spam", "\\Junk"),
    }
    target_system_key = _gmail_target_system_key(target_mailbox, target_mailboxes)
    desired_system_key = (
        _gmail_target_system_key(desired_target_mailbox, target_mailboxes)
        if desired_target_mailbox
        else target_system_key
    )
    system_labels = {
        "\\all",
        "\\allmail",
        "\\archive",
        "\\drafts",
        "\\flagged",
        "\\important",
        "\\inbox",
        "\\junk",
        "\\muted",
        "\\sent",
        "\\spam",
        "\\starred",
        "\\trash",
        "important",
        "starred",
    }
    labels: List[str] = []
    desired_restore_labels = {
        "inbox": "\\Inbox",
        "sent": "\\Sent",
        "drafts": "\\Drafts",
        "trash": "\\Trash",
        "spam": "\\Junk",
    }
    desired_restore = desired_restore_labels.get(desired_system_key)
    if desired_restore and desired_system_key != target_system_key:
        labels.append(desired_restore)
    for raw in row.get("gmail_labels") or []:
        label = str(raw).strip()
        lower = label.lower()
        system_restore = system_restore_labels.get(lower)
        if system_restore:
            key, restore_label = system_restore
            if key != target_system_key and restore_label not in labels:
                labels.append(restore_label)
            continue
        if (
            not label
            or lower in system_labels
            or lower.startswith("[gmail]/")
            or lower.startswith("[googlemail]/")
            or lower == target_mailbox.lower()
        ):
            continue
        if label not in labels:
            labels.append(label)
    if row_has_gmail_important(row) and target_mailbox.lower() not in {"[gmail]/important", "[googlemail]/important", "important"}:
        labels.append("Important")
    return sorted(labels, key=str.lower)


def _first_target_match_num(imap: imaplib.IMAP4, target_mailbox: str, row: Dict[str, Any]) -> bytes:
    nums = target_matching_message_nums(imap, target_mailbox, row, create_if_missing=False)
    if not nums:
        raise RuntimeError(f"cannot find target message for {row.get('canonical_id')} to restore Gmail metadata")
    return nums[0]


def restore_gmail_labels(
    imap: imaplib.IMAP4,
    target_mailbox: str,
    row: Dict[str, Any],
    *,
    target_num: Optional[bytes] = None,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
    desired_target_mailbox: Optional[str] = None,
) -> None:
    labels = gmail_labels_for_restore(
        row,
        target_mailbox,
        target_mailboxes,
        desired_target_mailbox=desired_target_mailbox,
    )
    if not labels:
        return
    num = target_num or _first_target_match_num(imap, target_mailbox, row)
    status, _ = select_mailbox(imap, target_mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select target mailbox {target_mailbox!r} to restore Gmail labels")
    label_list = "(" + " ".join(_quote_gmail_label(label) for label in labels) + ")"
    status, response = _target_store(imap, num, "+X-GM-LABELS", label_list)
    if status != "OK":
        raise RuntimeError(f"failed to restore Gmail labels for {row.get('canonical_id')}: {response}")


def restore_gmail_starred_flag(imap: imaplib.IMAP4, target_mailbox: str, row: Dict[str, Any], *, target_num: Optional[bytes] = None) -> None:
    if not row_has_gmail_starred(row):
        return
    num = target_num or _first_target_match_num(imap, target_mailbox, row)
    status, _ = select_mailbox(imap, target_mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select target mailbox {target_mailbox!r} to restore Gmail starred flag")
    status, response = _target_store(imap, num, "+FLAGS", "(\\Flagged)")
    if status != "OK":
        raise RuntimeError(f"failed to restore Gmail starred flag for {row.get('canonical_id')}: {response}")


def _target_uid_command_available(imap: imaplib.IMAP4) -> bool:
    return callable(getattr(imap, "uid", None))


def _target_uid_bytes(uid: int) -> bytes:
    return str(uid).encode("ascii")


def _target_store(imap: imaplib.IMAP4, num: bytes, command: str, value: str):
    if _target_uid_command_available(imap):
        return imap.uid("store", num, command, value)
    return imap.store(num, command, value)


def _expected_content_identities(
    manifest_row: Dict[str, Any],
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> set[Tuple[int, str]]:
    identities: set[Tuple[int, str]] = set()
    for size, digest in expected_content_identities or ():
        try:
            size_int = int(size)
        except (TypeError, ValueError):
            continue
        digest_text = str(digest or "").lower()
        if size_int >= 0 and re.fullmatch(r"[0-9a-f]{64}", digest_text):
            identities.add((size_int, digest_text))
    if identities:
        return identities
    try:
        expected_size = int(manifest_row.get("rfc822_size") or 0)
    except (TypeError, ValueError):
        expected_size = 0
    expected_hash = str(manifest_row.get("content_sha256") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        identities.add((expected_size, expected_hash))
    return identities


def target_matching_message_nums(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    *,
    create_if_missing: bool = True,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> List[bytes]:
    message_id_raw = manifest_row.get("message_id_header")
    message_id = message_id_raw.strip() if isinstance(message_id_raw, str) else ""
    if create_if_missing:
        ensure_mailbox(imap, mailbox)
    status, _ = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        return []
    try:
        expected_size = int(manifest_row.get("rfc822_size") or 0)
    except (TypeError, ValueError):
        expected_size = 0
    expected_hash = str(manifest_row.get("content_sha256") or "").lower()
    content_identities = _expected_content_identities(manifest_row, expected_content_identities)
    if expected_hash and not content_identities:
        return []
    if _target_uid_command_available(imap):
        if message_id:
            status, data = imap.uid("search", None, "HEADER", "Message-ID", quote_imap_search_value(message_id))
        else:
            status, data = imap.uid("search", None, "ALL")
        if status != "OK" or not data or not data[0]:
            return []
        uids = parse_imap_uid_search_data(data, label="target UID SEARCH response")
        if expected_size <= 0 and not expected_hash and message_id:
            return [_target_uid_bytes(uid) for uid in uids]
        matches: List[bytes] = []
        for uid in uids:
            uid_bytes = _target_uid_bytes(uid)
            status, fetched = imap.uid("fetch", uid_bytes, "(UID RFC822.SIZE BODY.PEEK[])")
            if status != "OK":
                continue
            try:
                parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
            except RuntimeError:
                continue
            body = parsed.get("message_bytes")
            body_bytes = bytes(body) if isinstance(body, (bytes, bytearray)) else None
            if content_identities:
                if body_bytes is not None and (len(body_bytes), hashlib.sha256(body_bytes).hexdigest()) in content_identities:
                    matches.append(uid_bytes)
                continue
            if expected_size > 0:
                body_size = len(body_bytes) if body_bytes is not None else None
                parsed_size = int(parsed.get("rfc822_size") or 0)
                if body_size != expected_size and parsed_size != expected_size:
                    continue
            if expected_hash:
                if (
                    body_bytes is not None
                    and len(body_bytes) == expected_size
                    and hashlib.sha256(body_bytes).hexdigest() == expected_hash
                ):
                    matches.append(uid_bytes)
                continue
            if int(parsed.get("rfc822_size") or 0) > 0:
                matches.append(uid_bytes)
        return matches
    if message_id:
        status, data = imap.search(None, "HEADER", "Message-ID", quote_imap_search_value(message_id))
    else:
        status, data = imap.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        return []
    if expected_size <= 0 and not expected_hash and message_id:
        return list(data[0].split())
    matches: List[bytes] = []
    for num in data[0].split():
        status, fetched = imap.fetch(num, "(RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            continue
        try:
            fetched_for_num = _provider_fetch_response_for_sequence(fetched or [], num)
        except RuntimeError:
            continue
        for part in fetched_for_num:
            raw = part[0] if isinstance(part, tuple) else part
            if not isinstance(raw, (bytes, bytearray)):
                continue
            match = re.search(rb"RFC822\.SIZE\s+(\d+)", bytes(raw), flags=re.IGNORECASE)
            if content_identities:
                if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
                    body = bytes(part[1])
                    if (len(body), hashlib.sha256(body).hexdigest()) in content_identities:
                        matches.append(num)
                        break
                continue
            if expected_size > 0:
                body_size = (
                    len(part[1])
                    if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))
                    else None
                )
                if body_size != expected_size and (not match or int(match.group(1)) != expected_size):
                    continue
            if expected_hash and isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
                body = bytes(part[1])
                if len(body) == expected_size and hashlib.sha256(body).hexdigest() == expected_hash:
                    matches.append(num)
                    break
                continue
            if match and not expected_hash:
                matches.append(num)
                break
    return matches


def target_message_content_identity(
    imap: imaplib.IMAP4,
    num: bytes,
) -> Optional[Tuple[int, str]]:
    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            return None
        try:
            parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        except RuntimeError:
            return None
        body = parsed.get("message_bytes")
        if isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
            return (len(body_bytes), hashlib.sha256(body_bytes).hexdigest())
        return None
    status, fetched = imap.fetch(num, "(RFC822.SIZE BODY.PEEK[])")
    if status != "OK":
        return None
    try:
        fetched_for_num = _provider_fetch_response_for_sequence(fetched or [], num)
    except RuntimeError:
        return None
    for part in fetched_for_num:
        if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
            body = bytes(part[1])
            return (len(body), hashlib.sha256(body).hexdigest())
    return None


def _max_expected_content_identity_matches(
    target_content_identities: List[Tuple[int, str]],
    expected_identity_sets: List[set[Tuple[int, str]]],
) -> int:
    assigned_targets_by_expected: Dict[int, int] = {}

    def assign(target_index: int, seen_expected: set[int]) -> bool:
        target_identity = target_content_identities[target_index]
        for expected_index, expected_identities in enumerate(expected_identity_sets):
            if expected_index in seen_expected or target_identity not in expected_identities:
                continue
            seen_expected.add(expected_index)
            previous_target = assigned_targets_by_expected.get(expected_index)
            if previous_target is None or assign(previous_target, seen_expected):
                assigned_targets_by_expected[expected_index] = target_index
                return True
        return False

    matched = 0
    for target_index in range(len(target_content_identities)):
        if assign(target_index, set()):
            matched += 1
    return matched


def target_has_message(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    *,
    create_if_missing: bool = True,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> bool:
    return bool(
        target_matching_message_nums(
            imap,
            mailbox,
            manifest_row,
            create_if_missing=create_if_missing,
            expected_content_identities=expected_content_identities,
        )
    )


def _target_gmail_msgid(imap: imaplib.IMAP4, num: bytes) -> str:
    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID X-GM-MSGID)")
        if status != "OK":
            raise RuntimeError(f"failed to fetch Gmail message id for target message {num!r}")
        parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        gmail_msgid = str(parsed.get("gmail_msgid") or "")
        if not gmail_msgid:
            raise RuntimeError(f"target Gmail did not return X-GM-MSGID for message {num!r}")
        return gmail_msgid
    status, fetched = imap.fetch(num, "(X-GM-MSGID)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch Gmail message id for target message {num!r}")
    parsed = parse_provider_fetch_response(_provider_fetch_response_for_sequence(fetched or [], num))
    gmail_msgid = str(parsed.get("gmail_msgid") or "")
    if not gmail_msgid:
        raise RuntimeError(f"target Gmail did not return X-GM-MSGID for message {num!r}")
    return gmail_msgid


def consume_target_match_num(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
    used_gmail_msgids: Optional[set[str]] = None,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
    require_internaldate_match: bool = False,
) -> Optional[bytes]:
    mailbox_key = _target_mailbox_lookup_key(mailbox)
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(
        imap,
        mailbox,
        manifest_row,
        create_if_missing=create_if_missing,
        expected_content_identities=expected_content_identities,
    ):
        if num not in used:
            if require_internaldate_match and not _target_internaldate_matches_row(imap, num, manifest_row):
                continue
            if used_gmail_msgids is not None:
                gmail_msgid = _target_gmail_msgid(imap, num)
                if gmail_msgid and gmail_msgid in used_gmail_msgids:
                    continue
                if gmail_msgid:
                    used_gmail_msgids.add(gmail_msgid)
            used.add(num)
            return num
    return None


def consume_target_gmail_msgid_match_num(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    target_gmail_msgid: str,
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
    used_gmail_msgids: Optional[set[str]] = None,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
    require_internaldate_match: bool = False,
) -> Optional[bytes]:
    if not target_gmail_msgid:
        return None
    mailbox_key = _target_mailbox_lookup_key(mailbox, "gmail")
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(
        imap,
        mailbox,
        manifest_row,
        create_if_missing=create_if_missing,
        expected_content_identities=expected_content_identities,
    ):
        if num in used:
            continue
        gmail_msgid = _target_gmail_msgid(imap, num)
        if gmail_msgid != target_gmail_msgid:
            continue
        if require_internaldate_match and not _target_internaldate_matches_row(imap, num, manifest_row):
            continue
        if used_gmail_msgids is not None:
            if gmail_msgid in used_gmail_msgids:
                continue
            used_gmail_msgids.add(gmail_msgid)
        used.add(num)
        return num
    return None


def consume_target_gmail_match_in_mailboxes(
    imap: imaplib.IMAP4,
    mailboxes: List[str],
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    target_gmail_msgid: str = "",
    used_gmail_msgids: Optional[set[str]] = None,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
    require_internaldate_match: bool = False,
) -> Optional[Tuple[str, bytes, str]]:
    for mailbox in mailboxes:
        mailbox_key = _target_mailbox_lookup_key(mailbox, "gmail")
        used = used_by_mailbox.setdefault(mailbox_key, set())
        for num in target_matching_message_nums(
            imap,
            mailbox,
            manifest_row,
            create_if_missing=False,
            expected_content_identities=expected_content_identities,
        ):
            if num in used:
                continue
            gmail_msgid = _target_gmail_msgid(imap, num)
            if target_gmail_msgid and gmail_msgid != target_gmail_msgid:
                continue
            if require_internaldate_match and not _target_internaldate_matches_row(imap, num, manifest_row):
                continue
            if used_gmail_msgids is not None:
                if gmail_msgid and gmail_msgid in used_gmail_msgids:
                    continue
                if gmail_msgid:
                    used_gmail_msgids.add(gmail_msgid)
            used.add(num)
            return mailbox, num, gmail_msgid
    return None


def consume_target_match(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
    used_gmail_msgids: Optional[set[str]] = None,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
    require_internaldate_match: bool = False,
) -> bool:
    return consume_target_match_num(
        imap,
        mailbox,
        manifest_row,
        used_by_mailbox,
        create_if_missing=create_if_missing,
        used_gmail_msgids=used_gmail_msgids,
        expected_content_identities=expected_content_identities,
        require_internaldate_match=require_internaldate_match,
    ) is not None


def _target_gmail_label_and_flag_keys(imap: imaplib.IMAP4, num: bytes) -> Tuple[set[str], set[str]]:
    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID X-GM-LABELS FLAGS)")
        if status != "OK":
            raise RuntimeError(f"failed to fetch Gmail labels for target message {num!r}")
        parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        labels = {_gmail_label_key(str(label)) for label in (parsed.get("gmail_labels") or [])}
        flags = {token.upper() for token in str(parsed.get("flags") or "").split()}
        labels.update(_gmail_label_key(token) for token in flags)
        return {label for label in labels if label}, flags
    status, fetched = imap.fetch(num, "(X-GM-LABELS FLAGS)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch Gmail labels for target message {num!r}")
    parsed = parse_provider_fetch_response(_provider_fetch_response_for_sequence(fetched or [], num))
    labels = {_gmail_label_key(str(label)) for label in (parsed.get("gmail_labels") or [])}
    flags = {token.upper() for token in str(parsed.get("flags") or "").split()}
    labels.update(_gmail_label_key(token) for token in flags)
    return {label for label in labels if label}, flags


def _target_gmail_label_flag_internaldate(imap: imaplib.IMAP4, num: bytes) -> Tuple[set[str], set[str], str]:
    labels, flags = _target_gmail_label_and_flag_keys(imap, num)
    return labels, flags, target_message_internaldate(imap, num)


def _target_gmail_label_keys(imap: imaplib.IMAP4, num: bytes) -> set[str]:
    labels, _flags = _target_gmail_label_and_flag_keys(imap, num)
    return labels


def consume_target_match_with_gmail_state(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
    used_gmail_msgids: Optional[set[str]] = None,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> Optional[Tuple[set[str], set[str], str]]:
    mailbox_key = _target_mailbox_lookup_key(mailbox)
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(
        imap,
        mailbox,
        manifest_row,
        create_if_missing=create_if_missing,
        expected_content_identities=expected_content_identities,
    ):
        if num in used:
            continue
        if used_gmail_msgids is not None:
            gmail_msgid = _target_gmail_msgid(imap, num)
            if gmail_msgid and gmail_msgid in used_gmail_msgids:
                continue
            if gmail_msgid:
                used_gmail_msgids.add(gmail_msgid)
        used.add(num)
        return _target_gmail_label_flag_internaldate(imap, num)
    return None


def gmail_expected_target_mailboxes_for_row(
    row: Dict[str, Any],
    target_mailbox: str,
    target_mailboxes: List[MailboxInfo],
) -> List[str]:
    names: List[str] = []
    by_name = _target_mailboxes_by_name(target_mailboxes, target_provider="gmail")
    system_by_key = _gmail_system_mailboxes_by_key(target_mailboxes)

    def add(name: str) -> None:
        if name and name not in names:
            names.append(name)

    add(target_mailbox)
    for name in system_by_key.get("all", []):
        add(name)
    for name in gmail_system_view_mailboxes_for_row(row, target_mailboxes):
        add(name)
    for label in gmail_labels_for_restore(row, target_mailbox, target_mailboxes):
        system_key = _gmail_system_key_for_label(label)
        if system_key in system_by_key:
            for name in system_by_key[system_key]:
                add(name)
            continue
        mailbox = by_name.get(_target_mailbox_lookup_key(label, "gmail"))
        if mailbox is not None:
            add(mailbox.name)
    return names


def matching_gmail_msgids_for_row(
    imap: imaplib.IMAP4,
    row: Dict[str, Any],
    mailboxes: List[str],
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> set[str]:
    gmail_msgids: set[str] = set()
    used_by_mailbox: Dict[str, set[bytes]] = {}
    for mailbox in mailboxes:
        for num in target_matching_message_nums(
            imap,
            mailbox,
            row,
            create_if_missing=False,
            expected_content_identities=expected_content_identities,
        ):
            used = used_by_mailbox.setdefault(_target_mailbox_lookup_key(mailbox, "gmail"), set())
            if num in used:
                continue
            used.add(num)
            gmail_msgid = _target_gmail_msgid(imap, num)
            if gmail_msgid:
                gmail_msgids.add(gmail_msgid)
    return gmail_msgids


def target_gmail_labels_for_msgid(
    imap: imaplib.IMAP4,
    row: Dict[str, Any],
    mailboxes: List[str],
    target_gmail_msgid: str,
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> Optional[set[str]]:
    result = target_gmail_labels_and_flags_for_msgid(
        imap,
        row,
        mailboxes,
        target_gmail_msgid,
        expected_content_identities=expected_content_identities,
    )
    if result is None:
        return None
    labels, _flags = result
    return labels


def target_gmail_labels_and_flags_for_msgid(
    imap: imaplib.IMAP4,
    row: Dict[str, Any],
    mailboxes: List[str],
    target_gmail_msgid: str,
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> Optional[Tuple[set[str], set[str]]]:
    result = target_gmail_labels_flags_internaldate_for_msgid(
        imap,
        row,
        mailboxes,
        target_gmail_msgid,
        expected_content_identities=expected_content_identities,
    )
    if result is None:
        return None
    labels, flags, _internaldate = result
    return labels, flags


def target_gmail_labels_flags_internaldate_for_msgid(
    imap: imaplib.IMAP4,
    row: Dict[str, Any],
    mailboxes: List[str],
    target_gmail_msgid: str,
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]] = None,
) -> Optional[Tuple[set[str], set[str], str]]:
    used_by_mailbox: Dict[str, set[bytes]] = {}
    for mailbox in mailboxes:
        for num in target_matching_message_nums(
            imap,
            mailbox,
            row,
            create_if_missing=False,
            expected_content_identities=expected_content_identities,
        ):
            used = used_by_mailbox.setdefault(_target_mailbox_lookup_key(mailbox, "gmail"), set())
            if num in used:
                continue
            used.add(num)
            if _target_gmail_msgid(imap, num) == target_gmail_msgid:
                return _target_gmail_label_flag_internaldate(imap, num)
    return None


def target_message_count(imap: imaplib.IMAP4, mailbox: str) -> int:
    status, data = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        raise RuntimeError(f"target mailbox {mailbox!r} could not be selected for empty-target check: {data}")
    status, data = imap.search(None, "ALL")
    if status != "OK" or not data:
        raise RuntimeError(f"target mailbox {mailbox!r} could not be searched for empty-target check: {data}")
    return len((data[0] or b"").split())


def gmail_system_view_mailboxes_for_row(row: Dict[str, Any], target_mailboxes: List[MailboxInfo]) -> List[str]:
    wanted: set[str] = set()
    if row_has_gmail_starred(row):
        wanted.update({"\\flagged", "\\starred", "starred", "[gmail]/starred", "[googlemail]/starred"})
    if row_has_gmail_important(row):
        wanted.update({"\\important", "important", "[gmail]/important", "[googlemail]/important"})
    result: List[str] = []
    for mailbox in target_mailboxes:
        attr_lowers = {attr.lower() for attr in mailbox.attributes}
        name_lower = mailbox.name.lower()
        if attr_lowers & wanted or name_lower in wanted:
            result.append(mailbox.name)
    return result


def generic_special_view_mailboxes_for_row(row: Dict[str, Any], target_mailboxes: List[MailboxInfo]) -> List[str]:
    result: List[str] = []
    row_is_flagged = row_has_gmail_starred(row)
    for mailbox in target_mailboxes:
        if is_noselect(mailbox):
            continue
        attr_lowers = {attr.lower() for attr in mailbox.attributes}
        if "\\all" in attr_lowers:
            result.append(mailbox.name)
        elif "\\flagged" in attr_lowers and row_is_flagged:
            result.append(mailbox.name)
    return result


def enforce_empty_target(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    manifest_rows: List[Dict[str, Any]],
    journaled: set[Tuple[str, str]],
    *,
    target_provider: str = "imap",
    gmail_journal_msgids: Optional[Dict[Tuple[str, str], str]] = None,
    expected_content_identities_by_id: Optional[Dict[str, set[Tuple[int, str]]]] = None,
) -> None:
    target_provider = (target_provider or "imap").lower()
    permitted_by_mailbox: Dict[str, List[Tuple[Dict[str, Any], Tuple[str, str]]]] = {}
    by_name = _target_mailboxes_by_name(target_mailboxes, target_provider=target_provider)
    gmail_system_by_key = _gmail_system_mailboxes_by_key(target_mailboxes) if target_provider == "gmail" else {}
    gmail_all_mailboxes = gmail_all_mail_names(target_mailboxes) if target_provider == "gmail" else []
    gmail_journal_msgids = gmail_journal_msgids or {}
    for row in manifest_rows:
        identity = str(row.get("canonical_id") or "")
        desired = translate_source_mailbox_for_target(
            row,
            str(row.get("primary_mailbox") or "Archive"),
            target_mailboxes,
            target_provider=target_provider,
        )
        target_mailbox = resolve_target_mailbox(desired, target_mailboxes, target_provider=target_provider)
        key = journal_target_key(
            identity,
            target_mailbox,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        if key in journaled:
            permitted_names = [target_mailbox]
            if target_provider == "gmail":
                permitted_names.extend(gmail_all_mailboxes)
                permitted_names.extend(gmail_system_view_mailboxes_for_row(row, target_mailboxes))
                for label in gmail_labels_for_restore(row, target_mailbox, target_mailboxes):
                    system_key = _gmail_system_key_for_label(label)
                    if system_key in gmail_system_by_key:
                        permitted_names.extend(gmail_system_by_key[system_key])
                        continue
                    mailbox = by_name.get(_target_mailbox_lookup_key(label, target_provider))
                    if mailbox is not None:
                        permitted_names.append(mailbox.name)
            else:
                permitted_names.extend(generic_special_view_mailboxes_for_row(row, target_mailboxes))
            seen_permitted_names: set[str] = set()
            for name in permitted_names:
                key_name = _target_mailbox_lookup_key(name, target_provider)
                if key_name in seen_permitted_names:
                    continue
                seen_permitted_names.add(key_name)
                permitted_by_mailbox.setdefault(key_name, []).append((row, key))
    for mailbox in target_mailboxes:
        if is_noselect(mailbox):
            continue
        if is_virtual_target_mailbox(target_provider, mailbox):
            continue
        count = target_message_count(imap, mailbox.name)
        if count <= 0:
            continue
        verified = 0
        used: Dict[str, set[bytes]] = {}
        mailbox_key = _target_mailbox_lookup_key(mailbox.name, target_provider)
        for permitted_row, journal_key in permitted_by_mailbox.get(mailbox_key, []):
            identity = str(permitted_row.get("canonical_id") or "")
            expected_content_identities = (
                expected_content_identities_by_id.get(identity)
                if expected_content_identities_by_id and identity
                else None
            )
            target_gmail_msgid = gmail_journal_msgids.get(journal_key, "") if target_provider == "gmail" else ""
            if target_gmail_msgid:
                matched = consume_target_gmail_msgid_match_num(
                    imap,
                    mailbox.name,
                    permitted_row,
                    target_gmail_msgid,
                    used,
                    create_if_missing=False,
                    expected_content_identities=expected_content_identities,
                    require_internaldate_match=True,
                )
                if matched is not None:
                    verified += 1
                continue
            if consume_target_match(
                imap,
                mailbox.name,
                permitted_row,
                used,
                create_if_missing=False,
                expected_content_identities=expected_content_identities,
                require_internaldate_match=True,
            ):
                verified += 1
        if count > verified:
            raise RuntimeError(
                f"target_mode=empty but target mailbox {mailbox.name!r} contains "
                f"{count} message(s), only {verified} matching journaled message(s) from this migration"
            )


def translated_target_mailboxes_for_rows(
    rows: List[Dict[str, Any]],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> Dict[str, str]:
    translated_sources_by_target: Dict[str, Tuple[str, ...]] = {}
    result: Dict[str, str] = {}
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        source_desired = str(row.get("primary_mailbox") or "Archive")
        desired = translate_source_mailbox_for_target(
            row,
            source_desired,
            target_mailboxes,
            target_provider=target_provider,
        )
        target_mailbox = resolve_target_mailbox(desired, target_mailboxes, target_provider=target_provider)
        source_paths = row.get("source_mailbox_paths")
        source_key = (source_desired,)
        if isinstance(source_paths, dict) and isinstance(source_paths.get(source_desired), list):
            source_key = tuple(str(segment) for segment in source_paths[source_desired])
        target_mailbox_key = _target_mailbox_lookup_key(target_mailbox, target_provider)
        previous_source = translated_sources_by_target.setdefault(target_mailbox_key, source_key)
        if previous_source != source_key:
            raise RuntimeError(
                f"target mailbox translation collision for {target_mailbox!r}: "
                f"{previous_source!r} and {source_key!r}"
            )
        if identity:
            result[identity] = target_mailbox
    return result


def provider_account_merge_enabled(config: ProviderMigrationConfig) -> bool:
    return config.migration.account_merge_mode == "many_to_one"


def target_merge_group_key(config: ProviderMigrationConfig, account: MigrationAccount) -> Tuple[str, str]:
    target_username, _auth = effective_auth(config.target, account, role="target")
    normalized_username = auth_username_identity(config.target, target_username)
    return (
        normalized_username,
        provider_endpoint_state_digest(config.target, username=normalized_username),
    )


def same_target_accounts(config: ProviderMigrationConfig, account: MigrationAccount) -> List[MigrationAccount]:
    target_key = target_merge_group_key(config, account)
    return [
        candidate
        for candidate in config.accounts
        if target_merge_group_key(config, candidate) == target_key
    ]


def _validated_group_stage(
    config: ProviderMigrationConfig,
    in_root: Path,
    account: MigrationAccount,
    current_account: MigrationAccount,
    current_manifest_rows: List[Dict[str, Any]],
    current_journal_rows: List[Dict[str, Any]],
    *,
    repair_trailing_journal: bool = False,
) -> Tuple[Path, List[Dict[str, Any]], List[Dict[str, Any]]]:
    if account is current_account or account.source_email == current_account.source_email:
        account_dir = account_export_dir(in_root, current_account)
        _raise_if_provider_path_symlink(account_dir, "account directory")
        return account_dir, current_manifest_rows, current_journal_rows
    account_dir = account_export_dir(in_root, account)
    _raise_if_provider_path_symlink(account_dir, "account directory")
    manifest_rows = load_manifest(account_dir)
    require_manifest_schema(manifest_rows)
    require_unique_manifest_identities(manifest_rows)
    require_manifest_accounts(manifest_rows, account)
    require_manifest_source_provider(manifest_rows, config.source.provider)
    require_manifest_integrity_metadata(manifest_rows)
    require_provider_delivery_metadata(manifest_rows)
    require_complete_export_state(
        account_dir,
        account=account,
        manifest_rows=manifest_rows,
        source_provider=config.source.provider,
        target_provider=config.target.provider,
        source_endpoint=config.source,
        target_endpoint=config.target,
    )
    metadata_issues = metadata_manifest_issues(account_dir, manifest_rows)
    if metadata_issues:
        raise RuntimeError(
            f"metadata does not match manifest for merge source {account.source_email}: "
            + "; ".join(metadata_issues)
        )
    payload_issues = manifest_payload_issues(account_dir, manifest_rows)
    if payload_issues:
        raise RuntimeError(
            f"payload does not match manifest for merge source {account.source_email}: "
            + "; ".join(payload_issues)
        )
    artifact_issues = _provider_artifact_orphan_issues(account_dir, manifest_rows)
    if artifact_issues:
        raise RuntimeError(
            f"invalid provider artifacts for merge source {account.source_email}: "
            + "; ".join(artifact_issues)
        )
    mixed_layout_issues = provider_mixed_legacy_layout_issues(account_dir)
    if mixed_layout_issues:
        raise RuntimeError(
            f"invalid provider account layout for merge source {account.source_email}: "
            + "; ".join(mixed_layout_issues)
        )
    journal_rows = load_import_journal(account_dir, account, repair_trailing=repair_trailing_journal)
    require_valid_import_journal(journal_rows, account)
    journal_target_issues = journal_target_endpoint_issues(journal_rows, config=config, account=account)
    if journal_target_issues:
        raise RuntimeError(
            f"invalid import journal for merge source {account.source_email}: "
            + "; ".join(journal_target_issues)
        )
    journal_content_issues = committed_journal_manifest_content_issues(
        journal_rows,
        manifest_rows,
        target_provider=config.target.provider,
    )
    if journal_content_issues:
        raise RuntimeError(
            f"invalid import journal for merge source {account.source_email}: "
            + "; ".join(journal_content_issues)
        )
    journal_mailbox_issues = offline_journal_target_mailbox_issues(
        journal_rows,
        manifest_rows,
        target_provider=config.target.provider,
    )
    if journal_mailbox_issues:
        raise RuntimeError(
            f"invalid import journal for merge source {account.source_email}: "
            + "; ".join(journal_mailbox_issues)
        )
    if config.target.provider == "gmail":
        manifest_ids = {str(row.get("canonical_id") or "") for row in manifest_rows if row.get("canonical_id")}
        gmail_journal_issues: List[str] = []
        gmail_journal_issues.extend(invalid_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids))
        gmail_journal_issues.extend(missing_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids))
        gmail_journal_issues.extend(duplicate_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids))
        if gmail_journal_issues:
            raise RuntimeError(
                f"invalid Gmail import journal for merge source {account.source_email}: "
                + "; ".join(gmail_journal_issues)
            )
    return account_dir, manifest_rows, journal_rows


def validated_merge_group_stages(
    config: ProviderMigrationConfig,
    in_root: Path,
    account: MigrationAccount,
    current_manifest_rows: List[Dict[str, Any]],
    current_journal_rows: List[Dict[str, Any]],
    *,
    repair_trailing_journal: bool = False,
) -> List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]]:
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]] = []
    for group_account in same_target_accounts(config, account):
        account_dir, manifest_rows, journal_rows = _validated_group_stage(
            config,
            in_root,
            group_account,
            account,
            current_manifest_rows,
            current_journal_rows,
            repair_trailing_journal=repair_trailing_journal,
        )
        stages.append((group_account, account_dir, manifest_rows, journal_rows))
    return stages


def require_merge_group_unique_manifest_identities(
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
) -> None:
    owners_by_identity: Dict[str, str] = {}
    collisions: List[str] = []
    for group_account, _account_dir, manifest_rows, _journal_rows in stages:
        for row in manifest_rows:
            identity = str(row.get("canonical_id") or "")
            if not identity:
                continue
            previous_owner = owners_by_identity.get(identity)
            if previous_owner is None:
                owners_by_identity[identity] = group_account.source_email
            elif previous_owner != group_account.source_email:
                collisions.append(f"{identity} in {previous_owner} and {group_account.source_email}")
    if collisions:
        raise RuntimeError("merge group canonical_id collision: " + "; ".join(collisions))


def require_merge_group_target_translation_safe(
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> None:
    merged_rows: List[Dict[str, Any]] = []
    for _account, _account_dir, manifest_rows, _journal_rows in stages:
        merged_rows.extend(manifest_rows)
    translated_target_mailboxes_for_rows(
        merged_rows,
        target_mailboxes,
        target_provider=target_provider,
    )


def require_merge_group_journals_remote_complete(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    *,
    target_provider: str,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
) -> None:
    for group_account, _account_dir, manifest_rows, journal_rows in stages:
        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        committed_keys = set(latest_committed)
        for row in latest_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        ).values():
            if row.get("status") != "pending":
                continue
            identity = str(row.get("canonical_id") or "<missing>")
            target_mailbox = str(row.get("target_mailbox") or "<missing>")
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=target_provider,
                target_mailboxes=target_mailboxes,
            )
            if key in committed_keys:
                continue
            raise RuntimeError(
                f"merge group source {group_account.source_email} has unresolved pending import journal row: "
                f"{identity} in {target_mailbox}"
            )
        row_by_id = {
            str(row.get("canonical_id") or ""): row
            for row in manifest_rows
            if row.get("canonical_id")
        }
        for (identity, _target_mailbox_key), journal_row in latest_committed.items():
            target_mailbox = str(journal_row.get("target_mailbox") or "")
            manifest_row = row_by_id.get(identity)
            if manifest_row is None:
                continue
            expected_content_identities = expected_content_identities_by_id.get(identity)
            row_used_by_mailbox: Dict[str, set[bytes]] = {}
            if target_provider == "gmail":
                row_used_gmail_msgids: set[str] = set()
                target_gmail_msgid = str(journal_row.get("target_gmail_msgid") or "")
                matching_mailboxes = gmail_expected_target_mailboxes_for_row(
                    manifest_row,
                    target_mailbox,
                    target_mailboxes,
                )
                matched = consume_target_gmail_match_in_mailboxes(
                    imap,
                    matching_mailboxes,
                    manifest_row,
                    row_used_by_mailbox,
                    target_gmail_msgid=target_gmail_msgid,
                    used_gmail_msgids=row_used_gmail_msgids,
                    expected_content_identities=expected_content_identities,
                    require_internaldate_match=True,
                )
                if matched is not None:
                    continue
                if target_gmail_msgid:
                    raise RuntimeError(
                        f"merge group journal says {identity} from {group_account.source_email} "
                        f"is committed to Gmail target message {target_gmail_msgid} in {target_mailbox!r}, "
                        "but that exact target message was not found"
                    )
            else:
                matched_num = consume_target_match_num(
                    imap,
                    target_mailbox,
                    manifest_row,
                    row_used_by_mailbox,
                    create_if_missing=False,
                    expected_content_identities=expected_content_identities,
                    require_internaldate_match=True,
                )
                if matched_num is not None:
                    continue
            raise RuntimeError(
                f"merge group journal says {identity} from {group_account.source_email} "
                f"is committed to {target_mailbox!r}, but the target message was not found"
            )


def merge_group_empty_target_context(
    config: ProviderMigrationConfig,
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
) -> Tuple[List[Dict[str, Any]], set[Tuple[str, str]], Dict[Tuple[str, str], str]]:
    permitted_rows: List[Dict[str, Any]] = []
    permitted_keys: set[Tuple[str, str]] = set()
    gmail_journal_msgids: Dict[Tuple[str, str], str] = {}
    for _group_account, _account_dir, manifest_rows, journal_rows in stages:
        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        journaled = set(latest_committed)
        if config.target.provider == "gmail":
            for key, journal_row in latest_committed.items():
                target_gmail_msgid = str(journal_row.get("target_gmail_msgid") or "")
                if target_gmail_msgid:
                    gmail_journal_msgids[key] = target_gmail_msgid
        journaled.update(
            journal_row_target_key(
                row,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            for row in journal_rows
            if row.get("status") == "pending"
        )
        if not journaled:
            continue
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=config.target.provider,
        )
        for row in manifest_rows:
            identity = str(row.get("canonical_id") or "")
            if not identity:
                continue
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not target_mailbox:
                desired = translate_source_mailbox_for_target(
                    row,
                    str(row.get("primary_mailbox") or "Archive"),
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
                target_mailbox = resolve_target_mailbox(desired, target_mailboxes, target_provider=config.target.provider)
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            if key not in journaled:
                continue
            permitted_rows.append(row)
            permitted_keys.add(key)
    return permitted_rows, permitted_keys, gmail_journal_msgids


def provider_import_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
) -> None:
    _raise_if_provider_path_symlink(in_root, "import root")
    account_dir = account_export_dir(in_root, account)
    _raise_if_provider_path_symlink(account_dir, "account directory")
    manifest_rows = load_manifest(account_dir)
    require_manifest_schema(manifest_rows)
    require_unique_manifest_identities(manifest_rows)
    require_manifest_accounts(manifest_rows, account)
    require_manifest_source_provider(manifest_rows, config.source.provider)
    require_manifest_integrity_metadata(manifest_rows)
    require_provider_delivery_metadata(manifest_rows)
    require_complete_export_state(
        account_dir,
        account=account,
        manifest_rows=manifest_rows,
        source_provider=config.source.provider,
        target_provider=config.target.provider,
        source_endpoint=config.source,
        target_endpoint=config.target,
    )
    metadata_issues = metadata_manifest_issues(account_dir, manifest_rows)
    if metadata_issues:
        raise RuntimeError("metadata does not match manifest: " + "; ".join(metadata_issues))
    payloads_by_identity: Dict[str, bytes] = {}
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]] = {}
    for row in manifest_rows:
        identity = str(row.get("canonical_id") or "")
        eml_path = _manifest_path(account_dir, row, "eml_path")
        if not eml_path.exists():
            raise RuntimeError(f"message file missing for {identity}: {eml_path}")
        data = _read_provider_artifact_bytes(eml_path, "provider message artifact")
        require_manifest_payload_matches(row, data)
        payloads_by_identity[identity] = data
        expected_content_identities_by_id[identity] = provider_payload_content_identities(data)
    artifact_issues = _provider_artifact_orphan_issues(account_dir, manifest_rows)
    if artifact_issues:
        raise RuntimeError("invalid provider artifacts: " + "; ".join(artifact_issues))
    mixed_layout_issues = provider_mixed_legacy_layout_issues(account_dir)
    if mixed_layout_issues:
        raise RuntimeError("invalid provider account layout: " + "; ".join(mixed_layout_issues))
    journal_rows = load_import_journal(account_dir, account, repair_trailing=True)
    require_valid_import_journal(journal_rows, account)
    journal_target_issues = journal_target_endpoint_issues(journal_rows, config=config, account=account)
    if journal_target_issues:
        raise RuntimeError("invalid import journal: " + "; ".join(journal_target_issues))
    manifest_ids = {str(row.get("canonical_id") or "") for row in manifest_rows if row.get("canonical_id")}
    journal_content_issues = committed_journal_manifest_content_issues(
        journal_rows,
        manifest_rows,
        target_provider=config.target.provider,
    )
    if journal_content_issues:
        raise RuntimeError("invalid import journal: " + "; ".join(journal_content_issues))
    if config.target.provider == "gmail":
        invalid_gmail_msgid_issues = invalid_journal_target_gmail_msgid_issues(
            journal_rows,
            manifest_ids=manifest_ids,
        )
        if invalid_gmail_msgid_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(invalid_gmail_msgid_issues))
        duplicate_gmail_msgid_issues = duplicate_journal_target_gmail_msgid_issues(
            journal_rows,
            manifest_ids=manifest_ids,
        )
        if duplicate_gmail_msgid_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(duplicate_gmail_msgid_issues))
    limiter = limiter or RateLimiter(config.limits.throttle.max_bytes_per_second)
    used_target_nums: Dict[str, set[bytes]] = {}
    used_target_gmail_msgids: set[str] = set()
    target_binding = provider_target_journal_binding(config, account)
    merge_group_stages: Optional[List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]]] = None
    if provider_account_merge_enabled(config):
        merge_group_stages = validated_merge_group_stages(
            config,
            in_root,
            account,
            manifest_rows,
            journal_rows,
            repair_trailing_journal=True,
        )
        require_merge_group_unique_manifest_identities(merge_group_stages)

    with imap_connection(config.target, account, role="target") as imap:
        capabilities: List[str] = []
        if config.target.provider == "gmail":
            capabilities = get_capabilities(imap)
            if "X-GM-EXT-1" not in capabilities:
                raise RuntimeError(
                    f"Gmail target is not import-ready for {account.target_email}: "
                    "IMAP server did not advertise X-GM-EXT-1"
                )
        target_mailboxes = list_mailboxes(imap)
        journal_content_issues = committed_journal_manifest_content_issues(
            journal_rows,
            manifest_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        if journal_content_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(journal_content_issues))
        pending = {
            key
            for key, row in latest_journal_rows(
                journal_rows,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            ).items()
            if row.get("status") == "pending"
        }
        if merge_group_stages is not None:
            require_merge_group_target_translation_safe(
                merge_group_stages,
                target_mailboxes,
                target_provider=config.target.provider,
            )
        merge_group_expected_content_identities_by_id = expected_content_identities_by_id
        if merge_group_stages is not None:
            merge_group_expected_content_identities_by_id = merge_group_payload_content_identities(merge_group_stages)
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=config.target.provider,
        )
        committed_target_issues = committed_journal_target_mailbox_issues(
            journal_rows,
            target_mailbox_by_identity,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        if committed_target_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(committed_target_issues))
        pending_target_issues = pending_journal_target_mailbox_issues(
            journal_rows,
            target_mailbox_by_identity,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        if pending_target_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(pending_target_issues))
        if config.target.provider == "gmail":
            target_issues = gmail_target_readiness_issues(capabilities, target_mailboxes)
            target_issues.extend(gmail_all_mail_select_issues(imap, target_mailboxes, role="target"))
            target_issues.extend(gmail_target_decommission_issues(config.target, account))
            target_issues.extend(gmail_target_system_mailbox_issues(manifest_rows, target_mailboxes))
            if target_issues:
                raise RuntimeError("Gmail target is not import-ready: " + "; ".join(target_issues))
            journal_rows = repair_missing_journal_target_gmail_msgids(
                imap,
                account_dir,
                account,
                journal_rows,
                manifest_rows,
                target_mailbox_by_identity,
                target_binding,
                expected_content_identities_by_id,
                target_mailboxes=target_mailboxes,
            )
            repaired_journal_issues = []
            repaired_journal_issues.extend(
                missing_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                    target_mailboxes=target_mailboxes,
                )
            )
            repaired_journal_issues.extend(
                duplicate_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                    target_mailboxes=target_mailboxes,
                )
            )
            if repaired_journal_issues:
                raise RuntimeError("invalid import journal: " + "; ".join(repaired_journal_issues))
        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        committed = set(latest_committed)
        if merge_group_stages is not None:
            require_merge_group_journals_remote_complete(
                imap,
                target_mailboxes,
                merge_group_stages,
                target_provider=config.target.provider,
                expected_content_identities_by_id=merge_group_expected_content_identities_by_id,
            )
        if config.migration.target_mode == "empty":
            empty_target_rows = manifest_rows
            empty_target_journaled = committed | pending
            empty_target_gmail_msgids = {
                key: str(row.get("target_gmail_msgid") or "")
                for key, row in latest_committed.items()
                if config.target.provider == "gmail" and row.get("target_gmail_msgid")
            }
            if merge_group_stages is not None:
                empty_target_rows, empty_target_journaled, empty_target_gmail_msgids = merge_group_empty_target_context(
                    config,
                    target_mailboxes,
                    merge_group_stages,
                )
            enforce_empty_target(
                imap,
                target_mailboxes,
                empty_target_rows,
                empty_target_journaled,
                target_provider=config.target.provider,
                gmail_journal_msgids=empty_target_gmail_msgids,
                expected_content_identities_by_id=merge_group_expected_content_identities_by_id,
            )
        for row in sorted(manifest_rows, key=lambda item: str(item.get("canonical_id", ""))):
            _raise_if_stopped(stop_event, f"provider import {account.target_email}")
            identity = str(row.get("canonical_id") or "")
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not target_mailbox:
                desired = translate_source_mailbox_for_target(
                    row,
                    str(row.get("primary_mailbox") or "Archive"),
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
                target_mailbox = resolve_target_mailbox(desired, target_mailboxes, target_provider=config.target.provider)
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            data = payloads_by_identity[identity]
            expected_content_identities = expected_content_identities_by_id.get(identity)
            if key in committed:
                journal_target_gmail_msgid = str(latest_committed.get(key, {}).get("target_gmail_msgid") or "")
                committed_mailbox = target_mailbox
                if config.target.provider == "gmail" and journal_target_gmail_msgid:
                    committed_match = consume_target_gmail_match_in_mailboxes(
                        imap,
                        gmail_expected_target_mailboxes_for_row(row, target_mailbox, target_mailboxes),
                        row,
                        used_target_nums,
                        target_gmail_msgid=journal_target_gmail_msgid,
                        used_gmail_msgids=used_target_gmail_msgids,
                        expected_content_identities=expected_content_identities,
                        require_internaldate_match=False,
                    )
                    if committed_match is None:
                        committed_num = None
                    else:
                        committed_mailbox, committed_num, _committed_gmail_msgid = committed_match
                else:
                    committed_num = consume_target_match_num(
                        imap,
                        target_mailbox,
                        row,
                        used_target_nums,
                        create_if_missing=False,
                        used_gmail_msgids=used_target_gmail_msgids if config.target.provider == "gmail" else None,
                        expected_content_identities=expected_content_identities,
                        require_internaldate_match=False,
                    )
                if committed_num is None and config.target.provider == "gmail" and journal_target_gmail_msgid:
                    raise RuntimeError(
                        f"journal says {identity} is committed to Gmail target message {journal_target_gmail_msgid} "
                        f"in {target_mailbox!r}, but that exact target message was not found"
                    )
                if committed_num is None and config.migration.target_mode == "empty":
                    raise RuntimeError(
                        f"journal says {identity} is committed to {target_mailbox!r}, "
                        "but the target message was not found"
                    )
                if committed_num is not None:
                    subscribe_mailbox(imap, target_mailbox)
                    if config.target.provider == "gmail":
                        restore_gmail_labels(
                            imap,
                            committed_mailbox,
                            row,
                            target_num=committed_num,
                            target_mailboxes=target_mailboxes,
                            desired_target_mailbox=target_mailbox,
                        )
                        restore_gmail_starred_flag(imap, committed_mailbox, row, target_num=committed_num)
                        restore_imap_flags(
                            imap,
                            committed_mailbox,
                            row,
                            target_num=committed_num,
                            target_provider=config.target.provider,
                        )
                    else:
                        restore_imap_flags(
                            imap,
                            target_mailbox,
                            row,
                            target_num=committed_num,
                            target_provider=config.target.provider,
                        )
                    continue
            matched_num = None
            matched_mailbox = target_mailbox
            matched_gmail_msgid = ""
            if config.migration.target_mode == "merge" or provider_account_merge_enabled(config) or key in pending:
                if config.target.provider == "gmail":
                    matched = consume_target_gmail_match_in_mailboxes(
                        imap,
                        gmail_expected_target_mailboxes_for_row(row, target_mailbox, target_mailboxes),
                        row,
                        used_target_nums,
                        used_gmail_msgids=used_target_gmail_msgids,
                        expected_content_identities=expected_content_identities,
                        require_internaldate_match=False,
                    )
                    if matched is not None:
                        matched_mailbox, matched_num, matched_gmail_msgid = matched
                else:
                    matched_num = consume_target_match_num(
                        imap,
                        target_mailbox,
                        row,
                        used_target_nums,
                        expected_content_identities=expected_content_identities,
                        require_internaldate_match=False,
                    )
            if matched_num is not None:
                subscribe_mailbox(imap, target_mailbox)
                if config.target.provider == "gmail":
                    target_gmail_msgid = matched_gmail_msgid or _target_gmail_msgid(imap, matched_num)
                    restore_gmail_labels(
                        imap,
                        matched_mailbox,
                        row,
                        target_num=matched_num,
                        target_mailboxes=target_mailboxes,
                        desired_target_mailbox=target_mailbox,
                    )
                    restore_gmail_starred_flag(imap, matched_mailbox, row, target_num=matched_num)
                    restore_imap_flags(
                        imap,
                        matched_mailbox,
                        row,
                        target_num=matched_num,
                        target_provider=config.target.provider,
                    )
                else:
                    restore_imap_flags(
                        imap,
                        target_mailbox,
                        row,
                        target_num=matched_num,
                        target_provider=config.target.provider,
                    )
                    target_gmail_msgid = ""
                append_journal(
                    account_dir,
                    account,
                    _journal_row(
                        row,
                        target_mailbox,
                        "committed",
                        "existing",
                        target_binding=target_binding,
                        target_gmail_msgid=target_gmail_msgid,
                    ),
                )
                committed.add(key)
                continue
            ensure_mailbox(imap, target_mailbox)
            append_flags = _flags_for_provider_append(
                str(row.get("flags") or ""),
                target_provider=config.target.provider,
                permanent_flags=target_permanent_flags(imap),
            )
            _provider_throttle_wait(
                limiter,
                len(data),
                stop_event=stop_event,
                label=f"provider import {account.target_email}",
            )
            append_journal(
                account_dir,
                account,
                _journal_row(row, target_mailbox, "pending", "append-started", target_binding=target_binding),
            )
            status, response = append_message(
                imap,
                target_mailbox,
                append_flags,
                _internaldate_for_append(str(row.get("internaldate") or "")),
                data,
            )
            if status != "OK":
                append_journal(
                    account_dir,
                    account,
                    _journal_row(row, target_mailbox, "failed", "append-failed", target_binding=target_binding),
                )
                raise RuntimeError(f"append failed for {identity}: {response}")
            appended_num = consume_target_match_num(
                imap,
                target_mailbox,
                row,
                used_target_nums,
                create_if_missing=False,
                used_gmail_msgids=used_target_gmail_msgids if config.target.provider == "gmail" else None,
                expected_content_identities=expected_content_identities,
                require_internaldate_match=False,
            )
            if appended_num is None:
                raise RuntimeError(f"appended target message not found for {identity} in {target_mailbox!r}")
            if config.target.provider == "gmail":
                target_gmail_msgid = _target_gmail_msgid(imap, appended_num)
                restore_gmail_labels(imap, target_mailbox, row, target_num=appended_num, target_mailboxes=target_mailboxes)
                restore_gmail_starred_flag(imap, target_mailbox, row, target_num=appended_num)
            else:
                target_gmail_msgid = ""
            append_journal(
                account_dir,
                account,
                _journal_row(
                    row,
                    target_mailbox,
                    "committed",
                    "appended",
                    target_binding=target_binding,
                    target_gmail_msgid=target_gmail_msgid,
                ),
            )
            committed.add(key)
    logging.info("[provider-import] %s -> %s: completed", account.source_email, account.target_email)


def provider_import_all(
    config: ProviderMigrationConfig,
    in_root: Path,
    *,
    max_workers: int,
    ignore_errors: bool,
    stop_event: Optional[object] = None,
) -> None:
    max_workers = _require_max_workers(max_workers)
    _raise_if_provider_path_symlink(in_root, "import root")
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider import {acc.target_email}")
        with_retry(
            lambda: provider_import_account(config, acc, in_root, stop_event=stop_event, limiter=limiter),
            attempts=config.limits.retry_max_attempts,
            label=f"provider import {acc.target_email}",
            stop_event=stop_event,
        )

    if provider_account_merge_enabled(config):
        errors: List[str] = []
        grouped: Dict[Tuple[str, str], List[MigrationAccount]] = {}
        for account in config.accounts:
            grouped.setdefault(target_merge_group_key(config, account), []).append(account)
        for target_key, accounts in grouped.items():
            group_failed = False
            for acc in accounts:
                if group_failed:
                    message = (
                        f"{acc.email}: skipped because an earlier source in target merge group "
                        f"{target_key[0]} failed"
                    )
                    logging.error("[provider-import] %s", message)
                    errors.append(message)
                    continue
                try:
                    worker(acc)
                except Exception as exc:
                    message = f"{acc.email}: {exc}"
                    logging.error("[provider-import] %s", message)
                    errors.append(message)
                    group_failed = True
                    if not ignore_errors:
                        raise
        if errors:
            raise RuntimeError(f"provider-import failed for {len(errors)} account(s): " + "; ".join(errors))
        return

    parallel_process_accounts(
        "provider-import",
        worker,
        config.accounts,
        max_workers,
        stop_on_error=not ignore_errors,
        stop_event=stop_event,
    )


def _journal_row(
    row: Dict[str, Any],
    target_mailbox: str,
    status: str,
    action: str,
    *,
    target_binding: Dict[str, Any],
    target_gmail_msgid: str = "",
) -> Dict[str, Any]:
    journal_row = {
        "canonical_id": row.get("canonical_id"),
        "target_account": row.get("target_account"),
        "target_endpoint": target_binding["target_endpoint"],
        "target_endpoint_sha256": target_binding["target_endpoint_sha256"],
        "target_mailbox": target_mailbox,
        "status": status,
        "action": action,
        "flags": row.get("flags") or "",
        "internaldate": row.get("internaldate") or "",
        "content_sha256": row.get("content_sha256"),
        "rfc822_size": int(row.get("rfc822_size") or 0),
        CONTENT_BINDING_FIELD: row.get(CONTENT_BINDING_FIELD),
        "timestamp": _utc_now(),
    }
    if target_gmail_msgid:
        journal_row["target_gmail_msgid"] = target_gmail_msgid
    return journal_row


def provider_audit_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
) -> Tuple[str, List[str]]:
    issues: List[str] = []
    _raise_if_stopped(stop_event, f"provider audit {account.email}")
    try:
        _raise_if_provider_path_symlink(in_root, "audit root")
    except RuntimeError as exc:
        return account.email, [str(exc)]
    account_dir = account_export_dir(in_root, account)
    try:
        _raise_if_provider_path_symlink(account_dir, "account directory")
    except RuntimeError as exc:
        return account.email, [str(exc)]
    if not account_dir.exists():
        return account.email, [f"account export directory missing: {account_dir}"]
    try:
        rows = load_manifest(account_dir)
    except Exception as exc:
        return account.email, [f"manifest load failed: {exc}"]
    _raise_if_stopped(stop_event, f"provider audit {account.email}")
    issues.extend(
        provider_export_state_issues(
            account_dir,
            account=account,
            manifest_rows=rows,
            source_provider=config.source.provider,
            target_provider=config.target.provider,
            source_endpoint=config.source,
            target_endpoint=config.target,
        )
    )
    identities = set()
    issues.extend(manifest_schema_issues(rows))
    issues.extend(manifest_account_issues(rows, account))
    issues.extend(manifest_source_provider_issues(rows, config.source.provider))
    issues.extend(manifest_integrity_issues(rows))
    issues.extend(provider_delivery_metadata_issues(rows))
    issues.extend(metadata_manifest_issues(account_dir, rows, require_present=False))
    issues.extend(_provider_artifact_orphan_issues(account_dir, rows))
    issues.extend(provider_mixed_legacy_layout_issues(account_dir))
    issues.extend(gmail_target_decommission_issues(config.target, account))
    manifest_ids = {str(row.get("canonical_id") or "") for row in rows if row.get("canonical_id")}
    try:
        journal_rows = load_import_journal(account_dir, account)
    except Exception as exc:
        journal_rows = None
        issues.append(f"import journal load failed: {exc}")
    else:
        issues.extend(journal_row_issues(journal_rows, account))
        issues.extend(journal_target_endpoint_issues(journal_rows, config=config, account=account))
        issues.extend(
            committed_journal_manifest_content_issues(
                journal_rows,
                rows,
                target_provider=config.target.provider,
            )
        )
        issues.extend(
            offline_journal_target_mailbox_issues(
                journal_rows,
                rows,
                target_provider=config.target.provider,
            )
        )
        if config.target.provider == "gmail":
            issues.extend(invalid_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids))
    if config.target.provider == "gmail":
        if journal_rows is not None:
            issues.extend(
                missing_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                )
            )
            issues.extend(
                duplicate_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                )
            )
    for row in rows:
        _raise_if_stopped(stop_event, f"provider audit {account.email}")
        identity = str(row.get("canonical_id") or "")
        if not identity:
            issues.append("manifest row missing canonical_id")
            continue
        if identity in identities:
            issues.append(f"{identity}: duplicate manifest identity")
        identities.add(identity)
        for rel_key in ("eml_path", "metadata_path"):
            try:
                rel_path = _manifest_path(account_dir, row, rel_key)
                if not rel_path.exists():
                    issues.append(f"{identity}: missing {rel_key}")
            except Exception as exc:
                issues.append(f"{identity}: invalid {rel_key}: {exc}")
        eml_rel = row.get("eml_path")
        eml_path: Optional[Path] = None
        with contextlib.suppress(Exception):
            eml_path = _manifest_path(account_dir, row, "eml_path")
        if eml_rel and eml_path is not None and eml_path.exists():
            try:
                data = _read_provider_artifact_bytes(eml_path, "provider message artifact")
                try:
                    require_manifest_payload_matches(row, data)
                except Exception as exc:
                    issues.append(str(exc))
                try:
                    BytesParser(policy=default_policy).parsebytes(data)
                except Exception as exc:
                    issues.append(f"{identity}: failed to parse RFC822: {exc}")
            except Exception as exc:
                issues.append(f"{identity}: failed to read eml: {exc}")
    return account.email, issues


def provider_merge_group_identity_collision_issues(
    config: ProviderMigrationConfig,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
) -> List[str]:
    if not provider_account_merge_enabled(config):
        return []
    grouped: Dict[Tuple[str, str], List[MigrationAccount]] = {}
    for account in config.accounts:
        _raise_if_stopped(stop_event, "provider audit merge group collision scan")
        grouped.setdefault(target_merge_group_key(config, account), []).append(account)
    issues: List[str] = []
    for group_accounts in grouped.values():
        _raise_if_stopped(stop_event, "provider audit merge group collision scan")
        if len(group_accounts) < 2:
            continue
        owners_by_identity: Dict[str, str] = {}
        target_label = group_accounts[0].target_email
        for account in group_accounts:
            _raise_if_stopped(stop_event, "provider audit merge group collision scan")
            account_dir = account_export_dir(in_root, account)
            if _provider_symlink_component(account_dir) is not None or not account_dir.exists():
                continue
            try:
                manifest_rows = load_manifest(account_dir)
            except Exception:
                continue
            for row in manifest_rows:
                _raise_if_stopped(stop_event, "provider audit merge group collision scan")
                identity = str(row.get("canonical_id") or "")
                if not identity:
                    continue
                previous_owner = owners_by_identity.get(identity)
                if previous_owner is None:
                    owners_by_identity[identity] = account.source_email
                elif previous_owner != account.source_email:
                    issues.append(
                        f"{target_label}: merge group canonical_id collision: "
                        f"{identity} in {previous_owner} and {account.source_email}"
                    )
    return issues


def _provider_account_worker_results(
    label: str,
    accounts: List[MigrationAccount],
    max_workers: int,
    worker: Callable[[MigrationAccount], Any],
    stop_event: Optional[object],
) -> List[Tuple[MigrationAccount, Any]]:
    import concurrent.futures

    results: List[Tuple[MigrationAccount, Any]] = []
    account_iter = iter(accounts)
    futures = {}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label)
    wait_timeout = 0.2 if stop_event is not None else None

    def submit_next() -> bool:
        if _stop_requested(stop_event):
            return False
        try:
            acc = next(account_iter)
        except StopIteration:
            return False
        futures[executor.submit(worker, acc)] = acc
        return True

    try:
        for _ in range(min(max_workers, len(accounts))):
            if not submit_next():
                break
        while futures:
            _raise_if_stopped(stop_event, label)
            done, _pending = concurrent.futures.wait(
                futures,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            for fut in done:
                acc = futures.pop(fut)
                results.append((acc, fut.result()))
                _raise_if_stopped(stop_event, label)
            for _ in range(len(done)):
                submit_next()
        _raise_if_stopped(stop_event, label)
        return results
    finally:
        if _stop_requested(stop_event):
            for fut in futures:
                fut.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        else:
            executor.shutdown(wait=True)


def provider_audit_all(
    config: ProviderMigrationConfig,
    in_root: Path,
    *,
    max_workers: int,
    stop_event: Optional[object] = None,
) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    try:
        _raise_if_provider_path_symlink(in_root, "audit root")
    except RuntimeError as exc:
        return False, [str(exc)]
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> List[str]:
        _raise_if_stopped(stop_event, f"provider audit {acc.email}")
        _name, account_issues = provider_audit_account(config, acc, in_root, stop_event=stop_event)
        _raise_if_stopped(stop_event, f"provider audit {acc.email}")
        return [f"{acc.email}: {issue}" for issue in account_issues]

    for _acc, result in _provider_account_worker_results("provider-audit", config.accounts, max_workers, worker, stop_event):
        issues.extend(result)
    issues.extend(provider_merge_group_identity_collision_issues(config, in_root, stop_event=stop_event))
    return len(issues) == 0, issues


def provider_validate_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    check_target: bool = False,
    write_report: bool = True,
    allow_unresolved_pending: bool = False,
    repair_trailing_journal: bool = False,
    allow_missing_gmail_target_msgid: bool = False,
    stop_event: Optional[object] = None,
) -> Tuple[str, Dict[str, Any]]:
    _raise_if_stopped(stop_event, f"provider validate {account.email}")
    account_dir = account_export_dir(in_root, account)
    report: Dict[str, Any] = {
        "account": account.email,
        "missing": [],
        "duplicates": [],
        "failed": [],
        "remote_missing": [],
        "remote_checked": 0,
        "committed": 0,
        "exported": 0,
        "ok": False,
    }
    try:
        _raise_if_provider_path_symlink(in_root, "validate root")
    except RuntimeError as exc:
        report["failed"].append(str(exc))
        return account.email, report
    try:
        _raise_if_provider_path_symlink(account_dir, "account directory")
        journal_rows = load_import_journal(account_dir, account, repair_trailing=repair_trailing_journal)
        manifest_rows = load_manifest(account_dir)
    except Exception as exc:
        report["failed"].append(str(exc))
        return account.email, report
    _raise_if_stopped(stop_event, f"provider validate {account.email}")

    report["failed"].extend(
        provider_export_state_issues(
            account_dir,
            account=account,
            manifest_rows=manifest_rows,
            source_provider=config.source.provider,
            target_provider=config.target.provider,
            source_endpoint=config.source,
            target_endpoint=config.target,
        )
    )

    try:
        require_manifest_accounts(manifest_rows, account)
    except Exception as exc:
        report["failed"].append(str(exc))
    report["failed"].extend(manifest_schema_issues(manifest_rows))
    report["failed"].extend(manifest_source_provider_issues(manifest_rows, config.source.provider))
    report["failed"].extend(manifest_integrity_issues(manifest_rows))
    report["failed"].extend(provider_delivery_metadata_issues(manifest_rows))
    report["failed"].extend(metadata_manifest_issues(account_dir, manifest_rows))
    report["failed"].extend(manifest_payload_issues(account_dir, manifest_rows))
    report["failed"].extend(_provider_artifact_orphan_issues(account_dir, manifest_rows))
    report["failed"].extend(provider_mixed_legacy_layout_issues(account_dir))
    report["failed"].extend(gmail_target_decommission_issues(config.target, account))

    journal_issues = journal_row_issues(journal_rows, account)
    report["failed"].extend(journal_issues)
    report["failed"].extend(journal_target_endpoint_issues(journal_rows, config=config, account=account))

    journal_content_checked = False

    def append_journal_content_failures(
        target_mailboxes: Optional[List[MailboxInfo]] = None,
    ) -> None:
        nonlocal journal_content_checked
        journal_content_checked = True
        report["failed"].extend(
            committed_journal_manifest_content_issues(
                journal_rows,
                manifest_rows,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
        )

    pending_resolution_checked = False

    def append_unresolved_pending_failures(
        target_mailboxes: Optional[List[MailboxInfo]] = None,
    ) -> None:
        nonlocal pending_resolution_checked
        pending_resolution_checked = True
        if allow_unresolved_pending:
            return
        committed_journal_keys = set(
            latest_committed_journal_rows(
                journal_rows,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
        )
        for key, row in latest_journal_rows(
            journal_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        ).items():
            _raise_if_stopped(stop_event, f"provider validate {account.email}")
            if row.get("status") != "pending":
                continue
            identity = str(row.get("canonical_id") or "")
            target_mailbox = str(row.get("target_mailbox") or "")
            if key not in committed_journal_keys:
                report["failed"].append(
                    f"journal pending identity has no committed resolution: {identity or '<missing>'} in {target_mailbox or '<missing>'}"
                )

    if not check_target:
        append_journal_content_failures()
        report["failed"].extend(
            offline_journal_target_mailbox_issues(
                journal_rows,
                manifest_rows,
                target_provider=config.target.provider,
            )
        )
        append_unresolved_pending_failures()

    identity_issues, manifest_id_counts = manifest_identity_issues(manifest_rows)
    for issue in identity_issues:
        if issue.startswith("duplicate manifest identity:"):
            match = re.search(r"duplicate manifest identity: (.*?) \((\d+) rows\)", issue)
            if match:
                report["duplicates"].append({"canonical_id": match.group(1), "count": int(match.group(2)), "source": "manifest"})
            else:
                report["duplicates"].append(issue)
        else:
            report["failed"].append(issue)

    by_id = {str(row.get("canonical_id")): row for row in manifest_rows if row.get("canonical_id")}
    manifest_ids = set(by_id)
    expected_content_identities_by_id = manifest_payload_content_identities(account_dir, manifest_rows)
    merge_group_stages: Optional[List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]]] = None
    merge_group_stage_error: Optional[str] = None
    if provider_account_merge_enabled(config):
        try:
            merge_group_stages = validated_merge_group_stages(
                config,
                in_root,
                account,
                manifest_rows,
                journal_rows,
            )
            require_merge_group_unique_manifest_identities(merge_group_stages)
        except Exception as exc:
            merge_group_stage_error = str(exc)
            report["failed"].append(merge_group_stage_error)
    journal_gmail_msgid_missing = (
        missing_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids)
        if config.target.provider == "gmail" and not allow_missing_gmail_target_msgid
        else []
    )
    journal_gmail_msgid_invalid = (
        invalid_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids)
        if config.target.provider == "gmail"
        else []
    )
    journal_gmail_msgid_duplicates = (
        duplicate_journal_target_gmail_msgid_entries(journal_rows, manifest_ids=manifest_ids)
        if config.target.provider == "gmail"
        else []
    )
    report["exported"] = len(manifest_ids)

    def evaluate_journal(
        expected_target_by_id: Optional[Dict[str, str]] = None,
        target_mailboxes: Optional[List[MailboxInfo]] = None,
    ) -> Tuple[Dict[str, int], Dict[str, str], List[str]]:
        committed_by_id: Dict[str, int] = {}
        target_by_id: Dict[str, str] = {}
        failures: List[str] = []
        effective_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        for row in effective_committed.values():
            _raise_if_stopped(stop_event, f"provider validate {account.email}")
            identity = str(row.get("canonical_id") or "")
            if not identity:
                failures.append("journal committed row missing canonical_id")
                continue
            if identity not in manifest_ids:
                failures.append(f"journal committed identity not in manifest: {identity}")
                continue
            target_mailbox = str(row.get("target_mailbox") or "")
            expected_target = expected_target_by_id.get(identity) if expected_target_by_id else None
            if expected_target and not _target_mailbox_matches_expected(
                target_mailbox,
                expected_target,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            ):
                failures.append(
                    f"journal committed identity in wrong target mailbox: {identity} "
                    f"expected {expected_target!r} got {target_mailbox!r}"
                )
                continue
            committed_by_id[identity] = committed_by_id.get(identity, 0) + 1
            if target_mailbox:
                target_by_id[identity] = expected_target or target_mailbox
        return committed_by_id, target_by_id, failures

    def apply_counts(committed_by_id: Dict[str, int]) -> None:
        report["missing"] = []
        manifest_duplicates = [
            {"canonical_id": identity, "count": count, "source": "manifest"}
            for identity, count in sorted(manifest_id_counts.items())
            if count > 1
        ]
        report["duplicates"] = list(manifest_duplicates)
        for identity in sorted(manifest_ids):
            count = committed_by_id.get(identity, 0)
            if count == 0:
                report["missing"].append(identity)
            elif count > 1:
                report["duplicates"].append({"canonical_id": identity, "count": count})
        report["duplicates"].extend(journal_gmail_msgid_duplicates)
        report["failed"].extend(journal_gmail_msgid_invalid)
        report["failed"].extend(journal_gmail_msgid_missing)
        report["committed"] = sum(1 for identity in manifest_ids if committed_by_id.get(identity, 0) > 0)

    if check_target and merge_group_stage_error is None:
        try:
            _raise_if_stopped(stop_event, f"provider validate {account.email}")
            with imap_connection(config.target, account, role="target") as imap:
                _raise_if_stopped(stop_event, f"provider validate {account.email}")
                capabilities: List[str] = []
                if config.target.provider == "gmail":
                    capabilities = get_capabilities(imap)
                    _raise_if_stopped(stop_event, f"provider validate {account.email}")
                    if "X-GM-EXT-1" not in capabilities:
                        raise RuntimeError("target Gmail IMAP server did not advertise X-GM-EXT-1")
                target_mailboxes = list_mailboxes(imap)
                _raise_if_stopped(stop_event, f"provider validate {account.email}")
                append_journal_content_failures(target_mailboxes=target_mailboxes)
                if merge_group_stages is not None:
                    require_merge_group_target_translation_safe(
                        merge_group_stages,
                        target_mailboxes,
                        target_provider=config.target.provider,
                    )
                merge_group_expected_content_identities_by_id = expected_content_identities_by_id
                if merge_group_stages is not None:
                    merge_group_expected_content_identities_by_id = merge_group_payload_content_identities(merge_group_stages)
                target_mailbox_by_identity = translated_target_mailboxes_for_rows(
                    manifest_rows,
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
                if config.target.provider == "gmail":
                    report["failed"].extend(gmail_target_system_mailbox_issues(manifest_rows, target_mailboxes))
                append_unresolved_pending_failures(target_mailboxes=target_mailboxes)
                expected_target_by_id = {
                    identity: target_mailbox_by_identity[identity]
                    for identity, row in by_id.items()
                }
                committed_by_id, target_by_id, failures = evaluate_journal(
                    expected_target_by_id,
                    target_mailboxes=target_mailboxes,
                )
                if config.target.provider == "gmail":
                    journal_gmail_msgid_missing = (
                        missing_journal_target_gmail_msgid_issues(
                            journal_rows,
                            manifest_ids=manifest_ids,
                            target_mailboxes=target_mailboxes,
                        )
                        if not allow_missing_gmail_target_msgid
                        else []
                    )
                    journal_gmail_msgid_duplicates = duplicate_journal_target_gmail_msgid_entries(
                        journal_rows,
                        manifest_ids=manifest_ids,
                        target_mailboxes=target_mailboxes,
                    )
                report["failed"].extend(failures)
                apply_counts(committed_by_id)
                if config.target.provider == "gmail":
                    target_readiness_issues = gmail_target_readiness_issues(capabilities, target_mailboxes)
                    target_readiness_issues.extend(gmail_all_mail_select_issues(imap, target_mailboxes, role="target"))
                    if target_readiness_issues:
                        raise RuntimeError("; ".join(target_readiness_issues))
                if merge_group_stages is not None:
                    require_merge_group_journals_remote_complete(
                        imap,
                        target_mailboxes,
                        merge_group_stages,
                        target_provider=config.target.provider,
                        expected_content_identities_by_id=merge_group_expected_content_identities_by_id,
                    )
                if config.migration.target_mode == "empty":
                    empty_target_rows = manifest_rows
                    effective_committed_rows = latest_committed_journal_rows(
                        journal_rows,
                        target_provider=config.target.provider,
                        target_mailboxes=target_mailboxes,
                    )
                    empty_target_journaled = set(effective_committed_rows)
                    empty_target_gmail_msgids = {
                        key: str(row.get("target_gmail_msgid") or "")
                        for key, row in effective_committed_rows.items()
                        if config.target.provider == "gmail" and row.get("target_gmail_msgid")
                    }
                    if merge_group_stages is not None:
                        empty_target_rows, empty_target_journaled, empty_target_gmail_msgids = merge_group_empty_target_context(
                            config,
                            target_mailboxes,
                            merge_group_stages,
                        )
                    try:
                        enforce_empty_target(
                            imap,
                            target_mailboxes,
                            empty_target_rows,
                            empty_target_journaled,
                            target_provider=config.target.provider,
                            gmail_journal_msgids=empty_target_gmail_msgids,
                            expected_content_identities_by_id=merge_group_expected_content_identities_by_id,
                        )
                    except Exception as exc:
                        report["failed"].append(f"remote target validation failed: {exc}")
                if not report["missing"]:
                    used_target_nums: Dict[str, set[bytes]] = {}
                    target_content_identity_cache: Dict[Tuple[str, bytes], Optional[Tuple[int, str]]] = {}
                    used_target_gmail_msgids: set[str] = set()
                    effective_committed_rows = latest_committed_journal_rows(
                        journal_rows,
                        target_provider=config.target.provider,
                        target_mailboxes=target_mailboxes,
                    )
                    target_gmail_msgid_by_id = {
                        str(row.get("canonical_id") or ""): str(row.get("target_gmail_msgid") or "")
                        for row in effective_committed_rows.values()
                        if row.get("target_gmail_msgid")
                    }
                    committed_target_gmail_msgids = {
                        target_gmail_msgid
                        for target_gmail_msgid in target_gmail_msgid_by_id.values()
                        if target_gmail_msgid
                    }
                    for identity, row in by_id.items():
                        _raise_if_stopped(stop_event, f"provider validate {account.email}")
                        target_mailbox = target_by_id.get(identity)
                        if not target_mailbox:
                            continue
                        expected_content_identities = expected_content_identities_by_id.get(identity)
                        report["remote_checked"] += 1
                        if config.target.provider == "gmail":
                            expected_mailboxes = gmail_expected_target_mailboxes_for_row(
                                row,
                                target_mailbox,
                                target_mailboxes,
                            )
                            matching_gmail_msgids = matching_gmail_msgids_for_row(
                                imap,
                                row,
                                expected_mailboxes,
                                expected_content_identities=expected_content_identities,
                            )
                            journal_target_gmail_msgid = target_gmail_msgid_by_id.get(identity, "")
                            primary_actual_labels: Optional[set[str]] = None
                            primary_actual_flags: Optional[set[str]] = None
                            primary_actual_internaldate: Optional[str] = None
                            if journal_target_gmail_msgid:
                                if journal_target_gmail_msgid not in matching_gmail_msgids:
                                    report["remote_missing"].append(identity)
                                    continue
                                primary_actual_state = target_gmail_labels_flags_internaldate_for_msgid(
                                    imap,
                                    row,
                                    [target_mailbox],
                                    journal_target_gmail_msgid,
                                    expected_content_identities=expected_content_identities,
                                )
                                if primary_actual_state is None:
                                    report["remote_missing"].append(identity)
                                    continue
                                (
                                    primary_actual_labels,
                                    primary_actual_flags,
                                    primary_actual_internaldate,
                                ) = primary_actual_state
                                extra_gmail_msgids = matching_gmail_msgids - committed_target_gmail_msgids
                            else:
                                extra_gmail_msgids = matching_gmail_msgids if len(matching_gmail_msgids) > 1 else set()
                            if extra_gmail_msgids:
                                report["duplicates"].append({
                                    "canonical_id": identity,
                                    "count": len({journal_target_gmail_msgid} | extra_gmail_msgids)
                                    if journal_target_gmail_msgid
                                    else len(extra_gmail_msgids),
                                    "source": "target",
                                })
                            if journal_target_gmail_msgid:
                                actual_labels = primary_actual_labels
                                actual_flags = primary_actual_flags
                                actual_internaldate = primary_actual_internaldate
                            else:
                                actual_state = consume_target_match_with_gmail_state(
                                    imap,
                                    target_mailbox,
                                    row,
                                    used_target_nums,
                                    create_if_missing=False,
                                    used_gmail_msgids=used_target_gmail_msgids,
                                    expected_content_identities=expected_content_identities,
                                )
                                actual_labels = actual_state[0] if actual_state is not None else None
                                actual_flags = actual_state[1] if actual_state is not None else None
                                actual_internaldate = actual_state[2] if actual_state is not None else None
                            if actual_labels is None or actual_flags is None:
                                report["remote_missing"].append(identity)
                                continue
                            append_target_internaldate_failure(
                                report["failed"],
                                identity=identity,
                                target_mailbox=target_mailbox,
                                row=row,
                                actual_internaldate=actual_internaldate or "",
                            )
                            expected_labels = {
                                _gmail_label_key(label)
                                for label in gmail_labels_for_restore(row, target_mailbox, target_mailboxes)
                            }
                            if row_has_gmail_starred(row):
                                expected_labels.add("starred")
                            missing_labels = sorted(expected_labels - actual_labels)
                            if missing_labels:
                                report["failed"].append(
                                    f"target Gmail labels missing for {identity} in {target_mailbox}: "
                                    + ", ".join(missing_labels)
                                )
                            try:
                                required_flags = required_provider_flag_set(
                                    str(row.get("flags") or ""),
                                    target_provider=config.target.provider,
                                    permanent_flags=None,
                                )
                            except Exception as exc:
                                report["failed"].append(f"target Gmail flag validation failed for {identity}: {exc}")
                                continue
                            missing_flags = sorted(required_flags - actual_flags)
                            if missing_flags:
                                report["failed"].append(
                                    f"target Gmail flags missing for {identity} in {target_mailbox}: "
                                    + ", ".join(missing_flags)
                                )
                        else:
                            matching_nums = target_matching_message_nums(
                                imap,
                                target_mailbox,
                                row,
                                create_if_missing=False,
                                expected_content_identities=expected_content_identities,
                            )
                            current_content_identities = _expected_content_identities(row, expected_content_identities)
                            expected_identity_sets = [
                                _expected_content_identities(
                                    other_row,
                                    expected_content_identities_by_id.get(other_identity),
                                )
                                for other_identity, other_row in by_id.items()
                                if target_by_id.get(other_identity) == target_mailbox
                            ]
                            matching_content_identities: List[Tuple[int, str]] = []
                            for matching_num in matching_nums:
                                cache_key = (target_mailbox, matching_num)
                                if cache_key not in target_content_identity_cache:
                                    target_content_identity_cache[cache_key] = target_message_content_identity(
                                        imap,
                                        matching_num,
                                    )
                                target_content_identity = target_content_identity_cache[cache_key]
                                if target_content_identity is not None:
                                    matching_content_identities.append(target_content_identity)
                            if len(matching_content_identities) == len(matching_nums):
                                expected_occurrences = _max_expected_content_identity_matches(
                                    matching_content_identities,
                                    expected_identity_sets,
                                )
                            else:
                                expected_occurrences = sum(
                                    1
                                    for expected_identities in expected_identity_sets
                                    if expected_identities & current_content_identities
                                )
                            if len(matching_nums) > max(expected_occurrences, 1):
                                report["duplicates"].append({
                                    "canonical_id": identity,
                                    "count": len(matching_nums),
                                    "source": "target",
                                })
                            target_num = consume_target_match_num(
                                imap,
                                target_mailbox,
                                row,
                                used_target_nums,
                                create_if_missing=False,
                                expected_content_identities=expected_content_identities,
                            )
                            if target_num is None:
                                report["remote_missing"].append(identity)
                                continue
                            try:
                                required_flags = required_provider_flag_set(
                                    str(row.get("flags") or ""),
                                    target_provider=config.target.provider,
                                    permanent_flags=target_permanent_flags(imap),
                                )
                                actual_flags = target_message_flag_set(imap, target_num)
                                actual_internaldate = target_message_internaldate(imap, target_num)
                            except Exception as exc:
                                report["failed"].append(f"target IMAP delivery validation failed for {identity}: {exc}")
                                continue
                            append_target_internaldate_failure(
                                report["failed"],
                                identity=identity,
                                target_mailbox=target_mailbox,
                                row=row,
                                actual_internaldate=actual_internaldate,
                            )
                            missing_flags = sorted(required_flags - actual_flags)
                            if missing_flags:
                                report["failed"].append(
                                    f"target IMAP flags missing for {identity} in {target_mailbox}: "
                                    + ", ".join(missing_flags)
                                )
        except Exception as exc:
            if _stop_requested(stop_event):
                raise
            if not journal_content_checked:
                append_journal_content_failures()
            if not pending_resolution_checked:
                append_unresolved_pending_failures()
            committed_by_id, _target_by_id, failures = evaluate_journal()
            report["failed"].extend(failures)
            apply_counts(committed_by_id)
            report["failed"].append(f"remote target validation failed: {exc}")
    else:
        if not journal_content_checked:
            append_journal_content_failures()
        committed_by_id, _target_by_id, failures = evaluate_journal()
        report["failed"].extend(failures)
        apply_counts(committed_by_id)

    report["ok"] = not report["missing"] and not report["duplicates"] and not report["failed"]
    if report["remote_missing"]:
        report["ok"] = False
    _raise_if_stopped(stop_event, f"provider validate {account.email}")
    if write_report:
        _atomic_json(account_dir / f"validation-{sanitize_for_path(account.target_email)}.json", report)
    return account.email, report


def provider_validate_all(
    config: ProviderMigrationConfig,
    in_root: Path,
    *,
    max_workers: int,
    stop_event: Optional[object] = None,
) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    try:
        _raise_if_provider_path_symlink(in_root, "validate root")
    except RuntimeError as exc:
        return False, [str(exc)]
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> Dict[str, Any]:
        _raise_if_stopped(stop_event, f"provider validate {acc.email}")
        _name, report = provider_validate_account(config, acc, in_root, check_target=True, stop_event=stop_event)
        _raise_if_stopped(stop_event, f"provider validate {acc.email}")
        return report

    for _acc, report in _provider_account_worker_results("provider-validate", config.accounts, max_workers, worker, stop_event):
        if report.get("ok"):
            logging.info("[provider-validate] %s: OK exported=%s committed=%s", report["account"], report["exported"], report["committed"])
            continue
        prefix = str(report.get("account"))
        for key in ("missing", "duplicates", "remote_missing", "failed"):
            for item in report.get(key, []):
                issues.append(f"{prefix}: {key}: {item}")
    return len(issues) == 0, issues


def provider_test_accounts(
    config: ProviderMigrationConfig,
    *,
    max_workers: int,
    roles: Tuple[str, ...] = ("source", "target"),
    stop_event: Optional[object] = None,
) -> None:
    max_workers = _require_max_workers(max_workers)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider test {acc.email}")
        if "source" in roles:
            with imap_connection(config.source, acc, role="source"):
                pass
            _raise_if_stopped(stop_event, f"provider test {acc.email}")
        if "target" in roles:
            with imap_connection(config.target, acc, role="target"):
                pass
            _raise_if_stopped(stop_event, f"provider test {acc.email}")
        logging.info("[provider-test] %s: OK", acc.email)

    _provider_account_worker_results("provider-test", config.accounts, max_workers, worker, stop_event)


def provider_preflight(
    config: ProviderMigrationConfig,
    *,
    max_workers: int,
    stop_event: Optional[object] = None,
) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> Tuple[List[str], int]:
        account_issues: List[str] = []
        source_total = 0
        seen_identity: set[str] = set()
        _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
        try:
            with imap_connection(config.source, acc, role="source") as source_imap:
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                capabilities = get_capabilities(source_imap)
                use_gmail_metadata = config.source.provider == "gmail"
                gmail_extensions = use_gmail_metadata and "X-GM-EXT-1" in capabilities
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                source_mailboxes = list_mailboxes(source_imap)
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                if config.source.provider == "gmail":
                    account_issues.extend(gmail_source_readiness_issues(capabilities, source_mailboxes))
                    _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                    account_issues.extend(gmail_all_mail_select_issues(source_imap, source_mailboxes, role="source"))
                    account_issues.extend(gmail_account_decommission_issues(config.source, acc))
                provider_key = config.source.provider.lower()
                retained_source_mailboxes = _source_mailbox_scan_order(provider_key, [
                    mailbox
                    for mailbox in source_mailboxes
                    if not should_skip_source_mailbox(config.source.provider, mailbox, source_mailboxes)
                ])
                fetch_body_for_identity = (
                    provider_key != "gmail"
                    and any(_is_non_gmail_all_mailbox(provider_key, mailbox) for mailbox in retained_source_mailboxes)
                )
                ordinary_content_remaining_for_all: Dict[Tuple[int, str], int] = {}
                ordinary_delivery_remaining_for_all: Dict[Tuple[int, str], Dict[_ProviderVirtualDeliveryKey, int]] = {}
                for mailbox in retained_source_mailboxes:
                    _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                    try:
                        uids, _uidvalidity = fetch_all_uids_and_uidvalidity(source_imap, mailbox.name)
                    except Exception as exc:
                        if _stop_requested(stop_event):
                            raise
                        account_issues.append(f"source mailbox {mailbox.name} scan failed: {exc}")
                        continue
                    _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                    pending_all_sizes_by_content: Dict[Tuple[int, str], List[Tuple[int, _ProviderVirtualDeliveryKey]]] = {}
                    for uid in uids:
                        _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                        status, data = source_imap.uid(
                            "fetch",
                            str(uid),
                            fetch_items(include_body=fetch_body_for_identity, gmail_extensions=gmail_extensions),
                        )
                        _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                        if status != "OK":
                            account_issues.append(f"metadata fetch failed in {mailbox.name} for UID {uid}")
                            continue
                        raw_fetch_parts: List[str] = []
                        for item in data or []:
                            raw = item[0] if isinstance(item, tuple) and item else item
                            if isinstance(raw, (bytes, bytearray)):
                                raw_fetch_parts.append(bytes(raw).decode(errors="ignore"))
                        raw_fetch_text = " ".join(raw_fetch_parts)
                        if not _provider_fetch_number_after(
                            _provider_fetch_meta_without_label_values(raw_fetch_text),
                            "RFC822.SIZE",
                        ):
                            account_issues.append(f"metadata fetch missing RFC822.SIZE in {mailbox.name} for UID {uid}")
                            continue
                        try:
                            parsed = parse_provider_fetch_response(data or [], expected_uid=int(uid))
                        except Exception as exc:
                            account_issues.append(f"metadata fetch parse failed in {mailbox.name} for UID {uid}: {exc}")
                            continue
                        if gmail_extensions and not parsed.get("gmail_msgid"):
                            account_issues.append(f"metadata fetch missing X-GM-MSGID in {mailbox.name} for UID {uid}")
                            continue
                        if fetch_body_for_identity:
                            msg_bytes = parsed.get("message_bytes")
                            if not isinstance(msg_bytes, bytes):
                                account_issues.append(f"body fetch missing message bytes in {mailbox.name} for UID {uid}")
                                continue
                            size = int(parsed.get("rfc822_size") or len(msg_bytes))
                            content_identity = (size, hashlib.sha256(msg_bytes).hexdigest())
                            non_gmail_all_source = _is_non_gmail_all_mailbox(provider_key, mailbox)
                            non_gmail_flagged_source = _is_non_gmail_flagged_mailbox(provider_key, mailbox)
                            if non_gmail_all_source:
                                remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                                if remaining_ordinary > 0:
                                    pending_all_sizes_by_content.setdefault(content_identity, []).append((
                                        size,
                                        _provider_virtual_delivery_key(parsed),
                                    ))
                                    continue
                                source_total += size
                                continue
                            if not non_gmail_flagged_source:
                                ordinary_content_remaining_for_all[content_identity] = (
                                    ordinary_content_remaining_for_all.get(content_identity, 0) + 1
                                )
                                delivery_key = _provider_virtual_delivery_key(parsed)
                                delivery_remaining = ordinary_delivery_remaining_for_all.setdefault(content_identity, {})
                                delivery_remaining[delivery_key] = delivery_remaining.get(delivery_key, 0) + 1
                            else:
                                identity = f"{mailbox.name}:{uid}"
                                if identity in seen_identity:
                                    continue
                                seen_identity.add(identity)
                            source_total += size
                            continue
                        identity = (
                            str(parsed.get("gmail_msgid") or f"{mailbox.name}:{uid}")
                            if use_gmail_metadata
                            else f"{mailbox.name}:{uid}"
                        )
                        if identity in seen_identity:
                            continue
                        seen_identity.add(identity)
                        source_total += int(parsed.get("rfc822_size") or 0)
                    for content_identity, pending_sizes in pending_all_sizes_by_content.items():
                        remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                        pending_sizes, consumed_ordinary = _uncovered_provider_virtual_items(
                            pending_sizes,
                            remaining_ordinary=remaining_ordinary,
                            ordinary_delivery_remaining=ordinary_delivery_remaining_for_all.get(content_identity, {}),
                            delivery_key=lambda item: item[1],
                        )
                        ordinary_content_remaining_for_all[content_identity] = remaining_ordinary - consumed_ordinary
                        if not pending_sizes:
                            continue
                        source_total += sum(size for size, _delivery_key in pending_sizes)
        except Exception as exc:
            if _stop_requested(stop_event):
                raise
            account_issues.append(f"source preflight failed: {exc}")
        _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
        try:
            with imap_connection(config.target, acc, role="target") as target_imap:
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                target_capabilities = get_capabilities(target_imap)
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                target_mailboxes = list_mailboxes(target_imap)
                _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                if config.target.provider == "gmail":
                    account_issues.extend(gmail_target_readiness_issues(target_capabilities, target_mailboxes))
                    _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
                    account_issues.extend(gmail_all_mail_select_issues(target_imap, target_mailboxes, role="target"))
                    account_issues.extend(gmail_target_decommission_issues(config.target, acc))
                if not target_mailboxes:
                    account_issues.append("target returned no mailboxes")
        except Exception as exc:
            if _stop_requested(stop_event):
                raise
            account_issues.append(f"target preflight failed: {exc}")
        _raise_if_stopped(stop_event, f"provider preflight {acc.email}")
        if config.target.available_bytes is None:
            logging.warning("[provider-preflight] %s: target.available_bytes not configured; storage gate skipped", acc.email)
        elif not provider_account_merge_enabled(config) and source_total > config.target.available_bytes:
            account_issues.append(f"estimated source bytes {source_total} exceed target.available_bytes {config.target.available_bytes}")
        logging.info("[provider-preflight] %s: estimated_source_bytes=%d", acc.email, source_total)
        return account_issues, source_total

    merge_group_source_totals: Dict[Tuple[str, str], int] = {}
    for acc, (result, source_total) in _provider_account_worker_results("provider-preflight", config.accounts, max_workers, worker, stop_event):
        issues.extend(f"{acc.email}: {issue}" for issue in result)
        if provider_account_merge_enabled(config) and config.target.available_bytes is not None:
            target_key = target_merge_group_key(config, acc)
            merge_group_source_totals[target_key] = merge_group_source_totals.get(target_key, 0) + source_total
    _raise_if_stopped(stop_event, "provider preflight")
    if provider_account_merge_enabled(config) and config.target.available_bytes is not None:
        for target_key, source_total in sorted(merge_group_source_totals.items()):
            _raise_if_stopped(stop_event, "provider preflight")
            if source_total > config.target.available_bytes:
                issues.append(
                    f"target merge group {target_key[0]}: estimated source bytes {source_total} "
                    f"exceed target.available_bytes {config.target.available_bytes}"
                )
    return len(issues) == 0, issues


def _append_unique(values: List[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _stop_requested(stop_event: Optional[object]) -> bool:
    return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())


def _raise_if_stopped(stop_event: Optional[object], label: str) -> None:
    if _stop_requested(stop_event):
        raise RuntimeError(f"{label}: stop requested before completion")


def _require_max_workers(max_workers: int) -> int:
    max_workers = int(max_workers)
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    return max_workers


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
