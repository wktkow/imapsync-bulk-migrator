from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import errno
import fcntl
import hashlib
import imaplib
import itertools
import json
import logging
import os
import re
import socket
import ssl
import stat
import sys
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
from .imap_ops import (
    _imap_append_wire_bytes,
    _legacy_internaldate_for_append,
    _legacy_internaldate_utc_key,
    _legacy_internaldates_equal,
    _normalized_legacy_internaldate,
    _valid_legacy_flag_token,
    _valid_legacy_internaldate,
)
from .models import (
    AuthConfig,
    MigrationAccount,
    ProviderEndpoint,
    ProviderMigrationConfig,
    auth_username_identity,
)
from .routing import (
    CUSTOM_LABEL,
    GENERIC_MAILBOX,
    GMAIL_EXCLUSIVE_PRIMARY_ROLES,
    GMAIL_SYSTEM,
    RoutingPlan,
    SourceFolder,
    TargetLabel,
    gmail_incompatible_system_roles,
    resolve_routing_plan,
)
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
ROUTING_PLAN_FILENAME = "routing-plan.json"
_ROUTING_EXACT_TARGET_MAILBOX_FIELD = "routing_exact_target_mailbox"
IMPORT_LOCK_DIRNAME = ".import-locks"
PROVIDER_WORKFLOW_LOCK_FILENAME = "provider-workflow.lock"
IMPORT_LOCK_WAIT_SECONDS = 0.1
EXISTING_CONTENT_REUSE_INTERNALDATE_PROVENANCE = "existing-content-reuse"
_EXISTING_CONTENT_REUSE_INTERNALDATE_FIELDS = (
    "source_internaldate",
    "target_internaldate",
    "internaldate_provenance",
    "internaldate_origin_action",
)
_EXISTING_CONTENT_REUSE_FOLLOWUP_ACTIONS = frozenset(
    {"existing", "labels-reconciled", "route-verified", "verified"}
)
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


class ProviderImportIntegrityGateError(RuntimeError):
    """A read-only provider import evidence gate rejected target progression."""


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
        _raise_if_provider_parent_replaced(dir_path, dir_fd, "directory")
        _secure_provider_private_dir_fd(dir_fd, dir_path, "directory")
        _raise_if_provider_parent_replaced(dir_path, dir_fd, "directory")
    finally:
        os.close(dir_fd)


def _provider_effective_uid() -> int:
    get_effective_uid = getattr(os, "geteuid", None)
    if not callable(get_effective_uid):
        raise RuntimeError("platform does not expose an effective UID for provider artifact ownership checks")
    try:
        return int(get_effective_uid())
    except OSError as exc:
        raise RuntimeError("unable to determine effective UID for provider artifact ownership checks") from exc


def _secure_provider_private_dir_fd(dir_fd: int, path: Path, label: str) -> None:
    if path == Path(path.anchor):
        raise RuntimeError(f"refusing to secure provider {label} filesystem root: {path}")
    stat_result = os.fstat(dir_fd)
    if not stat.S_ISDIR(stat_result.st_mode):
        raise RuntimeError(f"provider {label} path is not a directory: {path}")
    effective_uid = _provider_effective_uid()
    if stat_result.st_uid != effective_uid:
        raise RuntimeError(
            f"refusing to secure provider {label} not owned by effective UID {effective_uid}: "
            f"{path} (owner UID {stat_result.st_uid})"
        )
    mode = stat.S_IMODE(stat_result.st_mode)
    unsafe_shared_bits = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    if mode & unsafe_shared_bits:
        raise RuntimeError(f"refusing to secure shared provider {label} directory: {path} (mode {mode:#05o})")
    try:
        os.fchmod(dir_fd, PRIVATE_DIR_MODE)
    except OSError as exc:
        raise RuntimeError(f"unable to set private permissions on provider {label} directory: {path}") from exc
    final_stat = os.fstat(dir_fd)
    final_mode = stat.S_IMODE(final_stat.st_mode)
    if not stat.S_ISDIR(final_stat.st_mode):
        raise RuntimeError(f"provider {label} path is no longer a directory: {path}")
    if final_stat.st_uid != effective_uid:
        raise RuntimeError(
            f"provider {label} ownership changed while securing {path}: "
            f"expected UID {effective_uid}, found {final_stat.st_uid}"
        )
    if final_mode != PRIVATE_DIR_MODE:
        raise RuntimeError(
            f"provider {label} directory permissions are not private: "
            f"{path} (expected {PRIVATE_DIR_MODE:#05o}, found {final_mode:#05o})"
        )


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
    if not endpoint.ssl and not endpoint.starttls:
        raise RuntimeError("refusing to send IMAP authentication credentials over a cleartext connection; enable SSL or STARTTLS")
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


def _non_gmail_foldable_virtual_membership(
    provider_key: str,
    mailbox: MailboxInfo,
    *,
    routed_memberships: bool,
) -> str:
    """Return the generic virtual-view kind that may fold into a real row.

    ``\\Flagged`` folding predates routing plans.  ``\\Starred`` and
    ``\\Important`` are folded only for routing-plan v2 exports, where every
    selectable source membership is part of the frozen routing contract.
    """

    if provider_key == "gmail":
        return ""
    attributes = _mailbox_attrs(mailbox)
    if "\\flagged" in attributes:
        return "flagged"
    if routed_memberships and "\\starred" in attributes:
        return "starred"
    if routed_memberships and "\\important" in attributes:
        return "important"
    return ""


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


def _source_mailbox_scan_order(
    provider_key: str,
    mailboxes: List[MailboxInfo],
    *,
    routed_virtual_memberships: bool = False,
) -> List[MailboxInfo]:
    indexed = list(enumerate(mailboxes))
    indexed.sort(
        key=lambda item: (
            2
            if _non_gmail_foldable_virtual_membership(
                provider_key,
                item[1],
                routed_memberships=routed_virtual_memberships,
            )
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


def _routing_exact_target_mailbox(row: Dict[str, Any]) -> Optional[str]:
    """Return the frozen generic mailbox target carried by a routed row."""

    if row.get("routing_active") is not True:
        return None
    target = row.get(_ROUTING_EXACT_TARGET_MAILBOX_FIELD)
    if not isinstance(target, str) or not target:
        return None
    return target


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
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
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
    if not isinstance(gmail_msgid, str):
        return ""
    msgid = _valid_gmail_uint64(gmail_msgid)
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
    raw_gmail_msgid = parsed.get("gmail_msgid") if use_gmail_msgid else None
    gmail_msgid = (
        raw_gmail_msgid
        if isinstance(raw_gmail_msgid, str)
        and _valid_gmail_uint64(raw_gmail_msgid) == raw_gmail_msgid
        else ""
    )
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


def _atomic_json_create_once(path: Path, payload: Dict[str, Any]) -> bool:
    return _atomic_bytes_create_once(
        path,
        (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"),
    )


def _rename_provider_entry_create_once(parent_fd: int, source: str, destination: str) -> bool:
    """Atomically rename within ``parent_fd`` without replacing a winner."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename_no_replace = getattr(libc, "renameatx_np", None)
        no_replace_flag = 0x00000004  # RENAME_EXCL
    else:
        rename_no_replace = getattr(libc, "renameat2", None)
        no_replace_flag = 1  # RENAME_NOREPLACE
    if rename_no_replace is None:
        raise RuntimeError(
            "platform does not support atomic no-replace rename for create-once publication"
        )
    rename_no_replace.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename_no_replace.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename_no_replace(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        no_replace_flag,
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise RuntimeError(
            "platform or filesystem does not support atomic no-replace rename "
            "for create-once publication"
        )
    raise OSError(error, os.strerror(error), destination)


def _atomic_bytes_create_once(path: Path, payload: bytes) -> bool:
    """Publish a complete private file only when the destination is absent.

    Atomic no-replace rename selects one concurrent winner and publishes its
    fully synced temporary inode.  Unlike link-based publication, the final
    pathname is therefore never observable with ``st_nlink == 2``.
    """

    ensure_private_dir(path.parent)
    parent_fd, name, parent_path = _open_provider_parent_dir(path, "file")
    tmp_name = f".{name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp"
    tmp_stat: Optional[os.stat_result] = None
    published = False
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
                raise RuntimeError(
                    f"refusing to use unsafe provider temporary file: {path.with_name(tmp_name)}"
                ) from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(
                    f"refusing to use symlinked provider temporary file: {path.with_name(tmp_name)}"
                ) from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(
                    f"refusing to use non-regular provider temporary file: {path.with_name(tmp_name)}"
                ) from exc
            raise
        try:
            with os.fdopen(fd, "wb") as f:
                os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
                tmp_stat = os.fstat(f.fileno())
            if tmp_stat is None or not stat.S_ISREG(tmp_stat.st_mode):
                raise RuntimeError(f"refusing to publish non-regular provider file: {path}")
            if getattr(tmp_stat, "st_nlink", 1) != 1:
                raise RuntimeError(f"refusing to publish hard-linked provider file: {path}")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            if not _rename_provider_entry_create_once(parent_fd, tmp_name, name):
                _unlink_provider_entry_and_fsync(parent_fd, tmp_name, parent_path, "file")
                tmp_name = ""
                _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
                return False
            tmp_name = ""
            published = True
            final_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(final_stat.st_mode)
                or final_stat.st_dev != tmp_stat.st_dev
                or final_stat.st_ino != tmp_stat.st_ino
                or getattr(final_stat, "st_nlink", 1) != 1
                or stat.S_IMODE(final_stat.st_mode) != PRIVATE_FILE_MODE
            ):
                raise RuntimeError(f"refusing to use unsafe published provider file: {path}")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            _fsync_provider_directory_fd(parent_fd, parent_path, "file")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "file")
            return True
        except Exception:
            if published:
                with contextlib.suppress(OSError):
                    final_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (
                        tmp_stat is not None
                        and final_stat.st_dev == tmp_stat.st_dev
                        and final_stat.st_ino == tmp_stat.st_ino
                    ):
                        _unlink_provider_entry_and_fsync(parent_fd, name, parent_path, "file")
            if tmp_name:
                _unlink_provider_entry_and_fsync(parent_fd, tmp_name, parent_path, "file")
            raise
    finally:
        os.close(parent_fd)


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
    routing_plan_sha256: Optional[str] = None,
    routing_enabled: Optional[bool] = None,
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
            routing_plan_sha256=routing_plan_sha256,
            routing_enabled=routing_enabled,
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
    routing_plan_sha256: Optional[str] = None,
    routing_enabled: Optional[bool] = None,
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
    state_routing_digest = state.get("routing_plan_sha256")
    if routing_enabled is False and state_routing_digest is not None:
        issues.append(
            "export-state is bound to a routing plan but migration.routing is disabled; "
            "consume this staged export with routing enabled and its persisted plan"
        )
    if routing_plan_sha256 is not None:
        if state_routing_digest != routing_plan_sha256:
            issues.append(
                "export-state routing_plan_sha256 does not match the persisted routing plan: "
                f"{state_routing_digest or '<missing>'} != {routing_plan_sha256}"
            )
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
    routing_plan_sha256: Optional[str] = None,
    routing_enabled: Optional[bool] = None,
) -> None:
    issues = provider_export_state_issues(
        account_dir,
        account=account,
        manifest_rows=manifest_rows,
        source_provider=source_provider,
        target_provider=target_provider,
        source_endpoint=source_endpoint,
        target_endpoint=target_endpoint,
        routing_plan_sha256=routing_plan_sha256,
        routing_enabled=routing_enabled,
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
            elif internaldate_raw != "" and not _valid_legacy_internaldate(internaldate_raw):
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


def merge_group_expected_identity_sets_by_target(
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
) -> Dict[str, List[List[set[Tuple[int, str]]]]]:
    """Return expected content multiplicities grouped by source and target.

    Generic IMAP messages are physical per mailbox.  Gmail message identity is
    physical across labels, so all Gmail target mailboxes share one capacity
    bucket.
    """

    grouped: Dict[str, List[List[set[Tuple[int, str]]]]] = {}
    for _group_account, _account_dir, manifest_rows, _journal_rows in stages:
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=target_provider,
        )
        source_sets_by_target: Dict[str, List[set[Tuple[int, str]]]] = {}
        for row in manifest_rows:
            identity = str(row.get("canonical_id") or "")
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not identity or not target_mailbox:
                continue
            target_key = (
                "gmail-physical-message"
                if target_provider == "gmail"
                else _target_mailbox_lookup_key(target_mailbox, target_provider)
            )
            source_sets_by_target.setdefault(target_key, []).append(
                _expected_content_identities(
                    row,
                    expected_content_identities_by_id.get(identity),
                )
            )
        for target_key, expected_sets in source_sets_by_target.items():
            grouped.setdefault(target_key, []).append(expected_sets)
    return grouped


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
    provider = (target_provider or "").lower()
    if (
        provider in {"imap", "icloud"}
        and target_mailbox.upper() == "INBOX"
        and expected_target.upper() == "INBOX"
    ):
        return True
    if provider == "gmail":
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
    exact_target_ids: Optional[set[str]] = None,
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
            may_defer = not exact_target_ids or identity not in exact_target_ids
            if (
                may_defer
                and defer_unknown_hierarchy_delimiter_ids
                and identity in defer_unknown_hierarchy_delimiter_ids
            ):
                continue
            if (
                may_defer
                and defer_generic_special_use
                and provider in {"imap", "icloud"}
                and _generic_imap_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            if (
                may_defer
                and defer_gmail_special_use
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
    exact_target_ids: Optional[set[str]] = None,
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
            may_defer = not exact_target_ids or identity not in exact_target_ids
            if (
                may_defer
                and defer_unknown_hierarchy_delimiter_ids
                and identity in defer_unknown_hierarchy_delimiter_ids
            ):
                continue
            if (
                may_defer
                and defer_generic_special_use
                and provider in {"imap", "icloud"}
                and _generic_imap_offline_target_requires_live_special_use(target_mailbox, expected_target)
            ):
                continue
            if (
                may_defer
                and defer_gmail_special_use
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
        exact_target = _routing_exact_target_mailbox(row)
        if exact_target is not None:
            expected[identity] = exact_target
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
        if _routing_exact_target_mailbox(row) is not None:
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
    exact_target_ids = {
        str(row.get("canonical_id") or "")
        for row in manifest_rows
        if row.get("canonical_id")
        and _routing_exact_target_mailbox(row) is not None
    }
    issues = committed_journal_target_mailbox_issues(
        journal_rows,
        expected,
        target_provider=target_provider,
        defer_generic_special_use=True,
        defer_gmail_special_use=True,
        defer_unknown_hierarchy_delimiter_ids=hierarchy_delimiter_dependent_ids,
        exact_target_ids=exact_target_ids,
    )
    issues.extend(
        pending_journal_target_mailbox_issues(
            journal_rows,
            expected,
            target_provider=target_provider,
            defer_generic_special_use=True,
            defer_gmail_special_use=True,
            defer_unknown_hierarchy_delimiter_ids=hierarchy_delimiter_dependent_ids,
            exact_target_ids=exact_target_ids,
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
    existing_reuse_evidence_by_key: Dict[Tuple[str, str], bool] = {}
    for row_index, journal_row in enumerate(rows, 1):
        if journal_row.get("status") != "committed":
            continue
        key = journal_row_target_key(
            journal_row,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        identity, target_mailbox = key
        if not identity or not target_mailbox:
            continue
        manifest_row = manifest_by_id.get(identity)
        if manifest_row is None:
            continue
        label = f"{identity} in {target_mailbox or '<missing>'}"
        has_evidence = _existing_content_reuse_internaldate_evidence_present(
            journal_row
        )
        if has_evidence:
            evidence_issue = _existing_content_reuse_internaldate_evidence_issue(
                manifest_row,
                journal_row,
            )
            if evidence_issue:
                issues.append(
                    f"journal committed INTERNALDATE evidence is invalid for {label} "
                    f"at row {row_index}: {evidence_issue}"
                )
            else:
                existing_reuse_evidence_by_key[key] = True
            continue
        action = str(journal_row.get("action") or "")
        if action == "appended":
            existing_reuse_evidence_by_key.pop(key, None)
            continue
        if (
            existing_reuse_evidence_by_key.get(key)
            and action in _EXISTING_CONTENT_REUSE_FOLLOWUP_ACTIONS
        ):
            issues.append(
                f"journal committed INTERNALDATE provenance downgrade for {label} "
                f"at row {row_index}: action {action!r} omitted previously established "
                "existing-content reuse evidence"
            )
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
        if manifest_row.get("routing_active"):
            binding_matches = (
                isinstance(journal_binding, str)
                and journal_binding == manifest_row.get(CONTENT_BINDING_FIELD)
            )
        else:
            binding_matches = (
                isinstance(journal_binding, str)
                and provider_content_binding_matches(manifest_row, journal_binding)
            )
        if not binding_matches:
            issues.append(f"journal committed {CONTENT_BINDING_FIELD} does not match manifest: {label}")
    return list(dict.fromkeys(issues))


def pending_journal_manifest_content_issues(
    rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    *,
    target_provider: str = "imap",
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[str]:
    """Validate that every latest pending APPEND still has its exact snapshot.

    A pending row is the durable record written immediately before APPEND.  It
    is useful for safe recovery only while the manifest row and its payload are
    still the exact ones whose content binding was journaled.
    """

    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    issues: List[str] = []
    latest = latest_journal_rows(
        rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    )
    for (identity, target_mailbox), journal_row in latest.items():
        if journal_row.get("status") != "pending":
            continue
        manifest_row = manifest_by_id.get(identity)
        label = f"{identity or '<missing>'} in {target_mailbox or '<missing>'}"
        if manifest_row is None:
            issues.append(f"journal pending identity not in manifest: {identity or '<missing>'}")
            continue
        journal_content_sha256 = journal_row.get("content_sha256")
        journal_size = journal_row.get("rfc822_size")
        journal_binding = journal_row.get(CONTENT_BINDING_FIELD)
        if (
            not isinstance(journal_content_sha256, str)
            or journal_content_sha256 != manifest_row.get("content_sha256")
        ):
            issues.append(f"journal pending content_sha256 does not match manifest: {label}")
        if type(journal_size) is not int or journal_size != manifest_row.get("rfc822_size"):
            issues.append(f"journal pending rfc822_size does not match manifest: {label}")
        if manifest_row.get("routing_active"):
            binding_matches = (
                isinstance(journal_binding, str)
                and journal_binding == manifest_row.get(CONTENT_BINDING_FIELD)
            )
        else:
            binding_matches = (
                isinstance(journal_binding, str)
                and provider_content_binding_matches(manifest_row, journal_binding)
            )
        if not binding_matches:
            issues.append(
                f"journal pending {CONTENT_BINDING_FIELD} does not match manifest: {label}"
            )
        if "pre_append_gmail_msgids" in journal_row:
            raw_baseline = journal_row.get("pre_append_gmail_msgids")
            canonical_baseline = (
                sorted(
                    {
                        str(value)
                        for value in raw_baseline
                        if is_valid_gmail_msgid(value)
                    },
                    key=lambda value: (len(value), value),
                )
                if isinstance(raw_baseline, list)
                else []
            )
            if (
                target_provider != "gmail"
                or not isinstance(raw_baseline, list)
                or any(not is_valid_gmail_msgid(value) for value in raw_baseline)
                or raw_baseline != canonical_baseline
            ):
                issues.append(
                    f"journal pending pre-APPEND Gmail-ID baseline is invalid: {label}"
                )
    return list(dict.fromkeys(issues))


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
    return (
        isinstance(value, str)
        and bool(value)
        and _valid_gmail_uint64(value) == value
    )


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
    latest_committed = latest_committed_journal_rows(
        repaired_rows,
        target_provider="gmail",
        target_mailboxes=target_mailboxes,
    )
    reserved_gmail_msgids = {
        str(journal_row.get("target_gmail_msgid") or "")
        for journal_row in latest_committed.values()
        if journal_row.get("target_gmail_msgid")
    }
    repair_candidates: Dict[str, Dict[str, Any]] = {}
    for (identity, _target_mailbox_key), journal_row in sorted(
        latest_committed.items()
    ):
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
        match_row = _committed_target_match_row(manifest_row, journal_row)
        expected_date_key = _legacy_internaldate_utc_key(
            match_row.get("internaldate")
        )
        matches: Dict[str, Dict[str, Any]] = {}
        for occurrence in _target_physical_occurrences_for_row(
            imap,
            manifest_row,
            search_mailbox,
            target_mailboxes or [],
            target_provider="gmail",
            expected_content_identities=(
                expected_content_identities_by_id.get(identity)
                if expected_content_identities_by_id
                else None
            ),
        ):
            gmail_msgid = str(occurrence.get("gmail_msgid") or "")
            if not gmail_msgid:
                continue
            if (
                expected_date_key
                and _legacy_internaldate_utc_key(
                    occurrence.get("internaldate")
                )
                != expected_date_key
            ):
                continue
            if manifest_row.get("routing_active") or manifest_row.get(
                "_gmail_duplicate_allocation"
            ):
                if _gmail_destination_profile_conflicts(
                    (
                        _gmail_required_destination_profile_for_row(
                            manifest_row
                        ),
                        _gmail_destination_profile_for_target_candidate(
                            manifest_row,
                            occurrence.get("gmail_label_keys") or (),
                            occurrence.get("gmail_flags") or (),
                            str(occurrence.get("mailbox") or ""),
                            gmail_msgid,
                        ),
                    )
                ):
                    continue
            matches.setdefault(gmail_msgid, occurrence)
        if not matches:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and target message was not found: "
                f"{identity} in {search_mailbox or '<missing>'}"
            )
            continue
        repair_candidates[identity] = {
            "journal_row": journal_row,
            "manifest_row": manifest_row,
            "search_mailbox": search_mailbox,
            "matches": matches,
        }

    planned_target_by_identity: Dict[str, Tuple[str, Dict[str, Any]]] = {}
    unresolved = set(repair_candidates)
    while unresolved:
        progress = False
        available_by_identity = {
            identity: {
                gmail_msgid: target_num
                for gmail_msgid, target_num in repair_candidates[identity]["matches"].items()
                if gmail_msgid not in reserved_gmail_msgids
            }
            for identity in unresolved
        }
        for identity in sorted(
            unresolved,
            key=lambda value: (len(available_by_identity[value]), value),
        ):
            available = available_by_identity[identity]
            if not available:
                details = repair_candidates[identity]
                issues.append(
                    "journal committed Gmail target row missing target_gmail_msgid and "
                    "has no unreserved target message: "
                    f"{identity} in {details['search_mailbox'] or '<missing>'}"
                )
                unresolved.remove(identity)
                progress = True
                continue
            if len(available) != 1:
                continue
            target_gmail_msgid, target_occurrence = next(iter(available.items()))
            planned_target_by_identity[identity] = (
                target_gmail_msgid,
                target_occurrence,
            )
            reserved_gmail_msgids.add(target_gmail_msgid)
            unresolved.remove(identity)
            progress = True
        if not progress:
            break
    for identity in sorted(unresolved):
        details = repair_candidates[identity]
        available = sorted(
            set(details["matches"]) - reserved_gmail_msgids,
        )
        issues.append(
            "journal committed Gmail target row missing target_gmail_msgid and matched multiple target Gmail messages: "
            f"{identity} in {details['search_mailbox']}: " + ", ".join(available)
        )
    if issues:
        raise ProviderImportIntegrityGateError(
            "invalid import journal: " + "; ".join(issues)
        )

    planned_repairs: List[Dict[str, Any]] = []
    for identity in sorted(planned_target_by_identity):
        details = repair_candidates[identity]
        journal_row = details["journal_row"]
        manifest_row = details["manifest_row"]
        search_mailbox = details["search_mailbox"]
        target_gmail_msgid, target_occurrence = planned_target_by_identity[identity]
        target_num = target_occurrence["num"]
        matched_mailbox = str(target_occurrence["mailbox"])
        actual_target_internaldate: Optional[str] = None
        internaldate_origin_action = ""
        if (
            not _existing_content_reuse_internaldate_evidence_present(journal_row)
            and journal_row.get("action") == "existing"
        ):
            status, _response = select_mailbox(
                imap,
                matched_mailbox,
                readonly=True,
            )
            if status != "OK":
                raise RuntimeError(
                    f"cannot select target mailbox {search_mailbox!r} while repairing {identity}"
                )
            actual_target_internaldate = target_message_internaldate(imap, target_num)
            internaldate_origin_action = "existing"
        planned_repairs.append(_journal_row(
            manifest_row,
            search_mailbox,
            "committed",
            "verified",
            target_binding=target_binding,
            target_gmail_msgid=target_gmail_msgid,
            internaldate_evidence_from=journal_row,
            actual_target_internaldate=actual_target_internaldate,
            internaldate_origin_action=internaldate_origin_action,
        ))
    for repaired in planned_repairs:
        append_journal(account_dir, account, repaired)
        repaired_rows.append(repaired)
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
    defer_trailing_repair: bool = False,
) -> List[Dict[str, Any]]:
    if repair_trailing and defer_trailing_repair:
        raise ValueError("journal trailing repair cannot be both applied and deferred")
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
            if repair_trailing or defer_trailing_repair:
                if repair_trailing:
                    logging.warning("[provider-import] ignoring incomplete trailing journal row: %s", path)
                    needs_rewrite = True
                break
            raise ValueError(f"{path}: journal row {line_no} is not newline-terminated")
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            if (repair_trailing or defer_trailing_repair) and line_no == len(lines):
                if repair_trailing:
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
            if (repair_trailing or defer_trailing_repair) and line_no == len(lines):
                if repair_trailing:
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


def persist_export_records(
    account_dir: Path,
    records: Dict[str, Dict[str, Any]],
    folder_map: Dict[str, str],
    *,
    preserve_exact_identities: Optional[set[str]] = None,
) -> None:
    preserve_exact_identities = preserve_exact_identities or set()
    for identity, record in records.items():
        if identity in preserve_exact_identities:
            continue
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
    internaldate = parsed.get("internaldate")
    return (
        tuple(sorted(_provider_export_flag_set(parsed.get("flags")))),
        _legacy_internaldate_utc_key(internaldate) or _normalized_provider_internaldate(internaldate),
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
    routing_plan: Optional[RoutingPlan] = None,
) -> None:
    if config.migration.routing.enabled:
        if routing_plan is None:
            raise RuntimeError("routing-enabled export requires a resolved preflight routing plan")
        validate_provider_routing_plan(config, routing_plan)
    elif routing_plan is not None:
        raise RuntimeError("routing plan supplied for a migration with routing disabled")
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
    retained_committed_identities: set[str] = set()
    retained_pending_identities: set[str] = set()
    retained_recovery_identities: set[str] = set()
    recovery_snapshot_by_identity: Dict[str, Dict[str, Any]] = {}
    source_drift_warnings_by_identity: Dict[str, Dict[str, Any]] = {}
    previous_rows_by_identity: Dict[str, Dict[str, Any]] = {}
    previous_uidvalidities_by_mailbox: Dict[str, set[str]] = {}
    ordinary_content_remaining_for_all: Dict[Tuple[int, str], int] = {}
    ordinary_delivery_remaining_for_all: Dict[Tuple[int, str], Dict[_ProviderVirtualDeliveryKey, int]] = {}
    ordinary_delivery_identities_for_all: Dict[
        Tuple[int, str],
        Dict[_ProviderVirtualDeliveryKey, List[str]],
    ] = {}
    mergeable_provider_records_by_content: Dict[Tuple[int, str], List[Tuple[str, str]]] = {}
    routed_virtual_membership_consumed_by_mailbox: Dict[str, set[str]] = {}
    scanned_uidvalidity_by_mailbox: Dict[str, str] = {}
    exported_delivery_by_mailbox_uid: Dict[str, Dict[int, Dict[str, Any]]] = {}
    existing_journal_rows: List[Dict[str, Any]] = []
    if account_dir.exists():
        try:
            existing_journal_rows = load_import_journal(
                account_dir,
                account,
                repair_trailing=False,
            )
        except Exception as exc:
            raise RuntimeError(
                f"cannot validate committed export evidence because the import journal is invalid: {exc}"
            ) from exc
        require_valid_import_journal(existing_journal_rows, account)
        journal_target_issues = journal_target_endpoint_issues(
            existing_journal_rows,
            config=config,
            account=account,
        )
        if journal_target_issues:
            raise RuntimeError("invalid import journal: " + "; ".join(journal_target_issues))
        journal_requires_manifest = bool(
            latest_committed_journal_rows(
                existing_journal_rows,
                target_provider=config.target.provider,
            )
            or any(
                row.get("status") == "pending"
                for row in latest_journal_rows(
                    existing_journal_rows,
                    target_provider=config.target.provider,
                ).values()
            )
        )
        if not manifest_path.exists() and journal_requires_manifest:
            raise RuntimeError(
                "invalid recovery export evidence: import journal contains committed or pending rows "
                "but the manifest is missing"
            )
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
            routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
            routing_enabled=config.migration.routing.enabled,
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
                routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
                routing_enabled=config.migration.routing.enabled,
            )
            if state_issues:
                raise RuntimeError("; ".join(state_issues))
            preserve_complete_state_until_ready = True
            trusted_payload_identities.update(messages)

        retained_committed_identities = {
            identity
            for identity, _target_mailbox in latest_committed_journal_rows(
                existing_journal_rows,
                target_provider=config.target.provider,
            )
            if identity
        }
        retained_pending_identities = {
            identity
            for (identity, _target_mailbox), row in latest_journal_rows(
                existing_journal_rows,
                target_provider=config.target.provider,
            ).items()
            if identity and row.get("status") == "pending"
        }
        retained_recovery_identities = (
            retained_committed_identities | retained_pending_identities
        )
        retained_rows = [
            row
            for row in existing_rows
            if str(row.get("canonical_id") or "") in retained_recovery_identities
        ]
        retained_evidence_rows = retained_rows
        retained_evidence_issues: List[str] = []
        retained_evidence_issues.extend(manifest_schema_issues(retained_rows))
        retained_evidence_issues.extend(manifest_integrity_issues(retained_rows))
        retained_evidence_issues.extend(provider_delivery_metadata_issues(retained_rows))
        retained_evidence_issues.extend(metadata_manifest_issues(account_dir, retained_rows))
        retained_evidence_issues.extend(manifest_payload_issues(account_dir, retained_rows))
        if routing_plan is not None and retained_recovery_identities:
            try:
                retained_evidence_rows, _excluded = routed_manifest_rows(
                    config,
                    account,
                    retained_rows,
                    routing_plan,
                )
            except Exception as exc:
                retained_evidence_issues.append(
                    f"committed routing evidence is invalid: {exc}"
                )
            else:
                retained_evidence_issues.extend(
                    routing_committed_journal_issues(
                        existing_journal_rows,
                        retained_evidence_rows,
                        target_provider=config.target.provider,
                    )
                )
        retained_evidence_issues.extend(
            committed_journal_manifest_content_issues(
                existing_journal_rows,
                retained_evidence_rows,
                target_provider=config.target.provider,
            )
        )
        retained_evidence_issues.extend(
            pending_journal_manifest_content_issues(
                existing_journal_rows,
                retained_evidence_rows,
                target_provider=config.target.provider,
            )
        )
        if config.target.provider == "gmail":
            retained_evidence_issues.extend(
                invalid_journal_target_gmail_msgid_issues(
                    existing_journal_rows,
                    manifest_ids=retained_committed_identities,
                )
            )
            retained_evidence_issues.extend(
                issue
                for issue in duplicate_journal_target_gmail_msgid_issues(
                    existing_journal_rows,
                    manifest_ids=retained_committed_identities,
                )
            )
        if retained_evidence_issues:
            evidence_kind = (
                "committed"
                if retained_committed_identities and not retained_pending_identities
                else "recovery"
            )
            raise RuntimeError(
                f"invalid {evidence_kind} export evidence: "
                + "; ".join(str(issue) for issue in retained_evidence_issues)
            )
        recovery_snapshot_by_identity = {
            identity: dict(previous_rows_by_identity[identity])
            for identity in retained_recovery_identities
            if identity in previous_rows_by_identity
        }

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
                **(
                    {"routing_plan_sha256": routing_plan.mapping_digest}
                    if routing_plan is not None
                    else {}
                ),
            },
        )

    if not preserve_complete_state_until_ready:
        write_in_progress_state()
    limiter = limiter or RateLimiter(config.limits.throttle.max_bytes_per_second)
    scope_gmail_source_identity = provider_account_merge_enabled(config)

    def update_membership(identity: str, mailbox: MailboxInfo, uid: int, uidvalidity: str, parsed: Dict[str, Any]) -> None:
        if identity in recovery_snapshot_by_identity:
            active_identities.add(identity)
            return
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
        records = {
            identity: messages[identity]
            for identity in sorted(active_identities)
            if identity in messages
        }
        for identity, recovery_snapshot in sorted(
            recovery_snapshot_by_identity.items()
        ):
            records[identity] = recovery_snapshot
        return records

    def persist_active_export_records() -> None:
        persist_export_records(
            account_dir,
            active_export_records(),
            config.migration.folder_map,
            preserve_exact_identities=retained_recovery_identities,
        )

    def record_committed_source_drift(
        identity: str,
        parsed: Dict[str, Any],
        *,
        content_sha256: Optional[str] = None,
        rfc822_size: Optional[int] = None,
    ) -> None:
        snapshot = recovery_snapshot_by_identity.get(identity)
        if snapshot is None:
            return
        if rfc822_size is None and type(parsed.get("rfc822_size")) is int:
            rfc822_size = int(parsed["rfc822_size"])
        changed_fields: List[str] = []
        if (
            content_sha256 is not None
            and content_sha256 != snapshot.get("content_sha256")
        ):
            changed_fields.append("content_sha256")
        if (
            rfc822_size is not None
            and rfc822_size != snapshot.get("rfc822_size")
        ):
            changed_fields.append("rfc822_size")
        if _provider_export_flag_set(parsed.get("flags")) != _provider_export_flag_set(
            snapshot.get("flags")
        ):
            changed_fields.append("flags")
        source_internaldate = _normalized_provider_internaldate(
            parsed.get("internaldate")
        )
        snapshot_internaldate = _normalized_provider_internaldate(
            snapshot.get("internaldate")
        )
        if (
            source_internaldate
            and snapshot_internaldate
            and not _legacy_internaldates_equal(
                source_internaldate,
                snapshot_internaldate,
            )
        ):
            changed_fields.append("internaldate")
        if not changed_fields:
            return
        fields = sorted(set(changed_fields))
        committed_snapshot = identity in retained_committed_identities
        message = (
            f"Source data for committed message {identity} changed in "
            f"{', '.join(fields)}; the exact committed export snapshot was retained."
            if committed_snapshot
            else f"Source data for pending APPEND recovery message {identity} changed in "
            f"{', '.join(fields)}; the exact pending recovery snapshot was retained."
        )
        warning = {
            "code": "committed-source-drift" if committed_snapshot else "pending-source-drift",
            "canonical_id": identity,
            "fields": fields,
            "message": message,
        }
        previous_warning = source_drift_warnings_by_identity.get(identity)
        source_drift_warnings_by_identity[identity] = warning
        if previous_warning != warning:
            logging.warning(
                "[provider-export] %s: %s",
                account.source_email,
                warning["message"],
            )

    def remember_provider_mergeable_record(identity: str, content_identity: Tuple[int, str]) -> None:
        record = messages.get(identity)
        if not record:
            return
        entries = mergeable_provider_records_by_content.setdefault(content_identity, [])
        if any(existing_identity == identity for existing_identity, _internaldate in entries):
            return
        entries.append((identity, str(record.get("internaldate") or "")))

    def merge_covered_provider_virtual_membership(
        content_identity: Tuple[int, str],
        virtual_kind: str,
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
        already_consumed = (
            routed_virtual_membership_consumed_by_mailbox.setdefault(
                mailbox.name,
                set(),
            )
            if routing_plan is not None
            else set()
        )
        same_date_identities = [
            identity
            for identity, candidate_internaldate in mergeable_provider_records_by_content.get(content_identity, [])
            if _legacy_internaldates_equal(candidate_internaldate, flagged_internaldate)
            and identity not in already_consumed
        ]
        if len(same_date_identities) != 1:
            return False
        target_identity = same_date_identities[0]
        if routing_plan is not None:
            already_consumed.add(target_identity)
        record = messages[target_identity]
        if virtual_kind != "important":
            merged_flags = _merge_provider_export_flag_strings(
                record.get("flags"),
                flags,
            )
            if merged_flags != str(record.get("flags") or ""):
                record["flags"] = merged_flags
        update_membership(target_identity, mailbox, uid, uidvalidity, parsed)
        persist_active_export_records()
        previous_rows_by_identity[target_identity] = dict(messages[target_identity])
        trusted_payload_identities.add(target_identity)
        return True

    def bind_covered_routed_all_memberships(
        content_identity: Tuple[int, str],
        pending_items: List[
            Tuple[str, str, str, Dict[str, Any], bytes, MailboxInfo, int, str]
        ],
        *,
        remaining_ordinary: int,
    ) -> Tuple[
        List[Tuple[str, str, str, Dict[str, Any], bytes, MailboxInfo, int, str]],
        int,
    ]:
        """Bind covered ``\\All`` deliveries to ordinary physical rows.

        This path is routing-v2-only.  Each exact content/delivery occurrence
        consumes one ordinary identity in deterministic source scan order and
        records the virtual mailbox membership without writing another
        payload.  The legacy/non-routing covered-marker behavior remains in
        ``_uncovered_provider_virtual_items``.
        """

        kept: List[
            Tuple[str, str, str, Dict[str, Any], bytes, MailboxInfo, int, str]
        ] = []
        consumed = 0
        identities_by_delivery = ordinary_delivery_identities_for_all.get(
            content_identity,
            {},
        )
        consumed_by_delivery: Dict[_ProviderVirtualDeliveryKey, int] = {}
        changed_identities: set[str] = set()
        for item in pending_items:
            parsed = item[3]
            delivery_key = _provider_virtual_delivery_key(parsed)
            candidate_identities = identities_by_delivery.get(delivery_key, [])
            delivery_index = consumed_by_delivery.get(delivery_key, 0)
            if (
                consumed < remaining_ordinary
                and delivery_index < len(candidate_identities)
            ):
                target_identity = candidate_identities[delivery_index]
                consumed_by_delivery[delivery_key] = delivery_index + 1
                update_membership(
                    target_identity,
                    item[5],
                    item[6],
                    item[7],
                    parsed,
                )
                changed_identities.add(target_identity)
                consumed += 1
            else:
                kept.append(item)
        if changed_identities:
            persist_active_export_records()
            for target_identity in sorted(changed_identities):
                if target_identity in messages:
                    previous_rows_by_identity[target_identity] = dict(
                        messages[target_identity]
                    )
                    trusted_payload_identities.add(target_identity)
        return kept, consumed

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
        if identity in recovery_snapshot_by_identity:
            record_committed_source_drift(
                identity,
                parsed,
                content_sha256=sha256,
                rfc822_size=int(parsed.get("rfc822_size") or len(msg_bytes)),
            )
            trusted_payload_identities.add(identity)
            update_membership(identity, mailbox, uid, uidvalidity, parsed)
            persist_active_export_records()
            return
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
        persist_active_export_records()
        previous_rows_by_identity[identity] = dict(messages[identity])

    with imap_connection(config.source, account, role="source") as imap:
        capabilities = get_capabilities(imap)
        use_gmail_metadata = config.source.provider == "gmail"
        gmail_extensions = use_gmail_metadata and "X-GM-EXT-1" in capabilities
        mailboxes = list_mailboxes(imap)
        if routing_plan is not None:
            actual_source_folders = _routing_source_folders(
                account,
                mailboxes,
                source_provider=config.source.provider,
            )
            expected_source_folders = sorted(
                (
                    entry.source
                    for entry in routing_plan.entries
                    if entry.source.source_account.casefold() == account.source_email.casefold()
                ),
                key=lambda folder: (folder.name.casefold(), folder.name),
            )
            actual_source_folders = sorted(
                actual_source_folders,
                key=lambda folder: (folder.name.casefold(), folder.name),
            )
            if actual_source_folders != expected_source_folders:
                raise RuntimeError(
                    f"source folder discovery changed for {account.source_email} after routing preflight; "
                    "rerun preflight and review the new plan before exporting"
                )
        _atomic_json(
            account_dir / "source-summary.json",
            {
                "source_account": account.source_email,
                "source_provider": config.source.provider,
                "capabilities": capabilities,
                "mailboxes": [m.__dict__ for m in mailboxes],
                "exported_at": _utc_now(),
                **(
                    {"routing_plan_sha256": routing_plan.mapping_digest}
                    if routing_plan is not None
                    else {}
                ),
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
        for mailbox in _source_mailbox_scan_order(
            provider_key,
            mailboxes,
            routed_virtual_memberships=routing_plan is not None,
        ):
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
                                record_committed_source_drift(
                                    identity_hint,
                                    pre_parsed,
                                )
                                if identity_hint not in recovery_snapshot_by_identity:
                                    _refresh_export_delivery_metadata(
                                        messages[identity_hint],
                                        pre_parsed,
                                    )
                                update_membership(identity_hint, mailbox, uid, uidvalidity, pre_parsed)
                                record_export_delivery_snapshot(mailbox.name, int(uid), pre_parsed)
                                persist_active_export_records()
                                if identity_hint not in recovery_snapshot_by_identity:
                                    previous_rows_by_identity[identity_hint] = dict(
                                        messages[identity_hint]
                                    )
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
                non_gmail_virtual_source = _non_gmail_foldable_virtual_membership(
                    provider_key,
                    mailbox,
                    routed_memberships=routing_plan is not None,
                )
                if non_gmail_all_source:
                    if routing_plan is not None:
                        pending_all_messages_by_content.setdefault(
                            content_identity,
                            [],
                        ).append(
                            (
                                identity,
                                sha256,
                                message_id,
                                parsed,
                                msg_bytes,
                                mailbox,
                                uid,
                                uidvalidity,
                            )
                        )
                        continue
                    remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                    if remaining_ordinary > 0:
                        pending_all_messages_by_content.setdefault(content_identity, []).append(
                            (identity, sha256, message_id, parsed, msg_bytes, mailbox, uid, uidvalidity)
                        )
                        continue
                if non_gmail_virtual_source and merge_covered_provider_virtual_membership(
                    content_identity,
                    non_gmail_virtual_source,
                    str(parsed.get("flags") or ""),
                    str(parsed.get("internaldate") or ""),
                    mailbox,
                    uid,
                    uidvalidity,
                    parsed,
                ):
                    continue
                persist_fetched_message(identity, sha256, message_id, parsed, msg_bytes, mailbox, uid, uidvalidity)
                if provider_key != "gmail" and not non_gmail_all_source and not non_gmail_virtual_source:
                    ordinary_content_remaining_for_all[content_identity] = (
                        ordinary_content_remaining_for_all.get(content_identity, 0) + 1
                    )
                    delivery_key = _provider_virtual_delivery_key(parsed)
                    delivery_remaining = ordinary_delivery_remaining_for_all.setdefault(content_identity, {})
                    delivery_remaining[delivery_key] = delivery_remaining.get(delivery_key, 0) + 1
                    if routing_plan is not None:
                        ordinary_delivery_identities_for_all.setdefault(
                            content_identity,
                            {},
                        ).setdefault(delivery_key, []).append(identity)
                if not non_gmail_virtual_source:
                    remember_provider_mergeable_record(identity, content_identity)
            for content_identity, pending_messages in pending_all_messages_by_content.items():
                remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                if routing_plan is not None:
                    remaining_ordinary = sum(
                        len(identities)
                        for identities in ordinary_delivery_identities_for_all.get(
                            content_identity,
                            {},
                        ).values()
                    )
                    (
                        pending_messages,
                        consumed_ordinary,
                    ) = bind_covered_routed_all_memberships(
                        content_identity,
                        pending_messages,
                        remaining_ordinary=remaining_ordinary,
                    )
                else:
                    pending_messages, consumed_ordinary = _uncovered_provider_virtual_items(
                        pending_messages,
                        remaining_ordinary=remaining_ordinary,
                        ordinary_delivery_remaining=ordinary_delivery_remaining_for_all.get(content_identity, {}),
                        delivery_key=lambda item: _provider_virtual_delivery_key(item[3]),
                    )
                if routing_plan is None:
                    ordinary_content_remaining_for_all[content_identity] = (
                        remaining_ordinary - consumed_ordinary
                    )
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
                    if routing_plan is not None:
                        delivery_key = _provider_virtual_delivery_key(parsed)
                        ordinary_delivery_identities_for_all.setdefault(
                            content_identity,
                            {},
                        ).setdefault(delivery_key, []).append(identity)
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
    persist_export_records(
        account_dir,
        final_records,
        config.migration.folder_map,
        preserve_exact_identities=retained_recovery_identities,
    )
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
            **(
                {
                    "warnings": [
                        source_drift_warnings_by_identity[identity]
                        for identity in sorted(source_drift_warnings_by_identity)
                    ]
                }
                if source_drift_warnings_by_identity
                else {}
            ),
            **(
                {"routing_plan_sha256": routing_plan.mapping_digest}
                if routing_plan is not None
                else {}
            ),
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
    routing_plan: Optional[RoutingPlan] = None,
) -> None:
    max_workers = _require_max_workers(max_workers)
    root_fd, root_path = _open_or_create_provider_dir(out_root, "export root")
    try:
        _raise_if_provider_parent_replaced(root_path, root_fd, "export root")
    finally:
        os.close(root_fd)
    routing_plan = _effective_provider_routing_plan(
        config,
        out_root,
        routing_plan,
        persist=True,
    )
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider export {acc.source_email}")
        with_retry(
            lambda: provider_export_account(
                config,
                acc,
                out_root,
                stop_event=stop_event,
                limiter=limiter,
                routing_plan=routing_plan,
            ),
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


def resolve_target_mailbox(
    desired: str,
    mailboxes: List[MailboxInfo],
    *,
    target_provider: str = "imap",
    exact: bool = False,
) -> str:
    provider = (target_provider or "imap").lower()
    by_name = _target_mailboxes_by_name(mailboxes, target_provider=provider)
    desired_name = str(desired)
    desired_key = _target_mailbox_lookup_key(desired, provider)
    if exact:
        mailbox = by_name.get(desired_key)
        return mailbox.name if mailbox is not None else desired_name
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


def _resolved_target_mailbox_for_row(
    row: Dict[str, Any],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> str:
    exact_target = _routing_exact_target_mailbox(row)
    if exact_target is not None:
        return resolve_target_mailbox(
            exact_target,
            target_mailboxes,
            target_provider=target_provider,
            exact=True,
        )
    desired = translate_source_mailbox_for_target(
        row,
        str(row.get("primary_mailbox") or "Archive"),
        target_mailboxes,
        target_provider=target_provider,
    )
    return resolve_target_mailbox(
        desired,
        target_mailboxes,
        target_provider=target_provider,
    )


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
    return _normalized_legacy_internaldate(value)


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


def _existing_content_reuse_internaldate_evidence_present(
    journal_row: Dict[str, Any],
) -> bool:
    return any(field in journal_row for field in _EXISTING_CONTENT_REUSE_INTERNALDATE_FIELDS)


def _existing_content_reuse_internaldate_evidence_issue(
    manifest_row: Dict[str, Any],
    journal_row: Dict[str, Any],
) -> Optional[str]:
    """Validate the narrow metadata exception for a content-first reuse."""

    if not _existing_content_reuse_internaldate_evidence_present(journal_row):
        return None
    if journal_row.get("status") != "committed":
        return "existing-content INTERNALDATE evidence is present on a non-committed row"
    action = journal_row.get("action")
    if action not in _EXISTING_CONTENT_REUSE_FOLLOWUP_ACTIONS:
        return f"existing-content INTERNALDATE evidence has invalid action {action!r}"
    if journal_row.get("internaldate_origin_action") != "existing":
        return "existing-content INTERNALDATE evidence is missing origin action 'existing'"
    if (
        journal_row.get("internaldate_provenance")
        != EXISTING_CONTENT_REUSE_INTERNALDATE_PROVENANCE
    ):
        return "existing-content INTERNALDATE evidence has invalid provenance"

    source_internaldate = journal_row.get("source_internaldate")
    target_internaldate = journal_row.get("target_internaldate")
    if not isinstance(source_internaldate, str) or not _valid_legacy_internaldate(
        source_internaldate
    ):
        return "existing-content INTERNALDATE evidence has invalid source_internaldate"
    if not isinstance(target_internaldate, str) or not _valid_legacy_internaldate(
        target_internaldate
    ):
        return "existing-content INTERNALDATE evidence has invalid target_internaldate"

    manifest_internaldate = manifest_row.get("internaldate")
    if not _legacy_internaldates_equal(source_internaldate, manifest_internaldate):
        return "existing-content source_internaldate does not match manifest"
    if not _legacy_internaldates_equal(journal_row.get("internaldate"), manifest_internaldate):
        return "existing-content journal internaldate does not match manifest"
    if _legacy_internaldates_equal(source_internaldate, target_internaldate):
        return "existing-content INTERNALDATE evidence does not record a divergence"
    return None


def _existing_content_reuse_target_internaldate(
    manifest_row: Dict[str, Any],
    journal_row: Dict[str, Any],
) -> Optional[str]:
    if not _existing_content_reuse_internaldate_evidence_present(journal_row):
        return None
    if _existing_content_reuse_internaldate_evidence_issue(manifest_row, journal_row):
        return None
    return _normalized_provider_internaldate(journal_row.get("target_internaldate"))


def _committed_target_match_row(
    manifest_row: Dict[str, Any],
    journal_row: Dict[str, Any],
) -> Dict[str, Any]:
    target_internaldate = _existing_content_reuse_target_internaldate(
        manifest_row,
        journal_row,
    )
    if not target_internaldate:
        return manifest_row
    match_row = dict(manifest_row)
    match_row["internaldate"] = target_internaldate
    return match_row


def _existing_content_reuse_internaldate_fields(
    manifest_row: Dict[str, Any],
    actual_target_internaldate: str,
) -> Dict[str, str]:
    source_internaldate = _normalized_provider_internaldate(
        manifest_row.get("internaldate")
    )
    target_internaldate = _normalized_provider_internaldate(actual_target_internaldate)
    if not source_internaldate:
        return {}
    if not _valid_legacy_internaldate(source_internaldate):
        raise RuntimeError("invalid source INTERNALDATE for existing-content reuse")
    if not target_internaldate:
        raise RuntimeError("missing target INTERNALDATE for existing-content reuse")
    if not _valid_legacy_internaldate(target_internaldate):
        raise RuntimeError("invalid target INTERNALDATE for existing-content reuse")
    if _legacy_internaldates_equal(source_internaldate, target_internaldate):
        return {}
    return {
        "source_internaldate": source_internaldate,
        "target_internaldate": target_internaldate,
        "internaldate_provenance": EXISTING_CONTENT_REUSE_INTERNALDATE_PROVENANCE,
        "internaldate_origin_action": "existing",
    }


def _existing_content_reuse_internaldate_warning(
    *,
    identity: str,
    target_mailbox: str,
    manifest_row: Dict[str, Any],
    journal_row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    target_internaldate = _existing_content_reuse_target_internaldate(
        manifest_row,
        journal_row,
    )
    if not target_internaldate:
        return None
    source_internaldate = _normalized_provider_internaldate(
        manifest_row.get("internaldate")
    )
    message = (
        f"Existing byte-identical target message reused for {identity} in {target_mailbox}; "
        f"target INTERNALDATE {target_internaldate!r} differs from source "
        f"{source_internaldate!r}, so source date metadata was not preserved and no "
        "duplicate was appended."
    )
    return {
        "code": "existing-target-internaldate-differs",
        "canonical_id": identity,
        "target_mailbox": target_mailbox,
        "source_internaldate": source_internaldate,
        "target_internaldate": target_internaldate,
        "provenance": EXISTING_CONTENT_REUSE_INTERNALDATE_PROVENANCE,
        "message": message,
    }


def existing_content_reuse_internaldate_warnings(
    journal_rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    *,
    target_provider: str,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[Dict[str, Any]]:
    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    warnings: List[Dict[str, Any]] = []
    for (identity, target_mailbox), journal_row in latest_committed_journal_rows(
        journal_rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    ).items():
        manifest_row = manifest_by_id.get(identity)
        if manifest_row is None:
            continue
        warning = _existing_content_reuse_internaldate_warning(
            identity=identity,
            target_mailbox=str(journal_row.get("target_mailbox") or target_mailbox),
            manifest_row=manifest_row,
            journal_row=journal_row,
        )
        if warning is not None:
            warnings.append(warning)
    return warnings


def _deduplicate_report_warnings(warnings: Iterable[Any]) -> List[Any]:
    deduplicated: List[Any] = []
    seen: set[str] = set()
    for warning in warnings:
        try:
            key = json.dumps(
                warning,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError):
            key = repr(warning)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(warning)
    return deduplicated


def append_target_internaldate_failure(
    failures: List[str],
    *,
    identity: str,
    target_mailbox: str,
    row: Dict[str, Any],
    actual_internaldate: str,
    journal_row: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[Dict[str, Any]]] = None,
) -> None:
    expected_internaldate = _normalized_provider_internaldate(row.get("internaldate"))
    if not expected_internaldate:
        return
    if _legacy_internaldates_equal(actual_internaldate, expected_internaldate):
        return
    if journal_row is not None:
        warning = _existing_content_reuse_internaldate_warning(
            identity=identity,
            target_mailbox=target_mailbox,
            manifest_row=row,
            journal_row=journal_row,
        )
        if warning is not None and _legacy_internaldates_equal(
            actual_internaldate,
            warning["target_internaldate"],
        ):
            if warnings is not None and warning not in warnings:
                warnings.append(warning)
            return
    failures.append(
        f"target INTERNALDATE mismatch for {identity} in {target_mailbox}: "
        f"expected {expected_internaldate!r} got {(actual_internaldate or '<missing>')!r}"
    )


def _target_internaldate_matches_row(imap: imaplib.IMAP4, num: bytes, row: Dict[str, Any]) -> bool:
    expected_internaldate = _normalized_provider_internaldate(row.get("internaldate"))
    if not expected_internaldate:
        return True
    return _legacy_internaldates_equal(target_message_internaldate(imap, num), expected_internaldate)


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
    status, response = _target_store(imap, target_num, "+FLAGS.SILENT", flags)
    if status != "OK":
        raise RuntimeError(f"failed to restore IMAP flags for {row.get('canonical_id')}: {response}")


def _internaldate_for_append(internaldate: str) -> str:
    try:
        value = _legacy_internaldate_for_append(internaldate)
    except ValueError as exc:
        raise RuntimeError("invalid provider internaldate") from exc
    return value if value is not None else imaplib.Time2Internaldate(time.time())


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
    if row.get("routing_active"):
        return "important" in {
            str(value).strip().lower()
            for value in (row.get("routing_system_destinations") or [])
        }
    labels = {_gmail_label_key(str(label)) for label in (row.get("gmail_labels") or [])}
    flags = {_gmail_label_key(token) for token in str(row.get("flags") or "").split()}
    return "important" in labels or "important" in flags


def row_has_gmail_starred(row: Dict[str, Any]) -> bool:
    if row.get("routing_active"):
        explicit = "starred" in {
            str(value).strip().lower()
            for value in (row.get("routing_system_destinations") or [])
        }
        portable_flags = {
            token.strip().upper() for token in str(row.get("flags") or "").split()
        }
        return explicit or "\\FLAGGED" in portable_flags
    labels = {_gmail_label_key(str(label)) for label in (row.get("gmail_labels") or [])}
    flags = {_gmail_label_key(token) for token in str(row.get("flags") or "").split()}
    return "starred" in labels or "starred" in flags


def gmail_draft_combination_issues(rows: List[Dict[str, Any]]) -> List[str]:
    """Reject label sets Gmail cannot safely apply to a Draft message."""

    issues: List[str] = []
    for row in rows:
        desired = str(row.get("primary_mailbox") or "Archive")
        desired_key = _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(desired.strip().lower(), "")
        routing_systems = {
            str(value).strip().lower()
            for value in (row.get("routing_system_destinations") or [])
            if isinstance(value, str) and value.strip()
        }
        source_tokens: List[str] = []
        if not row.get("routing_active"):
            for field in ("gmail_labels", "source_mailboxes"):
                values = row.get(field) or []
                if isinstance(values, list):
                    source_tokens.extend(
                        str(value).strip()
                        for value in values
                        if isinstance(value, str) and value.strip()
                    )
            source_attributes = row.get("source_mailbox_attributes")
            if isinstance(source_attributes, dict):
                for values in source_attributes.values():
                    if isinstance(values, list):
                        source_tokens.extend(
                            str(value).strip()
                            for value in values
                            if isinstance(value, str) and value.strip()
                        )
        draft_present = desired_key == "drafts" or "drafts" in routing_systems
        if not draft_present:
            draft_present = any(
                _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(token.lower(), "") == "drafts"
                or _gmail_label_key(token) == "drafts"
                for token in source_tokens
            )
        if not draft_present:
            continue
        incompatible: set[str] = set()
        if row.get("routing_active"):
            incompatible.update(
                value
                for value in (row.get("routing_target_labels") or [])
                if isinstance(value, str) and value
            )
            incompatible.update(routing_systems - {"all", "drafts"})
        else:
            for token in source_tokens:
                key = (
                    _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(token.lower(), "")
                    or _gmail_label_key(token)
                )
                if key in {"all", "drafts"}:
                    continue
                if key.startswith("label:") and token.startswith("\\"):
                    # Structural IMAP attributes are not Gmail labels.
                    continue
                incompatible.add(token if key.startswith("label:") else key)
        if desired_key not in {"", "all", "drafts"}:
            incompatible.add(desired_key)
        elif not desired_key and desired.strip().lower() not in {"archive", "all mail"}:
            incompatible.add(desired)
        if row_has_gmail_important(row):
            incompatible.add("important")
        if row_has_gmail_starred(row):
            incompatible.add("starred")
        if incompatible:
            issues.append(
                f"{row.get('canonical_id') or '<unknown>'}: Gmail Drafts cannot be combined "
                "with non-draft label/location(s): "
                + ", ".join(
                    sorted(incompatible, key=lambda value: (value.casefold(), value))
                )
            )
    return issues


_GMAIL_ROUTING_LOCATION_ROLES = frozenset(
    {"all", "drafts", "important", "inbox", "sent", "spam", "starred", "trash"}
)

_GMAIL_DUPLICATE_ALLOCATION_FAMILIES: Tuple[
    Tuple[str, frozenset[str], bool],
    ...,
] = (
    ("draft", frozenset({"all", "drafts"}), False),
    (
        "sent",
        frozenset({"all", "inbox", "important", "starred", "sent"}),
        True,
    ),
    ("spam", frozenset({"important", "starred", "spam"}), True),
    ("trash", frozenset({"important", "starred", "trash"}), True),
    (
        "neutral",
        frozenset({"all", "inbox", "important", "starred"}),
        True,
    ),
)
_GMAIL_DUPLICATE_ALLOCATION_FAMILY_NAMES = tuple(
    family[0] for family in _GMAIL_DUPLICATE_ALLOCATION_FAMILIES
)
GMAIL_DUPLICATE_ALLOCATION_MAX_FAMILY_GROUPS = 256
GMAIL_DUPLICATE_ALLOCATION_MAX_SEARCH_STATES = 1_000_000


def _gmail_duplicate_profile_families(
    profile: Tuple[frozenset[str], frozenset[str]],
) -> Tuple[str, ...]:
    systems, custom_labels = profile
    return tuple(
        name
        for name, allowed_systems, allows_custom in (
            _GMAIL_DUPLICATE_ALLOCATION_FAMILIES
        )
        if systems <= allowed_systems
        and (not custom_labels or allows_custom)
    )


def _gmail_destination_profile_for_row(
    row: Dict[str, Any],
) -> Tuple[frozenset[str], frozenset[str]]:
    """Return immutable Gmail system/custom requirements for one source record."""

    systems: set[str] = set()
    custom_labels: set[str] = set()
    desired = str(row.get("primary_mailbox") or "Archive")
    desired_key = _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(
        desired.strip().lower(),
        "",
    )

    if row.get("routing_active"):
        systems.update(
            str(value).strip().lower()
            for value in (row.get("routing_system_destinations") or [])
            if isinstance(value, str) and value.strip()
        )
        custom_labels.update(
            str(value).casefold()
            for value in (row.get("routing_target_labels") or [])
            if isinstance(value, str) and value
        )
        if desired_key and (desired_key != "all" or not systems):
            # Archive is also the neutral IMAP append anchor for label-only
            # system views such as Important/Starred.  It is a destination
            # requirement only when no explicit system view was requested.
            systems.add(desired_key)
    else:
        if desired_key:
            systems.add(desired_key)
        for field in ("gmail_labels", "source_mailboxes"):
            values = row.get(field) or []
            if not isinstance(values, list):
                continue
            for raw_value in values:
                if not isinstance(raw_value, str) or not raw_value.strip():
                    continue
                value = raw_value.strip()
                key = (
                    _GMAIL_DESIRED_MAILBOX_SYSTEM_KEYS.get(value.lower(), "")
                    or _gmail_label_key(value)
                )
                if key in _GMAIL_ROUTING_LOCATION_ROLES:
                    systems.add(key)
                elif key.startswith("label:") and not value.startswith("\\"):
                    custom_labels.add(key.removeprefix("label:"))

    if row_has_gmail_important(row):
        systems.add("important")
    if row_has_gmail_starred(row):
        systems.add("starred")
    return frozenset(systems), frozenset(custom_labels)


def _gmail_required_destination_profile_for_row(
    row: Dict[str, Any],
) -> Tuple[frozenset[str], frozenset[str]]:
    allocation = row.get("_gmail_duplicate_allocation")
    if not isinstance(allocation, dict):
        return _gmail_destination_profile_for_row(row)
    raw_systems = allocation.get("systems")
    raw_custom_labels = allocation.get("custom_labels")
    if not isinstance(raw_systems, list) or not isinstance(raw_custom_labels, list):
        return _gmail_destination_profile_for_row(row)
    if any(not isinstance(value, str) or not value for value in raw_systems):
        return _gmail_destination_profile_for_row(row)
    if any(not isinstance(value, str) or not value for value in raw_custom_labels):
        return _gmail_destination_profile_for_row(row)
    return (
        frozenset(value.strip().lower() for value in raw_systems),
        frozenset(value.casefold() for value in raw_custom_labels),
    )


def _gmail_pending_needs_neutral_anchor_evidence(
    row: Dict[str, Any],
) -> bool:
    own_systems, _own_custom_labels = _gmail_destination_profile_for_row(row)
    required_systems, _required_custom_labels = (
        _gmail_required_destination_profile_for_row(row)
    )
    return bool(
        required_systems & {"spam", "trash"}
        and not own_systems & {"spam", "trash"}
        and "all" not in required_systems
    )


def _gmail_destination_profile_for_target_state(
    label_keys: Iterable[str],
    flags: Iterable[str],
    mailbox: str,
) -> Tuple[frozenset[str], frozenset[str]]:
    systems: set[str] = set()
    custom_labels: set[str] = set()
    mailbox_key = _gmail_target_system_key(mailbox)
    if mailbox_key:
        systems.add(mailbox_key)
    for raw_key in label_keys:
        key = str(raw_key).strip().lower()
        if key in _GMAIL_ROUTING_LOCATION_ROLES:
            systems.add(key)
        elif key.startswith("label:"):
            custom_labels.add(key.removeprefix("label:"))
    if any(str(flag).strip().upper() == "\\FLAGGED" for flag in flags):
        systems.add("starred")
    return frozenset(systems), frozenset(custom_labels)


def _gmail_destination_profile_for_target_candidate(
    row: Dict[str, Any],
    label_keys: Iterable[str],
    flags: Iterable[str],
    mailbox: str,
    target_gmail_msgid: str,
    *,
    fresh_neutral_anchor_msgids: Optional[set[str]] = None,
) -> Tuple[frozenset[str], frozenset[str]]:
    systems, custom_labels = _gmail_destination_profile_for_target_state(
        label_keys,
        flags,
        mailbox,
    )
    allocation = row.get("_gmail_duplicate_allocation")
    if not isinstance(allocation, dict):
        return systems, custom_labels
    bound_msgids = allocation.get("target_gmail_msgids")
    exact_slot_bound = bool(
        isinstance(bound_msgids, list) and target_gmail_msgid in bound_msgids
    )
    proven_fresh_anchor = bool(
        fresh_neutral_anchor_msgids
        and target_gmail_msgid in fresh_neutral_anchor_msgids
    )
    if not exact_slot_bound and not proven_fresh_anchor:
        return systems, custom_labels
    required_systems, _required_custom_labels = (
        _gmail_required_destination_profile_for_row(row)
    )
    if (
        "all" in systems
        and "all" not in required_systems
        and required_systems & {"spam", "trash"}
    ):
        # A prior row assigned to this exact migration slot, or the one
        # physical ID uniquely proven to have appeared after this APPEND, may
        # temporarily be visible through All Mail only because Archive was its
        # append anchor. Spam/Trash later replaces that neutral anchor. Never
        # make this relaxation for an unrelated target Gmail ID or an explicit
        # All route.
        systems = frozenset(set(systems) - {"all"})
    return systems, custom_labels


def _gmail_destination_profile_conflicts(
    profiles: Iterable[Tuple[frozenset[str], frozenset[str]]],
) -> Tuple[str, ...]:
    systems: set[str] = set()
    custom_labels: set[str] = set()
    for profile_systems, profile_custom_labels in profiles:
        systems.update(profile_systems)
        custom_labels.update(profile_custom_labels)
    conflicts: set[str] = set(gmail_incompatible_system_roles(systems))
    if "drafts" in systems:
        conflicts.update(systems - {"all", "drafts"})
        conflicts.update(f"label:{label}" for label in custom_labels)
    return tuple(
        sorted(conflicts, key=lambda value: (value.casefold(), value))
    )


def _gmail_duplicate_effective_date_and_msgid(
    row: Dict[str, Any],
    journal_rows: List[Dict[str, Any]],
) -> Tuple[str, str]:
    identity = str(row.get("canonical_id") or "")
    latest_committed: Optional[Dict[str, Any]] = None
    latest_status: Optional[Dict[str, Any]] = None
    target_gmail_msgid = ""
    for journal_row in journal_rows:
        if str(journal_row.get("canonical_id") or "") != identity:
            continue
        if journal_row.get("status") in {"committed", "failed", "pending"}:
            latest_status = journal_row
        if journal_row.get("status") == "committed":
            latest_committed = journal_row
            candidate_msgid = str(journal_row.get("target_gmail_msgid") or "")
            if candidate_msgid:
                target_gmail_msgid = candidate_msgid
    effective_row = row
    if latest_committed is not None:
        effective_row = _committed_target_match_row(row, latest_committed)
    elif latest_status is not None and latest_status.get("status") == "pending":
        effective_row = row
    normalized_date = _normalized_provider_internaldate(
        effective_row.get("internaldate")
    )
    return _legacy_internaldate_utc_key(normalized_date), target_gmail_msgid


def require_merge_group_gmail_destination_allocations_compatible(
    stages: List[
        Tuple[
            MigrationAccount,
            Path,
            List[Dict[str, Any]],
            List[Dict[str, Any]],
        ]
    ],
    *,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
    stop_event: Optional[object] = None,
) -> List[Dict[str, Any]]:
    """Prove strong duplicates fit compatible Gmail physical-message slots.

    Each content/effective-date class has the maximum multiplicity exported by
    any one source.  Rows from one source occupy distinct slots; rows from
    different sources may share a slot only when their combined Gmail
    destinations are representable.  Existing committed Gmail IDs bind rows
    to the same physical slot before any target or journal mutation occurs.
    """

    entries: List[Dict[str, Any]] = []
    missing_payloads: List[str] = []
    for group_account, _account_dir, manifest_rows, journal_rows in stages:
        _raise_if_stopped(
            stop_event,
            "Gmail duplicate destination allocation",
        )
        for row in manifest_rows:
            identity = str(row.get("canonical_id") or "")
            content_identities = expected_content_identities_by_id.get(identity)
            if not identity or not content_identities:
                missing_payloads.append(
                    f"{group_account.source_email}/{identity or '<missing>'}"
                )
                continue
            date_key, target_gmail_msgid = _gmail_duplicate_effective_date_and_msgid(
                row,
                journal_rows,
            )
            entries.append(
                {
                    "source_email": group_account.source_email,
                    "identity": identity,
                    "content_identities": frozenset(content_identities),
                    "date_key": date_key or "<missing>",
                    "target_gmail_msgid": target_gmail_msgid,
                    "profile": _gmail_destination_profile_for_row(row),
                }
            )
    if missing_payloads:
        raise ProviderImportIntegrityGateError(
            "cannot prove Gmail duplicate destination allocation because verified payload "
            "identity is missing for: " + "; ".join(sorted(missing_payloads))
        )

    entries.sort(
        key=lambda entry: (
            entry["date_key"],
            entry["source_email"].casefold(),
            entry["source_email"],
            entry["identity"],
        )
    )
    parents = list(range(len(entries)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parents[right_root] = left_root
        else:
            parents[left_root] = right_root

    first_by_dated_content: Dict[Tuple[str, Tuple[int, str]], int] = {}
    first_by_gmail_msgid: Dict[str, int] = {}
    for index, entry in enumerate(entries):
        for content_identity in sorted(entry["content_identities"]):
            key = (entry["date_key"], content_identity)
            previous = first_by_dated_content.setdefault(key, index)
            union(index, previous)
        if entry["target_gmail_msgid"]:
            previous = first_by_gmail_msgid.setdefault(
                entry["target_gmail_msgid"],
                index,
            )
            union(index, previous)

    entries_by_class: Dict[int, List[Dict[str, Any]]] = {}
    for index, entry in enumerate(entries):
        entries_by_class.setdefault(find(index), []).append(entry)

    allocation_classes: List[Dict[str, Any]] = []
    allocation_conflicts: List[str] = []
    for class_entries in entries_by_class.values():
        _raise_if_stopped(
            stop_event,
            "Gmail duplicate destination allocation",
        )
        class_entries.sort(
            key=lambda entry: (
                entry["source_email"].casefold(),
                entry["source_email"],
                entry["identity"],
            )
        )
        count_by_source: Dict[str, int] = {}
        for entry in class_entries:
            source_key = entry["source_email"].casefold()
            count_by_source[source_key] = count_by_source.get(source_key, 0) + 1
        capacity = max(count_by_source.values(), default=0)

        empty_slot = (
            frozenset(),
            frozenset(),
            frozenset(),
            "",
            tuple(),
        )
        initial_slots = [empty_slot for _ in range(capacity)]
        fixed_groups: Dict[str, List[int]] = {}
        for entry_index, entry in enumerate(class_entries):
            target_gmail_msgid = entry["target_gmail_msgid"]
            if target_gmail_msgid:
                fixed_groups.setdefault(target_gmail_msgid, []).append(entry_index)

        fixed_failure = ""
        assigned_indices: set[int] = set()
        allocation_by_index: Dict[int, int] = {}
        if len(fixed_groups) > capacity:
            fixed_failure = (
                f"{len(fixed_groups)} committed Gmail physical IDs exceed capacity {capacity}"
            )
        else:
            for slot_index, (target_gmail_msgid, group_indices) in enumerate(
                sorted(fixed_groups.items())
            ):
                group_entries = [class_entries[index] for index in group_indices]
                group_sources = {
                    entry["source_email"].casefold() for entry in group_entries
                }
                if len(group_sources) != len(group_entries):
                    fixed_failure = (
                        f"committed Gmail physical ID {target_gmail_msgid} binds multiple "
                        "records from one source"
                    )
                    break
                group_conflicts = _gmail_destination_profile_conflicts(
                    entry["profile"] for entry in group_entries
                )
                if group_conflicts:
                    fixed_failure = (
                        f"committed Gmail physical ID {target_gmail_msgid} has incompatible "
                        f"destinations ({', '.join(group_conflicts)})"
                    )
                    break
                group_systems = frozenset().union(
                    *(entry["profile"][0] for entry in group_entries)
                )
                group_labels = frozenset().union(
                    *(entry["profile"][1] for entry in group_entries)
                )
                initial_slots[slot_index] = (
                    frozenset(group_sources),
                    group_systems,
                    group_labels,
                    target_gmail_msgid,
                    tuple(sorted(group_indices)),
                )
                for entry_index in group_indices:
                    assigned_indices.add(entry_index)
                    allocation_by_index[entry_index] = slot_index

        pending_indices = tuple(
            index
            for index in range(len(class_entries))
            if index not in assigned_indices
        )
        allocation_search_states = 0
        aggregate_conflicts = _gmail_destination_profile_conflicts(
            entry["profile"] for entry in class_entries
        )
        allocation: Optional[Dict[int, int]] = None
        entry_families = {
            entry_index: _gmail_duplicate_profile_families(
                class_entries[entry_index]["profile"]
            )
            for entry_index in range(len(class_entries))
        }
        if not fixed_failure:
            invalid_entries = [
                entry_index
                for entry_index, families in entry_families.items()
                if not families
            ]
            if invalid_entries:
                fixed_failure = (
                    "one or more rows has no representable Gmail destination family"
                )

        pending_by_source: Dict[str, List[int]] = {}
        for entry_index in pending_indices:
            source_key = class_entries[entry_index]["source_email"].casefold()
            pending_by_source.setdefault(source_key, []).append(entry_index)
        for source_entries in pending_by_source.values():
            source_entries.sort(
                key=lambda index: (
                    len(entry_families[index]),
                    class_entries[index]["identity"],
                )
            )

        slot_domains: List[Tuple[str, ...]] = []
        for sources, systems, custom_labels, _fixed_id, members in initial_slots:
            if members:
                slot_domains.append(
                    _gmail_duplicate_profile_families(
                        (systems, custom_labels)
                    )
                )
            else:
                slot_domains.append(
                    _GMAIL_DUPLICATE_ALLOCATION_FAMILY_NAMES
                )
        if not fixed_failure and any(not domain for domain in slot_domains):
            fixed_failure = "a committed Gmail physical slot has no destination family"

        slot_groups_by_signature: Dict[
            Tuple[Tuple[str, ...], Tuple[str, ...]],
            List[int],
        ] = {}
        for slot_index, slot in enumerate(initial_slots):
            sources = tuple(sorted(slot[0]))
            signature = (slot_domains[slot_index], sources)
            slot_groups_by_signature.setdefault(signature, []).append(slot_index)
        slot_groups = sorted(
            slot_groups_by_signature.items(),
            key=lambda item: (
                len(item[0][0]),
                item[0][0],
                item[0][1],
                item[1],
            ),
        )
        if (
            not fixed_failure
            and len(slot_groups)
            > GMAIL_DUPLICATE_ALLOCATION_MAX_FAMILY_GROUPS
        ):
            raise ProviderImportIntegrityGateError(
                "Gmail duplicate destination allocation proof is indeterminate: "
                "family-group resource bound exceeded "
                f"({len(slot_groups)} > "
                f"{GMAIL_DUPLICATE_ALLOCATION_MAX_FAMILY_GROUPS})"
            )
        family_by_slot: List[Optional[str]] = [None] * capacity

        def source_family_matching(
            source_key: str,
            *,
            allow_unassigned: bool,
        ) -> Optional[Dict[int, int]]:
            source_entries = pending_by_source.get(source_key, [])
            slot_by_entry: Dict[int, List[int]] = {}
            for entry_index in source_entries:
                allowed_families = set(entry_families[entry_index])
                candidates: List[int] = []
                for slot_index, slot in enumerate(initial_slots):
                    _raise_if_stopped(
                        stop_event,
                        "Gmail duplicate destination allocation",
                    )
                    if source_key in slot[0]:
                        continue
                    family = family_by_slot[slot_index]
                    if family is not None:
                        if family in allowed_families:
                            candidates.append(slot_index)
                        continue
                    if allow_unassigned and allowed_families.intersection(
                        slot_domains[slot_index]
                    ):
                        candidates.append(slot_index)
                slot_by_entry[entry_index] = candidates

            entry_by_slot: Dict[int, int] = {}
            slot_by_matched_entry: Dict[int, int] = {}
            for entry_index in source_entries:
                queue = [entry_index]
                queue_index = 0
                seen_entries = {entry_index}
                parent_entry_by_slot: Dict[int, int] = {}
                free_slot: Optional[int] = None
                while queue_index < len(queue) and free_slot is None:
                    current_entry = queue[queue_index]
                    queue_index += 1
                    for slot_index in slot_by_entry[current_entry]:
                        _raise_if_stopped(
                            stop_event,
                            "Gmail duplicate destination allocation",
                        )
                        if slot_index in parent_entry_by_slot:
                            continue
                        parent_entry_by_slot[slot_index] = current_entry
                        owner = entry_by_slot.get(slot_index)
                        if owner is None:
                            free_slot = slot_index
                            break
                        if owner not in seen_entries:
                            seen_entries.add(owner)
                            queue.append(owner)
                if free_slot is None:
                    return None
                current_slot = free_slot
                while True:
                    current_entry = parent_entry_by_slot[current_slot]
                    previous_slot = slot_by_matched_entry.get(current_entry)
                    entry_by_slot[current_slot] = current_entry
                    slot_by_matched_entry[current_entry] = current_slot
                    if previous_slot is None:
                        break
                    current_slot = previous_slot
            return {
                entry_index: slot_index
                for entry_index, slot_index in slot_by_matched_entry.items()
            }

        def allocate_slot_families(
            group_index: int,
        ) -> Optional[Dict[int, int]]:
            nonlocal allocation_search_states
            _raise_if_stopped(
                stop_event,
                "Gmail duplicate destination allocation",
            )
            if group_index == len(slot_groups):
                combined: Dict[int, int] = {}
                for source_key in sorted(pending_by_source):
                    source_allocation = source_family_matching(
                        source_key,
                        allow_unassigned=False,
                    )
                    if source_allocation is None:
                        return None
                    combined.update(source_allocation)
                return combined

            (domain, _occupied_sources), slot_indices = slot_groups[group_index]
            for family_multiset in itertools.combinations_with_replacement(
                domain,
                len(slot_indices),
            ):
                if (
                    allocation_search_states
                    >= GMAIL_DUPLICATE_ALLOCATION_MAX_SEARCH_STATES
                ):
                    raise ProviderImportIntegrityGateError(
                        "Gmail duplicate destination allocation proof is "
                        "indeterminate: search-state resource bound exceeded "
                        f"({GMAIL_DUPLICATE_ALLOCATION_MAX_SEARCH_STATES})"
                    )
                allocation_search_states += 1
                _raise_if_stopped(
                    stop_event,
                    "Gmail duplicate destination allocation",
                )
                for slot_index, family in zip(slot_indices, family_multiset):
                    family_by_slot[slot_index] = family
                if all(
                    source_family_matching(
                        source_key,
                        allow_unassigned=True,
                    )
                    is not None
                    for source_key in sorted(pending_by_source)
                ):
                    result = allocate_slot_families(group_index + 1)
                    if result is not None:
                        return result
                for slot_index in slot_indices:
                    family_by_slot[slot_index] = None
            return None

        if not fixed_failure:
            allocation = allocate_slot_families(0)
        if fixed_failure or allocation is None:
            rows = ", ".join(
                f"{entry['source_email']}/{entry['identity']}"
                for entry in class_entries
            )
            detail = fixed_failure or "no compatible slot assignment exists"
            if not fixed_failure and aggregate_conflicts:
                detail += " (combined requirements include " + ", ".join(
                    aggregate_conflicts
                ) + ")"
            allocation_conflicts.append(
                f"strong duplicate class with capacity {capacity} ({rows}): {detail}"
            )
            continue
        allocation_by_index.update(allocation)
        slot_profiles: Dict[int, Dict[str, List[str]]] = {}
        for entry_index, slot_index in allocation_by_index.items():
            profile = slot_profiles.setdefault(
                slot_index,
                {
                    "systems": [],
                    "custom_labels": [],
                    "target_gmail_msgids": [],
                },
            )
            systems = set(profile["systems"])
            systems.update(class_entries[entry_index]["profile"][0])
            profile["systems"] = sorted(systems)
            custom_labels = set(profile["custom_labels"])
            custom_labels.update(class_entries[entry_index]["profile"][1])
            profile["custom_labels"] = sorted(
                custom_labels,
                key=lambda value: (value.casefold(), value),
            )
            target_gmail_msgids = set(profile["target_gmail_msgids"])
            target_gmail_msgid = class_entries[entry_index]["target_gmail_msgid"]
            if target_gmail_msgid:
                target_gmail_msgids.add(target_gmail_msgid)
            profile["target_gmail_msgids"] = sorted(
                target_gmail_msgids,
                key=lambda value: (len(value), value),
            )
        allocation_classes.append(
            {
                "capacity": capacity,
                "content_identities": set().union(
                    *(entry["content_identities"] for entry in class_entries)
                ),
                "date_keys": sorted({entry["date_key"] for entry in class_entries}),
                "allocations": {
                    (
                        class_entries[index]["source_email"],
                        class_entries[index]["identity"],
                    ): slot_index
                    for index, slot_index in sorted(allocation_by_index.items())
                },
                "slot_profiles": slot_profiles,
                "allocation_search_states": allocation_search_states,
            }
        )

    if allocation_conflicts:
        raise ProviderImportIntegrityGateError(
            "incompatible Gmail destinations for cross-source strong duplicates: "
            + "; ".join(sorted(allocation_conflicts))
        )
    allocation_classes.sort(
        key=lambda item: (
            item["date_keys"],
            sorted(item["content_identities"]),
        )
    )
    return allocation_classes


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
    if row.get("routing_active"):
        routing_labels = row.get("routing_target_labels")
        if not isinstance(routing_labels, list) or any(
            not isinstance(value, str) or not value for value in routing_labels
        ):
            raise RuntimeError(
                f"routing metadata for {row.get('canonical_id') or '<unknown>'} has invalid routing_target_labels"
            )
        for label in routing_labels:
            if label not in labels:
                labels.append(label)
        routing_systems = {
            str(value).strip().lower()
            for value in (row.get("routing_system_destinations") or [])
            if str(value).strip()
        }
        for key, restore_label in (
            ("inbox", "\\Inbox"),
            ("trash", "\\Trash"),
            ("spam", "\\Junk"),
        ):
            if key in routing_systems and key != target_system_key and restore_label not in labels:
                labels.append(restore_label)
        if "important" in routing_systems and "Important" not in labels:
            labels.append("Important")
    else:
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
    if (
        row_has_gmail_important(row)
        and "Important" not in labels
        and target_mailbox.lower() not in {"[gmail]/important", "[googlemail]/important", "important"}
    ):
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
) -> List[str]:
    labels = gmail_labels_for_restore(
        row,
        target_mailbox,
        target_mailboxes,
        desired_target_mailbox=desired_target_mailbox,
    )
    if not labels:
        return []
    num = target_num or _first_target_match_num(imap, target_mailbox, row)
    labels_to_add = list(labels)
    if row.get("routing_active"):
        status, _ = select_mailbox(imap, target_mailbox)
        if status != "OK":
            raise RuntimeError(
                f"cannot select target mailbox {target_mailbox!r} to verify Gmail labels"
            )
        actual_keys = _target_gmail_label_keys(imap, num)
        labels_to_add = [
            label for label in labels if _gmail_label_key(label) not in actual_keys
        ]
        if not labels_to_add:
            return []
    status, _ = select_mailbox(imap, target_mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select target mailbox {target_mailbox!r} to restore Gmail labels")
    label_list = "(" + " ".join(_quote_gmail_label(label) for label in labels_to_add) + ")"
    status, response = _target_store(imap, num, "+X-GM-LABELS", label_list)
    if status != "OK":
        raise RuntimeError(f"failed to restore Gmail labels for {row.get('canonical_id')}: {response}")
    if row.get("routing_active"):
        verified_keys = _target_gmail_label_keys(imap, num)
        missing = [
            label for label in labels if _gmail_label_key(label) not in verified_keys
        ]
        if missing:
            raise RuntimeError(
                f"Gmail labels missing after restore for {row.get('canonical_id')}: "
                + ", ".join(missing)
            )
    return labels_to_add


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
    if row.get("routing_active") and "starred" not in _target_gmail_label_keys(imap, num):
        raise RuntimeError(
            f"Gmail starred membership missing after restore for {row.get('canonical_id')}"
        )


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
    target_capacity_by_identity: Dict[Tuple[int, str], int] = {}
    target_identity_order: List[Tuple[int, str]] = []
    for identity in target_content_identities:
        if identity not in target_capacity_by_identity:
            target_identity_order.append(identity)
            target_capacity_by_identity[identity] = 0
        target_capacity_by_identity[identity] += 1

    allowed_identities_by_expected = [
        [identity for identity in target_identity_order if identity in expected_identities]
        for expected_identities in expected_identity_sets
    ]
    assigned_identity_by_expected: Dict[int, Tuple[int, str]] = {}
    assigned_expected_by_identity: Dict[Tuple[int, str], List[int]] = {
        identity: [] for identity in target_identity_order
    }

    def assign(start_expected: int) -> bool:
        pending = [start_expected]
        pending_index = 0
        seen_expected = {start_expected}
        seen_identities: set[Tuple[int, str]] = set()
        parent_expected_by_identity: Dict[Tuple[int, str], int] = {}
        free_identity: Optional[Tuple[int, str]] = None

        while pending_index < len(pending) and free_identity is None:
            expected_index = pending[pending_index]
            pending_index += 1
            for identity in allowed_identities_by_expected[expected_index]:
                if identity in seen_identities:
                    continue
                seen_identities.add(identity)
                parent_expected_by_identity[identity] = expected_index
                assigned_expected = assigned_expected_by_identity[identity]
                if len(assigned_expected) < target_capacity_by_identity[identity]:
                    free_identity = identity
                    break
                for assigned_index in assigned_expected:
                    if assigned_index not in seen_expected:
                        seen_expected.add(assigned_index)
                        pending.append(assigned_index)

        if free_identity is None:
            return False

        identity = free_identity
        while True:
            expected_index = parent_expected_by_identity[identity]
            previous_identity = assigned_identity_by_expected.get(expected_index)
            assigned_identity_by_expected[expected_index] = identity
            assigned_expected_by_identity[identity].append(expected_index)
            if previous_identity is None:
                return True
            assigned_expected_by_identity[previous_identity].remove(expected_index)
            identity = previous_identity

    for expected_index in range(len(expected_identity_sets)):
        assign(expected_index)
    return len(assigned_identity_by_expected)


def _max_group_expected_content_identity_matches(
    target_content_identities: List[Tuple[int, str]],
    expected_identity_sets_by_source: List[List[set[Tuple[int, str]]]],
) -> int:
    return max(
        (
            _max_expected_content_identity_matches(
                target_content_identities,
                expected_identity_sets,
            )
            for expected_identity_sets in expected_identity_sets_by_source
        ),
        default=0,
    )


def _max_group_expected_content_identity_intersections(
    current_content_identities: set[Tuple[int, str]],
    expected_identity_sets_by_source: List[List[set[Tuple[int, str]]]],
) -> int:
    return max(
        (
            sum(
                1
                for expected_identities in expected_identity_sets
                if expected_identities & current_content_identities
            )
            for expected_identity_sets in expected_identity_sets_by_source
        ),
        default=0,
    )


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
                if manifest_row.get("routing_active") or manifest_row.get(
                    "_gmail_duplicate_allocation"
                ):
                    label_keys, flags, _actual_internaldate = (
                        _target_gmail_label_flag_internaldate(imap, num)
                    )
                    if _gmail_destination_profile_conflicts(
                        (
                            _gmail_required_destination_profile_for_row(
                                manifest_row
                            ),
                            _gmail_destination_profile_for_target_candidate(
                                manifest_row,
                                label_keys,
                                flags,
                                mailbox,
                                gmail_msgid,
                            ),
                        )
                    ):
                        continue
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
    def parsed_keys(parsed: Dict[str, Any]) -> Tuple[set[str], set[str]]:
        labels = {
            _gmail_label_key(str(label))
            for label in (parsed.get("gmail_labels") or [])
        }
        flags = {
            token.upper()
            for token in str(parsed.get("flags") or "").split()
        }
        # Portable IMAP state is not a Gmail custom-label namespace. Only the
        # two flags with an actual Gmail destination meaning participate in
        # allocation compatibility; \Seen, \Answered, \Deleted, and other
        # ordinary flags remain ordinary message state.
        if "\\FLAGGED" in flags:
            labels.add("starred")
        if "\\DRAFT" in flags:
            labels.add("drafts")
        return {label for label in labels if label}, flags

    if _target_uid_command_available(imap):
        uid = parse_imap_uid_token(num, label="target UID")
        status, fetched = imap.uid("fetch", num, "(UID X-GM-LABELS FLAGS)")
        if status != "OK":
            raise RuntimeError(f"failed to fetch Gmail labels for target message {num!r}")
        parsed = parse_provider_fetch_response(fetched or [], expected_uid=uid)
        return parsed_keys(parsed)
    status, fetched = imap.fetch(num, "(X-GM-LABELS FLAGS)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch Gmail labels for target message {num!r}")
    parsed = parse_provider_fetch_response(_provider_fetch_response_for_sequence(fetched or [], num))
    return parsed_keys(parsed)


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
    require_internaldate_match: bool = False,
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
        if require_internaldate_match and not _target_internaldate_matches_row(
            imap,
            num,
            manifest_row,
        ):
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
    allocation = row.get("_gmail_duplicate_allocation")
    if isinstance(allocation, dict):
        allocation_systems = allocation.get("systems")
        if isinstance(allocation_systems, list):
            for system_key in allocation_systems:
                if not isinstance(system_key, str):
                    continue
                for name in system_by_key.get(system_key.strip().lower(), []):
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
        target_mailbox = _resolved_target_mailbox_for_row(
            row,
            target_mailboxes,
            target_provider=target_provider,
        )
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
        mailbox_key = _target_mailbox_lookup_key(mailbox.name, target_provider)
        candidates_by_row: Dict[str, List[Dict[str, Any]]] = {}
        for permitted_row, journal_key in permitted_by_mailbox.get(mailbox_key, []):
            identity = str(permitted_row.get("canonical_id") or "")
            expected_content_identities = (
                expected_content_identities_by_id.get(identity)
                if expected_content_identities_by_id and identity
                else None
            )
            target_gmail_msgid = gmail_journal_msgids.get(journal_key, "") if target_provider == "gmail" else ""
            expected_date_key = _legacy_internaldate_utc_key(
                permitted_row.get("internaldate")
            )
            candidates: List[Dict[str, Any]] = []
            for target_num in target_matching_message_nums(
                imap,
                mailbox.name,
                permitted_row,
                create_if_missing=False,
                expected_content_identities=expected_content_identities,
            ):
                actual_internaldate = target_message_internaldate(imap, target_num)
                if (
                    expected_date_key
                    and _legacy_internaldate_utc_key(actual_internaldate)
                    != expected_date_key
                ):
                    continue
                gmail_msgid = _target_gmail_msgid(imap, target_num) if target_provider == "gmail" else ""
                if target_gmail_msgid and gmail_msgid != target_gmail_msgid:
                    continue
                physical_key: Tuple[Any, ...] = (
                    ("gmail", gmail_msgid)
                    if target_provider == "gmail"
                    else ("imap", mailbox_key, target_num)
                )
                candidates.append({
                    "physical_key": physical_key,
                    "mailbox": mailbox.name,
                    "num": target_num,
                    "gmail_msgid": gmail_msgid,
                    "internaldate": actual_internaldate,
                })
            candidates_by_row[identity] = candidates
        verified = len(_maximum_target_candidate_assignments(
            candidates_by_row,
            required_row_keys=set(candidates_by_row),
        ))
        if count > verified:
            raise ProviderImportIntegrityGateError(
                f"target_mode=empty but target mailbox {mailbox.name!r} contains "
                f"{count} message(s), only {verified} matching journaled message(s) from this migration"
            )


def translated_target_mailboxes_for_rows(
    rows: List[Dict[str, Any]],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> Dict[str, str]:
    translated_sources_by_target: Dict[str, Tuple[Tuple[str, ...], Dict[str, Any]]] = {}
    result: Dict[str, str] = {}
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        source_desired = str(row.get("primary_mailbox") or "Archive")
        target_mailbox = _resolved_target_mailbox_for_row(
            row,
            target_mailboxes,
            target_provider=target_provider,
        )
        source_paths = row.get("source_mailbox_paths")
        source_key = (source_desired,)
        routing_sources = row.get("routing_source_folders")
        if row.get("routing_active") and isinstance(routing_sources, list) and routing_sources:
            source_key = (
                str(row.get("source_account") or "<unknown-source-account>"),
                *(str(value) for value in routing_sources),
            )
        elif isinstance(source_paths, dict) and isinstance(source_paths.get(source_desired), list):
            source_key = tuple(str(segment) for segment in source_paths[source_desired])
        target_mailbox_key = _target_mailbox_lookup_key(target_mailbox, target_provider)
        previous = translated_sources_by_target.setdefault(
            target_mailbox_key,
            (source_key, row),
        )
        previous_source, previous_row = previous
        if previous_source != source_key:
            same_frozen_plan = bool(
                row.get("routing_active")
                and previous_row.get("routing_active")
                and row.get("routing_plan_sha256")
                and row.get("routing_plan_sha256") == previous_row.get("routing_plan_sha256")
            )
            intentional = same_frozen_plan and target_provider == "gmail"
            if same_frozen_plan and target_provider != "gmail":
                current_shared = {
                    str(value).casefold()
                    for value in (row.get("routing_shared_destinations") or [])
                    if str(value)
                }
                previous_shared = {
                    str(value).casefold()
                    for value in (previous_row.get("routing_shared_destinations") or [])
                    if str(value)
                }
                intentional = (
                    target_mailbox.casefold() in current_shared
                    and target_mailbox.casefold() in previous_shared
                )
            if not intentional:
                raise ProviderImportIntegrityGateError(
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


def _provider_import_lock_path(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
) -> Path:
    lock_seed = json.dumps(
        target_merge_group_key(config, account),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    lock_key = hashlib.sha256(lock_seed).hexdigest()
    return in_root / IMPORT_LOCK_DIRNAME / f"provider-{lock_key}.lock"


def _provider_workflow_lock_path(root: Path) -> Path:
    return Path(root) / IMPORT_LOCK_DIRNAME / PROVIDER_WORKFLOW_LOCK_FILENAME


def _secure_existing_provider_import_root(in_root: Path) -> None:
    root_fd, root_path = _open_provider_dir(in_root, "import root")
    try:
        _raise_if_provider_parent_replaced(root_path, root_fd, "import root")
        _secure_provider_private_dir_fd(root_fd, root_path, "import root")
        _raise_if_provider_parent_replaced(root_path, root_fd, "import root")
    finally:
        os.close(root_fd)


def _provider_import_lock_stat_issue(stat_result: os.stat_result, effective_uid: int) -> Optional[str]:
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


def _require_provider_import_lock_visible(
    lock_fd: int,
    parent_fd: int,
    name: str,
    lock_path: Path,
    effective_uid: int,
) -> None:
    lock_stat = os.fstat(lock_fd)
    issue = _provider_import_lock_stat_issue(lock_stat, effective_uid)
    if issue:
        raise RuntimeError(f"refusing to use provider import lock {lock_path}: {issue}")
    try:
        visible_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"provider import lock changed while in use: {lock_path}") from exc
    visible_issue = _provider_import_lock_stat_issue(visible_stat, effective_uid)
    if visible_issue:
        raise RuntimeError(f"refusing to use provider import lock {lock_path}: {visible_issue}")
    if visible_stat.st_dev != lock_stat.st_dev or visible_stat.st_ino != lock_stat.st_ino:
        raise RuntimeError(f"provider import lock changed while in use: {lock_path}")


def _open_provider_import_lock(lock_path: Path) -> Tuple[int, int, Path, str]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("platform cannot safely open provider import lock files without O_NOFOLLOW")
    parent_fd, name, parent_path = _open_provider_parent_dir(lock_path, "import lock")
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
            raise RuntimeError(f"refusing to use symlinked provider import lock: {lock_path}") from exc
        if exc.errno in {errno.EISDIR, errno.ENXIO}:
            raise RuntimeError(f"refusing to use non-regular provider import lock: {lock_path}") from exc
        raise RuntimeError(f"unable to open provider import lock: {lock_path}") from exc
    try:
        effective_uid = _provider_effective_uid()
        initial_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(initial_stat.st_mode):
            raise RuntimeError(f"refusing to use non-regular provider import lock: {lock_path}")
        if getattr(initial_stat, "st_nlink", 1) != 1:
            raise RuntimeError(f"refusing to use hard-linked provider import lock: {lock_path}")
        if initial_stat.st_uid != effective_uid:
            raise RuntimeError(
                f"refusing to use provider import lock not owned by effective UID {effective_uid}: "
                f"{lock_path} (owner UID {initial_stat.st_uid})"
            )
        if created:
            try:
                os.fchmod(lock_fd, PRIVATE_FILE_MODE)
            except OSError as exc:
                raise RuntimeError(f"unable to set private permissions on provider import lock: {lock_path}") from exc
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "import lock")
        _require_provider_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        if created:
            os.fsync(lock_fd)
            _fsync_provider_directory_fd(parent_fd, parent_path, "import lock")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "import lock")
            _require_provider_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        return lock_fd, parent_fd, parent_path, name
    except Exception:
        os.close(lock_fd)
        os.close(parent_fd)
        raise


@contextlib.contextmanager
def _provider_import_lock(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object],
) -> Iterator[None]:
    _raise_if_provider_path_symlink(in_root, "import root")
    _secure_existing_provider_import_root(in_root)
    lock_path = _provider_import_lock_path(config, account, in_root)
    ensure_private_dir(lock_path.parent)
    lock_fd, parent_fd, parent_path, name = _open_provider_import_lock(lock_path)
    try:
        effective_uid = _provider_effective_uid()
        while True:
            _raise_if_stopped(stop_event, f"provider import {account.target_email} lock wait")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "import lock")
            _require_provider_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise RuntimeError(f"unable to acquire provider import lock: {lock_path}") from exc
            wait = getattr(stop_event, "wait", None) if stop_event is not None else None
            if callable(wait):
                if wait(IMPORT_LOCK_WAIT_SECONDS):
                    raise RuntimeError(
                        f"provider import {account.target_email} lock wait: stop requested before completion"
                    )
            else:
                time.sleep(IMPORT_LOCK_WAIT_SECONDS)
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "import lock")
        _require_provider_import_lock_visible(lock_fd, parent_fd, name, lock_path, effective_uid)
        _raise_if_stopped(stop_event, f"provider import {account.target_email} lock wait")
        yield
    finally:
        try:
            os.close(lock_fd)
        finally:
            os.close(parent_fd)


@contextlib.contextmanager
def provider_workflow_lock(
    root: Path,
    *,
    stop_event: Optional[object],
) -> Iterator[None]:
    """Serialize one complete provider workflow for a staging root.

    This fixed root-wide lock is deliberately distinct from per-target import
    locks, so a workflow may safely acquire those narrower locks while this
    one remains held.  The persistent inode makes process crashes release the
    advisory lock without creating an unlink/recreate race on normal reruns.
    """

    root = Path(root)
    _raise_if_provider_path_symlink(root, "workflow root")
    ensure_private_dir(root)
    lock_path = _provider_workflow_lock_path(root)
    ensure_private_dir(lock_path.parent)
    lock_fd, parent_fd, parent_path, name = _open_provider_import_lock(lock_path)
    try:
        effective_uid = _provider_effective_uid()
        while True:
            _raise_if_stopped(stop_event, "provider workflow lock wait")
            _raise_if_provider_parent_replaced(parent_path, parent_fd, "workflow lock")
            _require_provider_import_lock_visible(
                lock_fd,
                parent_fd,
                name,
                lock_path,
                effective_uid,
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise RuntimeError(
                        f"unable to acquire provider workflow lock: {lock_path}"
                    ) from exc
            wait = getattr(stop_event, "wait", None) if stop_event is not None else None
            if callable(wait):
                if wait(IMPORT_LOCK_WAIT_SECONDS):
                    raise RuntimeError(
                        "provider workflow lock wait: stop requested before completion"
                    )
            else:
                time.sleep(IMPORT_LOCK_WAIT_SECONDS)
        _raise_if_provider_parent_replaced(parent_path, parent_fd, "workflow lock")
        _require_provider_import_lock_visible(
            lock_fd,
            parent_fd,
            name,
            lock_path,
            effective_uid,
        )
        _raise_if_stopped(stop_event, "provider workflow lock wait")
        yield
    finally:
        try:
            os.close(lock_fd)
        finally:
            os.close(parent_fd)


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
    defer_trailing_journal_repair: bool = False,
    routing_plan_sha256: Optional[str] = None,
    routing_plan: Optional[RoutingPlan] = None,
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
        routing_plan_sha256=routing_plan_sha256,
        routing_enabled=config.migration.routing.enabled,
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
    journal_rows = load_import_journal(
        account_dir,
        account,
        repair_trailing=repair_trailing_journal,
        defer_trailing_repair=defer_trailing_journal_repair,
    )
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
    journal_content_issues.extend(
        pending_journal_manifest_content_issues(
            journal_rows,
            manifest_rows,
            target_provider=config.target.provider,
        )
    )
    if journal_content_issues:
        raise RuntimeError(
            f"invalid import journal for merge source {account.source_email}: "
            + "; ".join(journal_content_issues)
        )
    mailbox_validation_rows = manifest_rows
    if routing_plan is not None:
        mailbox_validation_rows = routed_manifest_rows(
            config,
            account,
            manifest_rows,
            routing_plan,
        )[0]
    journal_mailbox_issues = offline_journal_target_mailbox_issues(
        journal_rows,
        mailbox_validation_rows,
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
    defer_trailing_journal_repair: bool = False,
    routing_plan_sha256: Optional[str] = None,
    routing_plan: Optional[RoutingPlan] = None,
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
            defer_trailing_journal_repair=defer_trailing_journal_repair,
            routing_plan_sha256=routing_plan_sha256,
            routing_plan=routing_plan,
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
        raise ProviderImportIntegrityGateError(
            "merge group canonical_id collision: " + "; ".join(collisions)
        )


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


def _target_physical_occurrences_for_row(
    imap: imaplib.IMAP4,
    manifest_row: Dict[str, Any],
    target_mailbox: str,
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]],
) -> List[Dict[str, Any]]:
    search_mailboxes = [target_mailbox]
    if target_provider == "gmail":
        search_mailboxes = gmail_expected_target_mailboxes_for_row(
            manifest_row,
            target_mailbox,
            target_mailboxes,
        )
    occurrences: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for search_mailbox in search_mailboxes:
        for target_num in target_matching_message_nums(
            imap,
            search_mailbox,
            manifest_row,
            create_if_missing=False,
            expected_content_identities=expected_content_identities,
        ):
            target_gmail_msgid = ""
            target_gmail_label_keys: set[str] = set()
            target_gmail_flags: set[str] = set()
            if target_provider == "gmail":
                target_gmail_msgid = _target_gmail_msgid(imap, target_num)
                physical_key: Tuple[Any, ...] = ("gmail", target_gmail_msgid)
                if manifest_row.get("routing_active") or manifest_row.get(
                    "_gmail_duplicate_allocation"
                ):
                    (
                        target_gmail_label_keys,
                        target_gmail_flags,
                        actual_internaldate,
                    ) = _target_gmail_label_flag_internaldate(imap, target_num)
                else:
                    actual_internaldate = target_message_internaldate(imap, target_num)
            else:
                physical_key = (
                    "imap",
                    _target_mailbox_lookup_key(search_mailbox, target_provider),
                    target_num,
                )
                actual_internaldate = target_message_internaldate(imap, target_num)
            candidate = {
                "physical_key": physical_key,
                "mailbox": search_mailbox,
                "num": target_num,
                "gmail_msgid": target_gmail_msgid,
                "internaldate": actual_internaldate,
                "gmail_label_keys": target_gmail_label_keys,
                "gmail_flags": target_gmail_flags,
            }
            # Gmail exposes one physical message through several label views.
            # Keep the first view returned by gmail_expected_target_mailboxes_for_row:
            # the row's primary target mailbox is deliberately first so metadata
            # restoration and validation operate on that view when it exists.
            if physical_key not in occurrences:
                occurrences[physical_key] = candidate
    return sorted(
        occurrences.values(),
        key=lambda item: repr(item["physical_key"]),
    )


def _maximum_target_candidate_assignments(
    candidates_by_row: Dict[str, List[Dict[str, Any]]],
    *,
    required_row_keys: Optional[set[str]] = None,
    unavailable_physical_keys: Optional[set[Tuple[Any, ...]]] = None,
    stop_event: Optional[object] = None,
) -> Dict[str, Dict[str, Any]]:
    required = required_row_keys or set()
    unavailable = unavailable_physical_keys or set()
    candidate_by_row_and_key = {
        (row_key, candidate["physical_key"]): candidate
        for row_key, candidates in candidates_by_row.items()
        for candidate in candidates
        if candidate["physical_key"] not in unavailable
    }
    keys_by_row = {
        row_key: sorted(
            {
                candidate["physical_key"]
                for candidate in candidates
                if candidate["physical_key"] not in unavailable
            },
            key=repr,
        )
        for row_key, candidates in candidates_by_row.items()
    }
    row_by_candidate: Dict[Tuple[Any, ...], str] = {}
    visited_edges = 0

    def assign_iteratively(root_row_key: str) -> bool:
        """Emulate the former recursive Kuhn DFS without Python stack use."""

        nonlocal visited_edges
        seen: set[Tuple[Any, ...]] = set()
        # Each frame is [row key, next candidate index, incoming candidate].
        # ``incoming candidate`` is the parent edge whose previous owner is
        # this frame's row.  On success it is reassigned while unwinding.
        frames: List[List[Any]] = [[root_row_key, 0, None]]
        while frames:
            row_key = str(frames[-1][0])
            candidate_index = int(frames[-1][1])
            if candidate_index >= len(keys_by_row[row_key]):
                frames.pop()
                continue
            candidate_key = keys_by_row[row_key][candidate_index]
            frames[-1][1] = candidate_index + 1
            if candidate_key in seen:
                continue
            seen.add(candidate_key)
            visited_edges += 1
            if visited_edges % 256 == 0:
                _raise_if_stopped(stop_event, "target candidate assignment")
            previous_row = row_by_candidate.get(candidate_key)
            if previous_row is not None:
                frames.append([previous_row, 0, candidate_key])
                continue

            # The deepest row takes the free edge.  Reassign each displaced
            # edge to its parent row in the same order as recursive unwind.
            row_by_candidate[candidate_key] = row_key
            while len(frames) > 1:
                child_frame = frames.pop()
                incoming_candidate = child_frame[2]
                parent_row = str(frames[-1][0])
                row_by_candidate[incoming_candidate] = parent_row
            return True
        return False

    for row_key in sorted(
        keys_by_row,
        key=lambda value: (
            0 if value in required else 1,
            len(keys_by_row[value]),
            value,
        ),
    ):
        _raise_if_stopped(stop_event, "target candidate assignment")
        assign_iteratively(row_key)
    return {
        row_key: candidate_by_row_and_key[(row_key, candidate_key)]
        for candidate_key, row_key in row_by_candidate.items()
    }


def _target_row_assignments(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    row_specs: Dict[str, Dict[str, Any]],
    *,
    target_provider: str,
    required_row_keys: Optional[set[str]] = None,
    unavailable_physical_keys: Optional[set[Tuple[Any, ...]]] = None,
    stop_event: Optional[object] = None,
) -> Dict[str, Dict[str, Any]]:
    candidates_by_row: Dict[str, List[Dict[str, Any]]] = {}
    fresh_evidence_rows: set[str] = set()
    for row_key, spec in row_specs.items():
        match_row = spec.get("match_row") or spec["manifest_row"]
        expected_date_key = ""
        if spec.get("require_internaldate_match"):
            expected_date_key = _legacy_internaldate_utc_key(
                match_row.get("internaldate")
            )
        raw_target_gmail_msgid = spec.get("target_gmail_msgid")
        target_gmail_msgid = str(raw_target_gmail_msgid or "")
        required_mailbox = str(spec.get("required_mailbox") or "")
        raw_pre_append_gmail_msgids = spec.get("pre_append_gmail_msgids")
        pre_append_gmail_msgids: Optional[set[str]] = None
        if (
            target_provider == "gmail"
            and raw_target_gmail_msgid not in (None, "")
            and not is_valid_gmail_msgid(raw_target_gmail_msgid)
        ):
            raise ProviderImportIntegrityGateError(
                f"invalid canonical Gmail target message ID for {row_key}: "
                f"{raw_target_gmail_msgid!r}"
            )
        if isinstance(raw_pre_append_gmail_msgids, (list, tuple, set, frozenset)):
            invalid_baseline = [
                value
                for value in raw_pre_append_gmail_msgids
                if not is_valid_gmail_msgid(value)
            ]
            if invalid_baseline:
                raise ProviderImportIntegrityGateError(
                    f"invalid canonical pre-APPEND Gmail-ID evidence for {row_key}: "
                    + ", ".join(sorted(repr(value) for value in invalid_baseline))
                )
            pre_append_gmail_msgids = {
                value for value in raw_pre_append_gmail_msgids
            }
        elif raw_pre_append_gmail_msgids is not None:
            raise ProviderImportIntegrityGateError(
                f"invalid pre-APPEND Gmail-ID evidence collection for {row_key}"
            )
        candidate_occurrences = _target_physical_occurrences_for_row(
            imap,
            spec["manifest_row"],
            spec["target_mailbox"],
            target_mailboxes,
            target_provider=target_provider,
            expected_content_identities=spec.get("expected_content_identities"),
        )
        if target_provider == "gmail" and (
            spec["manifest_row"].get("routing_active")
            or spec["manifest_row"].get("_gmail_duplicate_allocation")
        ):
            desired_profile = _gmail_required_destination_profile_for_row(
                spec["manifest_row"]
            )
            candidate_occurrences = [
                occurrence
                for occurrence in candidate_occurrences
                if not _gmail_destination_profile_conflicts(
                    (
                        desired_profile,
                        _gmail_destination_profile_for_target_candidate(
                            spec["manifest_row"],
                            occurrence.get("gmail_label_keys") or (),
                            occurrence.get("gmail_flags") or (),
                            str(occurrence.get("mailbox") or ""),
                            str(occurrence.get("gmail_msgid") or ""),
                            fresh_neutral_anchor_msgids=(
                                {
                                    str(occurrence.get("gmail_msgid") or "")
                                }
                                if pre_append_gmail_msgids is not None
                                and str(occurrence.get("gmail_msgid") or "")
                                not in pre_append_gmail_msgids
                                else None
                            ),
                        ),
                    )
                )
            ]
        candidates_by_row[row_key] = [
            occurrence
            for occurrence in candidate_occurrences
            if (
                not expected_date_key
                or _legacy_internaldate_utc_key(occurrence["internaldate"])
                == expected_date_key
            )
            and (
                not target_gmail_msgid
                or occurrence["gmail_msgid"] == target_gmail_msgid
            )
            and (
                pre_append_gmail_msgids is None
                or occurrence["gmail_msgid"] not in pre_append_gmail_msgids
            )
            and (
                not required_mailbox
                or spec["manifest_row"].get("_gmail_duplicate_allocation")
                or _target_mailbox_lookup_key(
                    occurrence["mailbox"],
                    target_provider,
                )
                == _target_mailbox_lookup_key(required_mailbox, target_provider)
            )
        ]
        if spec.get("require_unique_fresh_append") and candidates_by_row[row_key]:
            fresh_evidence_rows.add(row_key)

    effective_required = set(required_row_keys or set()) | fresh_evidence_rows
    assignments = _maximum_target_candidate_assignments(
        candidates_by_row,
        required_row_keys=effective_required,
        unavailable_physical_keys=unavailable_physical_keys,
        stop_event=stop_event,
    )
    missing_fresh = sorted(fresh_evidence_rows - set(assignments))
    if missing_fresh:
        raise ProviderImportIntegrityGateError(
            "cannot confirm pending/fresh Gmail APPENDs one-to-one from "
            "post-APPEND evidence: " + ", ".join(missing_fresh)
        )
    for row_key in sorted(fresh_evidence_rows):
        chosen_key = assignments[row_key]["physical_key"]
        candidates_without_chosen_edge = {
            candidate_row_key: [
                candidate
                for candidate in candidates
                if candidate_row_key != row_key
                or candidate["physical_key"] != chosen_key
            ]
            for candidate_row_key, candidates in candidates_by_row.items()
        }
        alternative = _maximum_target_candidate_assignments(
            candidates_without_chosen_edge,
            required_row_keys=effective_required,
            unavailable_physical_keys=unavailable_physical_keys,
            stop_event=stop_event,
        )
        if effective_required <= set(alternative):
            raise ProviderImportIntegrityGateError(
                f"cannot uniquely confirm fresh Gmail APPEND for {row_key}: "
                "multiple one-to-one post-APPEND physical allocations remain"
            )
    return assignments


def _gmail_pre_append_message_ids(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    row: Dict[str, Any],
    target_mailbox: str,
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]],
) -> List[str]:
    """Snapshot every dated physical content candidate before one APPEND."""

    expected_date_key = _legacy_internaldate_utc_key(row.get("internaldate"))
    return sorted(
        {
            str(occurrence.get("gmail_msgid") or "")
            for occurrence in _target_physical_occurrences_for_row(
                imap,
                row,
                target_mailbox,
                target_mailboxes,
                target_provider="gmail",
                expected_content_identities=expected_content_identities,
            )
            if occurrence.get("gmail_msgid")
            and (
                not expected_date_key
                or _legacy_internaldate_utc_key(occurrence.get("internaldate"))
                == expected_date_key
            )
        },
        key=lambda value: (len(value), value),
    )


def _gmail_confirmed_fresh_append_occurrence(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    row: Dict[str, Any],
    target_mailbox: str,
    pre_append_gmail_msgids: Iterable[str],
    *,
    expected_content_identities: Optional[Iterable[Tuple[int, str]]],
) -> Optional[Dict[str, Any]]:
    """Return only a uniquely proven post-APPEND Gmail physical message."""

    row_key = str(row.get("canonical_id") or "<fresh-append>")
    assignments = _target_row_assignments(
        imap,
        target_mailboxes,
        {
            row_key: {
                "manifest_row": row,
                "match_row": row,
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": "",
                "expected_content_identities": expected_content_identities,
                "require_internaldate_match": True,
                "pre_append_gmail_msgids": list(pre_append_gmail_msgids),
                "require_unique_fresh_append": True,
            }
        },
        target_provider="gmail",
        required_row_keys={row_key},
    )
    return assignments.get(row_key)


def require_one_to_one_committed_target_evidence(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    manifest_rows: List[Dict[str, Any]],
    journal_rows: List[Dict[str, Any]],
    target_mailbox_by_identity: Dict[str, str],
    *,
    target_provider: str,
    target_mode: str,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
) -> None:
    """Prove mandatory committed allocations before any recovery mutation."""
    latest_committed = latest_committed_journal_rows(
        journal_rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    )
    latest_status = latest_journal_rows(
        journal_rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    )
    row_specs: Dict[str, Dict[str, Any]] = {}
    required_identities: set[str] = set()
    committed_row_by_identity: Dict[str, Dict[str, Any]] = {}
    target_mailbox_by_required_identity: Dict[str, str] = {}
    for manifest_row in sorted(
        manifest_rows,
        key=lambda row: str(row.get("canonical_id") or ""),
    ):
        identity = str(manifest_row.get("canonical_id") or "")
        target_mailbox = target_mailbox_by_identity.get(identity)
        if not identity or not target_mailbox:
            continue
        key = journal_target_key(
            identity,
            target_mailbox,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        committed_row = latest_committed.get(key)
        if committed_row is not None:
            target_gmail_msgid = str(
                committed_row.get("target_gmail_msgid") or ""
            )
            legacy_existing_without_date_evidence = (
                committed_row.get("action") == "existing"
                and _existing_content_reuse_target_internaldate(
                    manifest_row,
                    committed_row,
                )
                is None
            )
            row_specs[identity] = {
                "manifest_row": manifest_row,
                "match_row": _committed_target_match_row(
                    manifest_row,
                    committed_row,
                ),
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": target_gmail_msgid,
                "expected_content_identities": expected_content_identities_by_id.get(
                    identity
                ),
                "require_internaldate_match": not legacy_existing_without_date_evidence,
            }
            if target_mode == "empty" or (
                target_provider == "gmail" and target_gmail_msgid
            ):
                required_identities.add(identity)
                committed_row_by_identity[identity] = committed_row
                target_mailbox_by_required_identity[identity] = target_mailbox
            continue
        status_row = latest_status.get(key)
        if target_mode == "merge" or (
            status_row is not None and status_row.get("status") == "pending"
        ):
            row_specs[identity] = {
                "manifest_row": manifest_row,
                "match_row": manifest_row,
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": "",
                "expected_content_identities": expected_content_identities_by_id.get(
                    identity
                ),
                "require_internaldate_match": bool(
                    status_row is not None and status_row.get("status") == "pending"
                ),
            }
    if not required_identities:
        return
    assignments = _target_row_assignments(
        imap,
        target_mailboxes,
        row_specs,
        target_provider=target_provider,
        required_row_keys=required_identities,
    )
    for identity in sorted(required_identities):
        if identity in assignments:
            continue
        target_mailbox = target_mailbox_by_required_identity[identity]
        target_gmail_msgid = str(
            committed_row_by_identity[identity].get("target_gmail_msgid") or ""
        )
        if target_provider == "gmail" and target_gmail_msgid:
            raise ProviderImportIntegrityGateError(
                f"journal says {identity} is committed to Gmail target message "
                f"{target_gmail_msgid} in {target_mailbox!r}, but that exact "
                "target message was not found"
            )
        raise ProviderImportIntegrityGateError(
            f"journal says {identity} is committed to {target_mailbox!r}, "
            "but the target message was not found"
        )


def require_recovery_stages_live_integrity(
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    target_mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> Dict[str, str]:
    """Validate live-canonicalized stage evidence before any stage mutates."""
    ordered_stages = sorted(
        stages,
        key=lambda stage: (
            stage[0].source_email.casefold(),
            stage[0].source_email,
        ),
    )
    content_issues: List[str] = []
    for group_account, _account_dir, manifest_rows, journal_rows in ordered_stages:
        stage_issues = committed_journal_manifest_content_issues(
            journal_rows,
            manifest_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        stage_issues.extend(
            pending_journal_manifest_content_issues(
                journal_rows,
                manifest_rows,
                target_provider=target_provider,
                target_mailboxes=target_mailboxes,
            )
        )
        content_issues.extend(
            f"{group_account.source_email}: {issue}"
            for issue in stage_issues
        )
    if content_issues:
        raise ProviderImportIntegrityGateError(
            "invalid import journal: " + "; ".join(content_issues)
        )

    if target_provider == "gmail":
        system_mailbox_issues = [
            f"{group_account.source_email}: {issue}"
            for group_account, _account_dir, manifest_rows, _journal_rows in ordered_stages
            for issue in gmail_target_system_mailbox_issues(
                manifest_rows,
                target_mailboxes,
            )
        ]
        if system_mailbox_issues:
            raise ProviderImportIntegrityGateError(
                "Gmail target is not import-ready: "
                + "; ".join(system_mailbox_issues)
            )

    combined_rows = [
        row
        for _group_account, _account_dir, manifest_rows, _journal_rows in ordered_stages
        for row in sorted(
            manifest_rows,
            key=lambda manifest_row: str(
                manifest_row.get("canonical_id") or ""
            ),
        )
    ]
    target_mailbox_by_identity = translated_target_mailboxes_for_rows(
        combined_rows,
        target_mailboxes,
        target_provider=target_provider,
    )
    target_binding_issues: List[str] = []
    for group_account, _account_dir, manifest_rows, journal_rows in ordered_stages:
        stage_identities = {
            str(row.get("canonical_id") or "")
            for row in manifest_rows
            if row.get("canonical_id")
        }
        stage_target_mailbox_by_identity = {
            identity: target_mailbox
            for identity, target_mailbox in target_mailbox_by_identity.items()
            if identity in stage_identities
        }
        stage_issues = committed_journal_target_mailbox_issues(
            journal_rows,
            stage_target_mailbox_by_identity,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        stage_issues.extend(
            pending_journal_target_mailbox_issues(
                journal_rows,
                stage_target_mailbox_by_identity,
                target_provider=target_provider,
                target_mailboxes=target_mailboxes,
            )
        )
        target_binding_issues.extend(
            f"{group_account.source_email}: {issue}"
            for issue in stage_issues
        )
    if target_binding_issues:
        raise ProviderImportIntegrityGateError(
            "invalid import journal: " + "; ".join(target_binding_issues)
        )
    return target_mailbox_by_identity


def require_merge_group_journals_remote_complete(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    *,
    target_provider: str,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
    allow_unresolved_pending: bool = False,
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
            if allow_unresolved_pending:
                continue
            raise ProviderImportIntegrityGateError(
                f"merge group source {group_account.source_email} has unresolved pending import journal row: "
                f"{identity} in {target_mailbox}"
            )
        row_by_id = {
            str(row.get("canonical_id") or ""): row
            for row in manifest_rows
            if row.get("canonical_id")
        }
        committed_specs: Dict[str, Dict[str, Any]] = {}
        journal_row_by_identity: Dict[str, Dict[str, Any]] = {}
        for (identity, _target_mailbox_key), journal_row in sorted(latest_committed.items()):
            target_mailbox = str(journal_row.get("target_mailbox") or "")
            manifest_row = row_by_id.get(identity)
            if manifest_row is None:
                continue
            committed_specs[identity] = {
                "manifest_row": manifest_row,
                "match_row": _committed_target_match_row(manifest_row, journal_row),
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": str(journal_row.get("target_gmail_msgid") or ""),
                "expected_content_identities": expected_content_identities_by_id.get(identity),
                "require_internaldate_match": True,
            }
            journal_row_by_identity[identity] = journal_row
        committed_assignments = _target_row_assignments(
            imap,
            target_mailboxes,
            committed_specs,
            target_provider=target_provider,
            required_row_keys=set(committed_specs),
        )
        for identity, spec in committed_specs.items():
            if identity in committed_assignments:
                continue
            journal_row = journal_row_by_identity[identity]
            target_mailbox = spec["target_mailbox"]
            target_gmail_msgid = str(journal_row.get("target_gmail_msgid") or "")
            if target_provider == "gmail" and target_gmail_msgid:
                raise ProviderImportIntegrityGateError(
                    f"merge group journal says {identity} from {group_account.source_email} "
                    f"is committed to Gmail target message {target_gmail_msgid} in {target_mailbox!r}, "
                    "but that exact target message was not found"
                )
            raise ProviderImportIntegrityGateError(
                f"merge group journal says {identity} from {group_account.source_email} "
                f"is committed to {target_mailbox!r}, but the target message was not found"
            )


def require_merge_group_pending_internaldates_compatible(
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    *,
    target_provider: str,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
) -> List[Dict[str, Any]]:
    """Return compatible physical content classes for strict journal recovery.

    A many-to-one target needs only the largest physical multiplicity exported
    by any one source.  Sources may reuse those physical occurrences, but rows
    within one source remain distinct.  Committed target-date evidence and
    unresolved pending source dates reserve strict dated occurrences.  For one
    physical mailbox/content class the invariant is therefore::

        capacity = max_source(total manifest rows)
        required = sum(max_source(strict rows at UTC-equivalent date))

    Compatibility requires ``required <= capacity``.  Content identity sets
    are unioned transitively so raw/APPEND-wire identity variants cannot make
    the result depend on manifest or source ordering.
    """

    entries: List[Dict[str, Any]] = []
    for group_account, _account_dir, manifest_rows, journal_rows in stages:
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=target_provider,
        )
        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        latest_status = latest_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        for manifest_row in manifest_rows:
            identity = str(manifest_row.get("canonical_id") or "")
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not identity or not target_mailbox:
                continue
            target_key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=target_provider,
                target_mailboxes=target_mailboxes,
            )
            journal_row = latest_committed.get(target_key)
            strict_status = "committed" if journal_row is not None else ""
            if journal_row is None:
                candidate = latest_status.get(target_key)
                if candidate is not None and candidate.get("status") == "pending":
                    journal_row = candidate
                    strict_status = "pending"
            physical_target_key = (
                "gmail-physical-message"
                if target_provider == "gmail"
                else _target_mailbox_lookup_key(target_mailbox, target_provider)
            )
            strict_internaldate = ""
            strict_date_key = ""
            if strict_status == "committed" and journal_row is not None:
                strict_internaldate = _normalized_provider_internaldate(
                    _committed_target_match_row(manifest_row, journal_row).get("internaldate")
                )
                strict_date_key = _legacy_internaldate_utc_key(strict_internaldate)
            elif strict_status == "pending":
                strict_internaldate = _normalized_provider_internaldate(
                    manifest_row.get("internaldate")
                )
                strict_date_key = _legacy_internaldate_utc_key(strict_internaldate)
            entries.append({
                "source_email": group_account.source_email,
                "identity": identity,
                "target_mailbox": target_mailbox,
                "physical_target_key": physical_target_key,
                "content_identities": _expected_content_identities(
                    manifest_row,
                    expected_content_identities_by_id.get(identity),
                ),
                "manifest_row": manifest_row,
                "journal_row": journal_row,
                "strict_status": strict_status,
                "strict_internaldate": strict_internaldate,
                "strict_date_key": strict_date_key,
            })

    entries.sort(
        key=lambda item: (
            item["physical_target_key"],
            item["source_email"].casefold(),
            item["source_email"],
            item["identity"],
        )
    )
    parents = list(range(len(entries)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parents[right_root] = left_root
        else:
            parents[left_root] = right_root

    first_entry_by_content: Dict[Tuple[str, Tuple[int, str]], int] = {}
    for index, entry in enumerate(entries):
        for content_identity in sorted(entry["content_identities"]):
            content_key = (entry["physical_target_key"], content_identity)
            previous = first_entry_by_content.setdefault(content_key, index)
            union(index, previous)

    entries_by_class: Dict[int, List[Dict[str, Any]]] = {}
    for index, entry in enumerate(entries):
        entries_by_class.setdefault(find(index), []).append(entry)

    classes: List[Dict[str, Any]] = []
    missing_dates: List[str] = []
    capacity_conflicts: List[str] = []
    for class_entries in entries_by_class.values():
        class_entries.sort(
            key=lambda item: (
                item["source_email"].casefold(),
                item["source_email"],
                item["identity"],
            )
        )
        total_by_source: Dict[str, int] = {}
        strict_by_date_source: Dict[str, Dict[str, int]] = {}
        date_display: Dict[str, str] = {}
        for entry in class_entries:
            source_key = entry["source_email"].casefold()
            total_by_source[source_key] = total_by_source.get(source_key, 0) + 1
            strict_status = entry["strict_status"]
            if not strict_status:
                continue
            date_key = entry["strict_date_key"]
            if not date_key:
                missing_dates.append(
                    f"{entry['source_email']}/{entry['identity']} "
                    f"({strict_status}) has {entry['strict_internaldate'] or '<missing>'}"
                )
                continue
            date_display.setdefault(date_key, entry["strict_internaldate"])
            by_source = strict_by_date_source.setdefault(date_key, {})
            by_source[source_key] = by_source.get(source_key, 0) + 1

        capacity = max(total_by_source.values(), default=0)
        required_by_date = {
            date_key: max(by_source.values(), default=0)
            for date_key, by_source in strict_by_date_source.items()
        }
        required = sum(required_by_date.values())
        target_label = (
            "Gmail physical message"
            if target_provider == "gmail"
            else repr(class_entries[0]["target_mailbox"])
        )
        if required > capacity:
            reservations = ", ".join(
                f"{date_display[date_key]} x{required_by_date[date_key]}"
                for date_key in sorted(required_by_date, key=lambda value: int(value))
            )
            reservation_rows = ", ".join(
                f"{entry['source_email']}/{entry['identity']}"
                for entry in class_entries
                if entry["strict_status"]
            )
            capacity_conflicts.append(
                f"overlapping content in {target_label} requires {required} physical "
                f"dated occurrence(s) ({reservations}) but per-source manifest capacity is {capacity}"
                f"; rows {reservation_rows}"
            )
        classes.append({
            "physical_target_key": class_entries[0]["physical_target_key"],
            "target_mailboxes": sorted(
                {str(entry["target_mailbox"]) for entry in class_entries},
                key=lambda value: (value.casefold(), value),
            ),
            "content_identities": set().union(
                *(entry["content_identities"] for entry in class_entries)
            ),
            "entries": class_entries,
            "capacity": capacity,
            "required_by_date": required_by_date,
            "date_display": date_display,
            "has_pending": any(
                entry["strict_status"] == "pending" for entry in class_entries
            ),
        })

    if missing_dates:
        raise ProviderImportIntegrityGateError(
            "merge group unresolved pending APPENDs have missing or unconfirmable "
            "INTERNALDATE values: " + "; ".join(sorted(missing_dates))
        )
    if capacity_conflicts:
        raise ProviderImportIntegrityGateError(
            "merge group unresolved pending APPENDs have incompatible INTERNALDATE values: "
            + "; ".join(sorted(capacity_conflicts))
        )
    classes.sort(
        key=lambda item: (
            item["physical_target_key"],
            tuple(item["target_mailboxes"]),
            sorted(item["content_identities"]),
        )
    )
    return classes


def require_merge_group_pending_target_capacity_compatible(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    capacity_classes: List[Dict[str, Any]],
    *,
    target_provider: str,
) -> None:
    """Prove strict pending recovery fits before any target or journal write."""

    capacity_issues: List[str] = []
    for content_class in capacity_classes:
        if not content_class["has_pending"]:
            continue
        occurrences: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for entry in content_class["entries"]:
            for occurrence in _target_physical_occurrences_for_row(
                imap,
                entry["manifest_row"],
                entry["target_mailbox"],
                target_mailboxes,
                target_provider=target_provider,
                expected_content_identities=entry["content_identities"],
            ):
                occurrences.setdefault(occurrence["physical_key"], occurrence)
        strict_entries_by_source: Dict[str, List[Dict[str, Any]]] = {}
        for entry in content_class["entries"]:
            if entry["strict_status"]:
                strict_entries_by_source.setdefault(
                    entry["source_email"].casefold(),
                    [],
                ).append(entry)
        unmatched_by_date_source: Dict[str, Dict[str, int]] = {}
        for source_key, source_entries in strict_entries_by_source.items():
            strict_specs = {
                entry["identity"]: {
                    "manifest_row": entry["manifest_row"],
                    "match_row": (
                        _committed_target_match_row(
                            entry["manifest_row"],
                            entry["journal_row"],
                        )
                        if entry["strict_status"] == "committed"
                        else entry["manifest_row"]
                    ),
                    "target_mailbox": entry["target_mailbox"],
                    "target_gmail_msgid": (
                        str(entry["journal_row"].get("target_gmail_msgid") or "")
                        if entry["strict_status"] == "committed"
                        else ""
                    ),
                    "expected_content_identities": entry["content_identities"],
                    "require_internaldate_match": True,
                }
                for entry in source_entries
            }
            assignments = _target_row_assignments(
                imap,
                target_mailboxes,
                strict_specs,
                target_provider=target_provider,
                required_row_keys={
                    entry["identity"]
                    for entry in source_entries
                    if entry["strict_status"] == "committed"
                },
            )
            for entry in source_entries:
                if entry["identity"] in assignments:
                    continue
                by_source = unmatched_by_date_source.setdefault(
                    entry["strict_date_key"],
                    {},
                )
                by_source[source_key] = by_source.get(source_key, 0) + 1
        missing_required = sum(
            max(by_source.values(), default=0)
            for by_source in unmatched_by_date_source.values()
        )
        completed_physical_count = len(occurrences) + missing_required
        if completed_physical_count <= content_class["capacity"]:
            continue
        observed_dates = ", ".join(
            sorted(
                {
                    str(occurrence["internaldate"] or "<missing>")
                    for occurrence in occurrences.values()
                }
            )
        ) or "<empty target>"
        target_label = (
            "Gmail physical message"
            if target_provider == "gmail"
            else repr(content_class["target_mailboxes"][0])
        )
        capacity_issues.append(
            f"overlapping content in {target_label} has {len(occurrences)} existing "
            f"physical occurrence(s) at {observed_dates} and needs {missing_required} "
            f"additional dated occurrence(s), exceeding manifest capacity "
            f"{content_class['capacity']}"
        )
    if capacity_issues:
        raise ProviderImportIntegrityGateError(
            "cannot confirm pending append recovery without exceeding physical content capacity: "
            + "; ".join(sorted(capacity_issues))
        )


def require_pending_gmail_append_evidence_safe(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    stages: List[
        Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]
    ],
    *,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
    stop_event: Optional[object] = None,
) -> Dict[Tuple[int, str, str], Dict[str, Any]]:
    """Read-only safety proof for every unresolved Gmail pending APPEND.

    Baselined rows are matched in one global graph so nested fresh-candidate
    sets cannot each claim the same physical message.  A baselined row with no
    post-APPEND candidate remains retryable.  Legacy neutral-anchor rows cannot
    be recovered safely and fail before missing-ID repair can write.
    """

    pending_specs: Dict[str, Dict[str, Any]] = {}
    pending_key_by_row_key: Dict[str, Tuple[int, str, str]] = {}
    for stage_index, (
        group_account,
        _account_dir,
        manifest_rows,
        journal_rows,
    ) in enumerate(stages):
        _raise_if_stopped(
            stop_event,
            f"provider import {group_account.target_email}",
        )
        manifest_by_id = {
            str(row.get("canonical_id") or ""): row
            for row in manifest_rows
            if row.get("canonical_id")
        }
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider="gmail",
        )
        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider="gmail",
            target_mailboxes=target_mailboxes,
        )
        latest_status = latest_journal_rows(
            journal_rows,
            target_provider="gmail",
            target_mailboxes=target_mailboxes,
        )
        for journal_key, pending_row in sorted(latest_status.items()):
            if (
                pending_row.get("status") != "pending"
                or journal_key in latest_committed
            ):
                continue
            identity = str(pending_row.get("canonical_id") or "")
            manifest_row = manifest_by_id.get(identity)
            if manifest_row is None:
                raise ProviderImportIntegrityGateError(
                    "invalid import journal: journal pending identity not in manifest: "
                    + (identity or "<missing>")
                )
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not target_mailbox:
                raise ProviderImportIntegrityGateError(
                    "invalid import journal: journal pending identity has no target mailbox: "
                    + identity
                )
            raw_baseline = pending_row.get("pre_append_gmail_msgids")
            if raw_baseline is None:
                if _gmail_pending_needs_neutral_anchor_evidence(manifest_row):
                    raise ProviderImportIntegrityGateError(
                        f"cannot safely recover legacy pending Gmail APPEND {identity}: "
                        "its allocated Spam/Trash slot may currently use an All Mail "
                        "append anchor, but the pending journal predates durable "
                        "pre-APPEND Gmail-ID evidence"
                    )
                continue
            if not isinstance(raw_baseline, list) or any(
                not is_valid_gmail_msgid(value) for value in raw_baseline
            ):
                raise ProviderImportIntegrityGateError(
                    f"invalid canonical pre-APPEND Gmail-ID evidence for {identity}"
                )
            row_key = (
                f"{stage_index:08d}\0{group_account.source_email.casefold()}\0"
                f"{identity}"
            )
            pending_specs[row_key] = {
                "manifest_row": manifest_row,
                "match_row": manifest_row,
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": "",
                "expected_content_identities": (
                    expected_content_identities_by_id.get(identity)
                ),
                "require_internaldate_match": True,
                "pre_append_gmail_msgids": list(raw_baseline),
                "require_unique_fresh_append": True,
            }
            pending_key_by_row_key[row_key] = (
                stage_index,
                group_account.source_email.casefold(),
                identity,
            )

    if pending_specs:
        assignments = _target_row_assignments(
            imap,
            target_mailboxes,
            pending_specs,
            target_provider="gmail",
            stop_event=stop_event,
        )
        return {
            pending_key_by_row_key[row_key]: occurrence
            for row_key, occurrence in assignments.items()
            if row_key in pending_key_by_row_key
        }
    return {}


def recover_merge_group_pending_appends(
    config: ProviderMigrationConfig,
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
    *,
    expected_content_identities_by_id: Dict[str, set[Tuple[int, str]]],
    limiter: RateLimiter,
    stop_event: Optional[object] = None,
    allow_unmatched_committed: bool = False,
) -> None:
    """Resolve every pending APPEND in a target group before ordinary import work.

    The inspection pass is intentionally separated from the mutation pass.  A
    byte-identical message with a different INTERNALDATE is therefore reported
    before a retry APPEND (or another source's ordinary APPEND) can run.
    """

    target_provider = config.target.provider
    globally_confirmed_pending: Dict[
        Tuple[int, str, str],
        Dict[str, Any],
    ] = {}
    if target_provider == "gmail":
        globally_confirmed_pending = require_pending_gmail_append_evidence_safe(
            imap,
            target_mailboxes,
            stages,
            expected_content_identities_by_id=expected_content_identities_by_id,
            stop_event=stop_event,
        )
    capacity_classes = require_merge_group_pending_internaldates_compatible(
        target_mailboxes,
        stages,
        target_provider=target_provider,
        expected_content_identities_by_id=expected_content_identities_by_id,
    )
    recovery_items: List[Dict[str, Any]] = []

    def reject_unconfirmed_internaldate(
        identity: str,
        manifest_row: Dict[str, Any],
        target_mailbox: str,
        expected_content_identities: Optional[Iterable[Tuple[int, str]]],
        used_target_nums: Dict[str, set[bytes]],
        used_target_gmail_msgids: set[str],
    ) -> None:
        search_mailboxes = [target_mailbox]
        if target_provider == "gmail":
            search_mailboxes = gmail_expected_target_mailboxes_for_row(
                manifest_row,
                target_mailbox,
                target_mailboxes,
            )
        observations: List[Tuple[str, str]] = []
        for search_mailbox in search_mailboxes:
            mailbox_key = _target_mailbox_lookup_key(
                search_mailbox,
                "gmail" if target_provider == "gmail" else "imap",
            )
            used_nums = used_target_nums.get(mailbox_key, set())
            for target_num in target_matching_message_nums(
                imap,
                search_mailbox,
                manifest_row,
                create_if_missing=False,
                expected_content_identities=expected_content_identities,
            ):
                if target_num in used_nums:
                    continue
                if target_provider == "gmail":
                    target_gmail_msgid = _target_gmail_msgid(imap, target_num)
                    if (
                        target_gmail_msgid
                        and target_gmail_msgid in used_target_gmail_msgids
                    ):
                        continue
                observations.append(
                    (search_mailbox, target_message_internaldate(imap, target_num))
                )
        if not observations:
            return
        expected_internaldate = _normalized_provider_internaldate(
            manifest_row.get("internaldate")
        )
        if any(
            _legacy_internaldates_equal(actual_internaldate, expected_internaldate)
            for _mailbox, actual_internaldate in observations
        ):
            return
        observed = ", ".join(
            sorted(
                {
                    f"{mailbox}: {actual_internaldate or '<missing>'}"
                    for mailbox, actual_internaldate in observations
                }
            )
        )
        raise RuntimeError(
            f"cannot confirm pending append recovery for {identity} in {target_mailbox!r}: "
            f"byte-identical target content has INTERNALDATE {observed}; expected "
            f"{expected_internaldate or '<missing>'}; no committed journal row was written"
        )

    # Establish that completing every missing strict row cannot exceed the
    # physical multiplicity exported by any source.  This is one global
    # inspection before journal or target mutation.  Raw counts per date are
    # insufficient: an LF occurrence at D2 can match a broad LF/CRLF row but
    # not a narrow CRLF-only row reserved at D2.  Match the actual dated rows
    # for every source so only usable occurrences reduce its missing demand.
    capacity_class_by_source_identity = {
        (entry["source_email"].casefold(), entry["identity"]): content_class
        for content_class in capacity_classes
        for entry in content_class["entries"]
    }
    recovery_batches: List[List[Dict[str, Any]]] = []

    # Reserve committed and pending rows in one maximum matching per source.
    # Cross-source reuse is intentional in many-to-one mode, while two rows in
    # one source still require distinct physical occurrences.  Committed rows
    # are processed first and remain mandatory, but may be rerouted along an
    # augmenting path so a broad raw/wire identity does not steal the only
    # candidate available to a narrower pending row.
    for stage_index, (
        group_account,
        account_dir,
        manifest_rows,
        journal_rows,
    ) in enumerate(stages):
        _raise_if_stopped(stop_event, f"provider import {group_account.target_email}")
        manifest_row_by_identity = {
            str(row.get("canonical_id") or ""): row
            for row in manifest_rows
            if row.get("canonical_id")
        }
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=target_provider,
        )
        pending_target_issues = pending_journal_target_mailbox_issues(
            journal_rows,
            target_mailbox_by_identity,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        if pending_target_issues:
            raise ProviderImportIntegrityGateError(
                f"invalid import journal for merge source {group_account.source_email}: "
                + "; ".join(pending_target_issues)
            )

        latest_committed = latest_committed_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        latest_status = latest_journal_rows(
            journal_rows,
            target_provider=target_provider,
            target_mailboxes=target_mailboxes,
        )
        committed_keys = set(latest_committed)
        used_target_nums: Dict[str, set[bytes]] = {}
        used_target_gmail_msgids: set[str] = set()
        used_physical_keys: set[Tuple[Any, ...]] = set()
        strict_specs: Dict[str, Dict[str, Any]] = {}
        committed_items: Dict[str, Dict[str, Any]] = {}
        for (identity, _target_mailbox_key), journal_row in sorted(latest_committed.items()):
            manifest_row = manifest_row_by_identity.get(identity)
            if manifest_row is None:
                continue
            target_mailbox = str(journal_row.get("target_mailbox") or "")
            expected_content_identities = expected_content_identities_by_id.get(identity)
            committed_match_row = _committed_target_match_row(manifest_row, journal_row)
            target_gmail_msgid = str(journal_row.get("target_gmail_msgid") or "")
            committed_items[identity] = {
                "identity": identity,
                "journal_row": journal_row,
            }
            strict_specs[identity] = {
                "manifest_row": manifest_row,
                "match_row": committed_match_row,
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": target_gmail_msgid,
                "expected_content_identities": expected_content_identities,
                "require_internaldate_match": True,
            }

        pending_items: Dict[str, Dict[str, Any]] = {}
        for key, pending_row in sorted(latest_status.items()):
            if pending_row.get("status") != "pending" or key in committed_keys:
                continue
            identity = str(pending_row.get("canonical_id") or "")
            manifest_row = manifest_row_by_identity.get(identity)
            if manifest_row is None:
                raise RuntimeError(
                    "invalid import journal: journal pending identity not in manifest: "
                    + (identity or "<missing>")
                )
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not target_mailbox:
                raise RuntimeError(
                    "invalid import journal: journal pending identity has no target mailbox: "
                    + identity
                )
            expected_content_identities = expected_content_identities_by_id.get(identity)
            raw_pre_append_gmail_msgids = pending_row.get(
                "pre_append_gmail_msgids"
            )
            pre_append_gmail_msgids = (
                list(raw_pre_append_gmail_msgids)
                if isinstance(raw_pre_append_gmail_msgids, list)
                else None
            )
            globally_confirmed = globally_confirmed_pending.get(
                (
                    stage_index,
                    group_account.source_email.casefold(),
                    identity,
                )
            )
            globally_confirmed_gmail_msgid = (
                str(globally_confirmed.get("gmail_msgid") or "")
                if globally_confirmed is not None
                else ""
            )
            if (
                target_provider == "gmail"
                and pre_append_gmail_msgids is None
                and _gmail_pending_needs_neutral_anchor_evidence(manifest_row)
            ):
                raise ProviderImportIntegrityGateError(
                    f"cannot safely recover legacy pending Gmail APPEND {identity}: "
                    "its allocated Spam/Trash slot may currently use an All Mail "
                    "append anchor, but the pending journal predates durable "
                    "pre-APPEND Gmail-ID evidence"
                )
            pending_items[identity] = {
                "account": group_account,
                "account_dir": account_dir,
                "journal_rows": journal_rows,
                "manifest_row": manifest_row,
                "identity": identity,
                "target_mailbox": target_mailbox,
                "expected_content_identities": expected_content_identities,
                "pre_append_gmail_msgids": pre_append_gmail_msgids,
                "globally_confirmed_gmail_msgid": (
                    globally_confirmed_gmail_msgid
                ),
            }
            strict_specs[identity] = {
                "manifest_row": manifest_row,
                "match_row": manifest_row,
                "target_mailbox": target_mailbox,
                "target_gmail_msgid": globally_confirmed_gmail_msgid,
                "expected_content_identities": expected_content_identities,
                "require_internaldate_match": True,
                "pre_append_gmail_msgids": pre_append_gmail_msgids,
                "require_unique_fresh_append": (
                    pre_append_gmail_msgids is not None
                ),
            }

        strict_assignments = _target_row_assignments(
            imap,
            target_mailboxes,
            strict_specs,
            target_provider=target_provider,
            required_row_keys=set(committed_items),
            stop_event=stop_event,
        )
        for row_key, item in committed_items.items():
            if row_key not in strict_assignments:
                if allow_unmatched_committed:
                    continue
                raise RuntimeError(
                    "merge group journal changed while pending APPENDs were being recovered: "
                    f"{item['identity']} from {group_account.source_email} is no longer present"
                )
        for occurrence in strict_assignments.values():
            used_physical_keys.add(occurrence["physical_key"])
            used_target_nums.setdefault(
                _target_mailbox_lookup_key(
                    occurrence["mailbox"],
                    "gmail" if target_provider == "gmail" else target_provider,
                ),
                set(),
            ).add(occurrence["num"])
            if occurrence["gmail_msgid"]:
                used_target_gmail_msgids.add(occurrence["gmail_msgid"])

        recovery_batch: List[Dict[str, Any]] = []
        for row_key, item in pending_items.items():
            occurrence = strict_assignments.get(row_key)
            matched_mailbox = item["target_mailbox"]
            matched_num: Optional[bytes] = None
            matched_gmail_msgid = ""
            matched_internaldate = ""
            if occurrence is not None:
                matched_mailbox = occurrence["mailbox"]
                matched_num = occurrence["num"]
                matched_gmail_msgid = occurrence["gmail_msgid"]
                matched_internaldate = str(occurrence.get("internaldate") or "")
            recovery_item = {
                **item,
                "used_target_nums": used_target_nums,
                "used_target_gmail_msgids": used_target_gmail_msgids,
                "used_physical_keys": used_physical_keys,
                "matched_mailbox": matched_mailbox,
                "matched_num": matched_num,
                "matched_gmail_msgid": matched_gmail_msgid,
                "matched_internaldate": matched_internaldate,
                "capacity_class": capacity_class_by_source_identity[
                    (group_account.source_email.casefold(), row_key)
                ],
            }
            recovery_items.append(recovery_item)
            recovery_batch.append(recovery_item)
        if recovery_batch:
            recovery_batches.append(recovery_batch)

    recovery_batch_by_first_item = {
        id(batch[0]): batch for batch in recovery_batches
    }
    for item in recovery_items:
        recovery_batch = recovery_batch_by_first_item.get(id(item))
        if recovery_batch is not None:
            unmatched_specs = {
                batch_item["identity"]: {
                    "manifest_row": batch_item["manifest_row"],
                    "match_row": batch_item["manifest_row"],
                    "target_mailbox": batch_item["target_mailbox"],
                    "target_gmail_msgid": batch_item[
                        "globally_confirmed_gmail_msgid"
                    ],
                    "expected_content_identities": batch_item["expected_content_identities"],
                    "require_internaldate_match": True,
                    "pre_append_gmail_msgids": batch_item[
                        "pre_append_gmail_msgids"
                    ],
                    "require_unique_fresh_append": (
                        batch_item["pre_append_gmail_msgids"] is not None
                    ),
                }
                for batch_item in recovery_batch
                if batch_item["matched_num"] is None
            }
            if unmatched_specs:
                close_assignments = _target_row_assignments(
                    imap,
                    target_mailboxes,
                    unmatched_specs,
                    target_provider=target_provider,
                    unavailable_physical_keys=item["used_physical_keys"],
                    stop_event=stop_event,
                )
                for batch_item in recovery_batch:
                    occurrence = close_assignments.get(batch_item["identity"])
                    if occurrence is None:
                        continue
                    batch_item["matched_mailbox"] = occurrence["mailbox"]
                    batch_item["matched_num"] = occurrence["num"]
                    batch_item["matched_gmail_msgid"] = occurrence["gmail_msgid"]
                    batch_item["matched_internaldate"] = str(
                        occurrence.get("internaldate") or ""
                    )
                    batch_item["used_physical_keys"].add(occurrence["physical_key"])
                    batch_item["used_target_nums"].setdefault(
                        _target_mailbox_lookup_key(
                            occurrence["mailbox"],
                            "gmail" if target_provider == "gmail" else target_provider,
                        ),
                        set(),
                    ).add(occurrence["num"])
                    if occurrence["gmail_msgid"]:
                        batch_item["used_target_gmail_msgids"].add(
                            occurrence["gmail_msgid"]
                        )
        group_account = item["account"]
        account_dir = item["account_dir"]
        journal_rows = item["journal_rows"]
        manifest_row = item["manifest_row"]
        identity = item["identity"]
        target_mailbox = item["target_mailbox"]
        expected_content_identities = item["expected_content_identities"]
        used_target_nums = item["used_target_nums"]
        used_target_gmail_msgids = item["used_target_gmail_msgids"]
        matched_mailbox = item["matched_mailbox"]
        matched_num = item["matched_num"]
        matched_gmail_msgid = item["matched_gmail_msgid"]
        matched_internaldate = item["matched_internaldate"]
        target_binding = provider_target_journal_binding(config, group_account)
        _raise_if_stopped(stop_event, f"provider import {group_account.target_email}")

        if matched_num is None:
            content_class = item["capacity_class"]
            current_occurrences: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
            for class_entry in content_class["entries"]:
                for occurrence in _target_physical_occurrences_for_row(
                    imap,
                    class_entry["manifest_row"],
                    class_entry["target_mailbox"],
                    target_mailboxes,
                    target_provider=target_provider,
                    expected_content_identities=class_entry["content_identities"],
                ):
                    current_occurrences.setdefault(
                        occurrence["physical_key"],
                        occurrence,
                    )
            if len(current_occurrences) >= content_class["capacity"]:
                raise RuntimeError(
                    f"cannot append pending recovery for {identity} in {target_mailbox!r}: "
                    f"physical content capacity {content_class['capacity']} is already full"
                )
            data = _read_provider_artifact_bytes(
                _manifest_path(account_dir, manifest_row, "eml_path"),
                "provider message artifact",
            )
            ensure_mailbox(imap, target_mailbox)
            retry_pre_append_gmail_msgids: Optional[List[str]] = None
            if target_provider == "gmail":
                retry_pre_append_gmail_msgids = _gmail_pre_append_message_ids(
                    imap,
                    target_mailboxes,
                    manifest_row,
                    target_mailbox,
                    expected_content_identities=expected_content_identities,
                )
            append_flags = _flags_for_provider_append(
                str(manifest_row.get("flags") or ""),
                target_provider=target_provider,
                permanent_flags=target_permanent_flags(imap),
            )
            _provider_throttle_wait(
                limiter,
                len(data),
                stop_event=stop_event,
                label=f"provider import {group_account.target_email}",
            )
            retry_pending = _journal_row(
                manifest_row,
                target_mailbox,
                "pending",
                "append-started",
                target_binding=target_binding,
                pre_append_gmail_msgids=retry_pre_append_gmail_msgids,
            )
            append_journal(account_dir, group_account, retry_pending)
            journal_rows.append(retry_pending)
            status, response = append_message(
                imap,
                target_mailbox,
                append_flags,
                _internaldate_for_append(str(manifest_row.get("internaldate") or "")),
                data,
            )
            if status != "OK":
                failed_row = _journal_row(
                    manifest_row,
                    target_mailbox,
                    "failed",
                    "append-failed",
                    target_binding=target_binding,
                )
                append_journal(account_dir, group_account, failed_row)
                journal_rows.append(failed_row)
                raise RuntimeError(f"append failed for {identity}: {response}")
            if target_provider == "gmail":
                fresh_occurrence = _gmail_confirmed_fresh_append_occurrence(
                    imap,
                    target_mailboxes,
                    manifest_row,
                    target_mailbox,
                    retry_pre_append_gmail_msgids or (),
                    expected_content_identities=expected_content_identities,
                )
                matched_num = (
                    fresh_occurrence["num"]
                    if fresh_occurrence is not None
                    else None
                )
                if fresh_occurrence is not None:
                    matched_mailbox = str(fresh_occurrence["mailbox"])
                    matched_gmail_msgid = str(
                        fresh_occurrence["gmail_msgid"]
                    )
                    matched_internaldate = str(
                        fresh_occurrence.get("internaldate") or ""
                    )
                    used_target_nums.setdefault(
                        _target_mailbox_lookup_key(matched_mailbox, "gmail"),
                        set(),
                    ).add(matched_num)
                    used_target_gmail_msgids.add(matched_gmail_msgid)
            else:
                matched_num = consume_target_match_num(
                    imap,
                    target_mailbox,
                    manifest_row,
                    used_target_nums,
                    create_if_missing=False,
                    expected_content_identities=expected_content_identities,
                    require_internaldate_match=True,
                )
            if matched_num is None:
                reject_unconfirmed_internaldate(
                    identity,
                    manifest_row,
                    target_mailbox,
                    expected_content_identities,
                    used_target_nums,
                    used_target_gmail_msgids,
                )
                raise RuntimeError(
                    f"appended target message not found for {identity} in {target_mailbox!r}"
                )
            if target_provider != "gmail":
                matched_mailbox = target_mailbox

        actual_target_internaldate = (
            matched_internaldate
            or target_message_internaldate(imap, matched_num)
        )
        expected_source_internaldate = _normalized_provider_internaldate(
            manifest_row.get("internaldate")
        )
        if not _legacy_internaldates_equal(
            actual_target_internaldate,
            expected_source_internaldate,
        ):
            raise RuntimeError(
                f"cannot confirm pending append recovery for {identity} in {target_mailbox!r}: "
                f"target INTERNALDATE {actual_target_internaldate or '<missing>'!r} does not "
                f"match source {expected_source_internaldate or '<missing>'!r}; no committed "
                "journal row was written"
            )

        subscribe_mailbox(imap, target_mailbox)
        labels_applied: List[str] = []
        if target_provider == "gmail":
            target_gmail_msgid = matched_gmail_msgid or _target_gmail_msgid(imap, matched_num)
            labels_applied = restore_gmail_labels(
                imap,
                matched_mailbox,
                manifest_row,
                target_num=matched_num,
                target_mailboxes=target_mailboxes,
                desired_target_mailbox=target_mailbox,
            )
            restore_gmail_starred_flag(
                imap,
                matched_mailbox,
                manifest_row,
                target_num=matched_num,
            )
            restore_imap_flags(
                imap,
                matched_mailbox,
                manifest_row,
                target_num=matched_num,
                target_provider=target_provider,
            )
        else:
            target_gmail_msgid = ""
            restore_imap_flags(
                imap,
                target_mailbox,
                manifest_row,
                target_num=matched_num,
                target_provider=target_provider,
            )
        committed_row = _journal_row(
            manifest_row,
            target_mailbox,
            "committed",
            "appended",
            target_binding=target_binding,
            target_gmail_msgid=target_gmail_msgid,
            labels_applied=labels_applied,
            actual_target_internaldate=actual_target_internaldate,
        )
        append_journal(account_dir, group_account, committed_row)
        journal_rows.append(committed_row)
        logging.info(
            "[provider-import] %s: resolved pending APPEND for %s in %s",
            group_account.source_email,
            identity,
            target_mailbox,
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
                target_gmail_msgid = journal_row.get("target_gmail_msgid")
                if is_valid_gmail_msgid(target_gmail_msgid):
                    gmail_journal_msgids[key] = target_gmail_msgid
        journaled.update(
            key
            for key, row in latest_journal_rows(
                journal_rows,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            ).items()
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
                target_mailbox = _resolved_target_mailbox_for_row(
                    row,
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
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


def provider_routing_plan_path(root: Path) -> Path:
    return root / ROUTING_PLAN_FILENAME


def _routing_source_discovery_snapshot(plan: RoutingPlan) -> Tuple[Tuple[Any, ...], ...]:
    return tuple(
        (
            entry.source.source_account,
            entry.source.name,
            entry.source.delimiter,
            tuple(entry.source.attributes),
        )
        for entry in plan.entries
    )


def _routing_plans_have_same_reviewed_mapping(
    left: RoutingPlan,
    right: RoutingPlan,
) -> bool:
    return bool(
        left.mapping_digest == right.mapping_digest
        and _routing_source_discovery_snapshot(left)
        == _routing_source_discovery_snapshot(right)
    )


def save_provider_routing_plan(root: Path, plan: RoutingPlan) -> Path:
    """Persist the exact reviewed plan once, without silently replacing it."""

    if not plan.ok:
        raise RuntimeError("refusing to persist an unresolved routing plan")
    _raise_if_provider_path_symlink(root, "routing plan root")
    ensure_private_dir(root)
    path = provider_routing_plan_path(root)
    if _atomic_json_create_once(path, plan.to_dict()):
        return path
    try:
        existing_payload = json.loads(_read_provider_private_file(path))
        existing = RoutingPlan.from_dict(existing_payload)
    except Exception as exc:
        raise RuntimeError(
            f"refusing to replace invalid existing routing plan {path}: {exc}"
        ) from exc
    if not existing.ok:
        raise RuntimeError(
            f"existing {ROUTING_PLAN_FILENAME} is unresolved; use a new export directory"
        )
    if not _routing_plans_have_same_reviewed_mapping(existing, plan):
        raise RuntimeError(
            f"refusing to replace existing {ROUTING_PLAN_FILENAME} with a different plan; "
            "use a new export directory after reviewing changed mapping or source discovery"
        )
    return path


def validate_provider_routing_plan(
    config: ProviderMigrationConfig,
    plan: RoutingPlan,
) -> None:
    routing = config.migration.routing
    if not routing.enabled:
        raise RuntimeError("a routing plan was supplied but migration.routing is disabled")
    if not plan.ok:
        details = list(plan.conflicts)
        details.extend(
            f"{entry.source.source_account}/{entry.source.name}: {issue}"
            for entry in plan.entries
            for issue in entry.ambiguities
        )
        raise RuntimeError("routing plan is unresolved: " + "; ".join(details))
    replay = resolve_routing_plan(
        routing,
        (entry.source for entry in plan.entries),
        plan.discovered_target_labels,
    )
    if replay.mapping_digest != plan.mapping_digest:
        raise RuntimeError(
            "persisted routing plan no longer matches migration.routing configuration; "
            "run preflight again and review the new mapping before importing"
        )
    if replay.to_dict() != plan.to_dict():
        raise RuntimeError(
            "persisted routing plan is not the canonical result for migration.routing and its "
            "recorded discovery; run preflight again and review the new plan"
        )


def load_provider_routing_plan(
    root: Path,
    config: ProviderMigrationConfig,
) -> RoutingPlan:
    _raise_if_provider_path_symlink(root, "routing plan root")
    path = provider_routing_plan_path(root)
    try:
        payload = json.loads(_read_provider_private_file(path))
    except Exception as exc:
        raise RuntimeError(
            f"routing-enabled migration requires a valid {ROUTING_PLAN_FILENAME}; "
            "rerun provider export or the end-to-end migrate mode with routing enabled: "
            f"{exc}"
        ) from exc
    try:
        plan = RoutingPlan.from_dict(payload)
    except Exception as exc:
        raise RuntimeError(f"invalid persisted routing plan {path}: {exc}") from exc
    validate_provider_routing_plan(config, plan)
    return plan


def _effective_provider_routing_plan(
    config: ProviderMigrationConfig,
    root: Path,
    supplied: Optional[RoutingPlan],
    *,
    persist: bool,
) -> Optional[RoutingPlan]:
    """Resolve the one immutable plan artifact used by an execution phase."""

    if not config.migration.routing.enabled:
        if supplied is not None:
            raise RuntimeError("routing plan supplied for a migration with routing disabled")
        return None

    if persist:
        if supplied is None:
            supplied = load_provider_routing_plan(root, config)
        else:
            validate_provider_routing_plan(config, supplied)
        save_provider_routing_plan(root, supplied)
        return load_provider_routing_plan(root, config)

    persisted = load_provider_routing_plan(root, config)
    if supplied is not None:
        validate_provider_routing_plan(config, supplied)
        if not _routing_plans_have_same_reviewed_mapping(supplied, persisted):
            raise RuntimeError(
                "supplied routing plan does not match the immutable plan persisted with this export"
            )
    return persisted


_ROUTING_GMAIL_PRIMARY_NAMES = {
    "all": "Archive",
    "inbox": "INBOX",
    "sent": "Sent",
    "drafts": "Drafts",
    "trash": "Trash",
    "spam": "Spam",
}
def _routing_plan_entries_for_account(
    plan: RoutingPlan,
    account: MigrationAccount,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    inbox_entry: Optional[Any] = None
    for entry in plan.entries:
        if entry.source.source_account.casefold() != account.source_email.casefold():
            continue
        if entry.source.name.upper() == "INBOX":
            if inbox_entry is not None:
                raise RuntimeError(f"routing plan has duplicate INBOX entries for {account.source_email}")
            inbox_entry = entry
            continue
        if entry.source.name in result:
            raise RuntimeError(
                f"routing plan has duplicate source folder {entry.source.name!r} for {account.source_email}"
            )
        result[entry.source.name] = entry
    if inbox_entry is not None:
        result["INBOX"] = inbox_entry
    return result


def _routing_entry_for_folder(entries: Dict[str, Any], folder: str) -> Optional[Any]:
    if folder.upper() == "INBOX":
        return entries.get("INBOX")
    return entries.get(folder)


def routed_manifest_rows(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    manifest_rows: List[Dict[str, Any]],
    plan: RoutingPlan,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Apply the frozen per-folder plan to staged message memberships.

    Returned rows are ephemeral copies.  Their original content bindings stay
    valid because routing is separately bound by ``routing_plan_sha256`` in the
    import journal and export state.
    """

    validate_provider_routing_plan(config, plan)
    entries = _routing_plan_entries_for_account(plan, account)
    if not entries:
        raise RuntimeError(
            f"routing plan contains no discovered source folders for {account.source_email}; "
            "rerun preflight/export with the complete account configuration"
        )
    routed: List[Dict[str, Any]] = []
    excluded_identities: List[str] = []
    for row in manifest_rows:
        identity = str(row.get("canonical_id") or "<missing>")
        raw_memberships = row.get("source_mailboxes")
        if not isinstance(raw_memberships, list) or not raw_memberships or any(
            not isinstance(value, str) or not value for value in raw_memberships
        ):
            raise RuntimeError(
                f"routing-enabled staged message {identity} lacks complete source_mailboxes metadata; "
                "rerun provider export with routing enabled"
            )
        membership_entries: List[Tuple[str, Any]] = []
        for folder in raw_memberships:
            entry = _routing_entry_for_folder(entries, folder)
            if entry is None:
                raise RuntimeError(
                    f"routing plan has no entry for staged source folder "
                    f"{account.source_email}/{folder}; rerun preflight/export to resolve discovery drift"
                )
            if entry.ambiguous:
                raise RuntimeError(
                    f"routing plan entry {account.source_email}/{folder} is ambiguous: "
                    + "; ".join(entry.ambiguities)
                )
            membership_entries.append((folder, entry))

        custom_labels: set[str] = set()
        system_destinations: set[str] = set()
        mailbox_destinations: set[str] = set()
        included_folders: List[str] = []
        excluded_folders: List[str] = []
        shared_destinations: set[str] = set()
        for folder, entry in membership_entries:
            if entry.excluded:
                excluded_folders.append(folder)
                continue
            included_folders.append(folder)
            for destination in entry.destinations:
                if destination.status in {"conflict", "missing_system"}:
                    raise RuntimeError(
                        f"routing destination for {account.source_email}/{folder} is unresolved: "
                        f"{destination.name!r} ({destination.status})"
                    )
                if destination.merged:
                    shared_destinations.add(destination.name)
                if destination.kind == CUSTOM_LABEL:
                    custom_labels.add(destination.name)
                elif destination.kind == GMAIL_SYSTEM:
                    system_destinations.add(destination.name)
                elif destination.kind == GENERIC_MAILBOX:
                    mailbox_destinations.add(destination.name)
                else:
                    raise RuntimeError(
                        f"unsupported routing destination type {destination.kind!r} for {identity}"
                    )

        if not custom_labels and not system_destinations and not mailbox_destinations:
            excluded_identities.append(identity)
            continue

        updated = dict(row)
        updated.pop(_ROUTING_EXACT_TARGET_MAILBOX_FIELD, None)
        updated["routing_active"] = True
        updated["routing_plan_sha256"] = plan.mapping_digest
        updated["routing_source_folders"] = sorted(
            set(included_folders),
            key=lambda value: (value.casefold(), value),
        )
        updated["routing_excluded_source_folders"] = sorted(
            set(excluded_folders),
            key=lambda value: (value.casefold(), value),
        )
        updated["routing_shared_destinations"] = sorted(
            shared_destinations,
            key=lambda value: (value.casefold(), value),
        )

        if config.target.provider == "gmail":
            if mailbox_destinations:
                raise RuntimeError("Gmail routing cannot use generic mailbox destinations")
            if "drafts" in system_destinations and (
                custom_labels or system_destinations - {"all", "drafts"}
            ):
                incompatible = sorted(
                    custom_labels,
                    key=lambda value: (value.casefold(), value),
                )
                incompatible.extend(
                    sorted(system_destinations - {"all", "drafts"})
                )
                raise RuntimeError(
                    f"staged message {identity} resolves to Gmail Drafts plus incompatible "
                    "label/location(s): "
                    + ", ".join(incompatible)
                )
            incompatible_roles = gmail_incompatible_system_roles(system_destinations)
            if incompatible_roles:
                raise RuntimeError(
                    f"staged message {identity} resolves to incompatible Gmail system locations: "
                    + ", ".join(incompatible_roles)
                )
            exclusive = system_destinations & GMAIL_EXCLUSIVE_PRIMARY_ROLES
            primary_role = next(iter(exclusive), "")
            if not primary_role:
                primary_role = "inbox" if "inbox" in system_destinations else "all"
            updated["primary_mailbox"] = _ROUTING_GMAIL_PRIMARY_NAMES[primary_role]
            updated["routing_target_labels"] = sorted(
                custom_labels,
                key=lambda value: (value.casefold(), value),
            )
            updated["routing_system_destinations"] = sorted(system_destinations)
        else:
            if custom_labels or system_destinations or len(mailbox_destinations) != 1:
                raise RuntimeError(
                    f"non-Gmail staged message {identity} must resolve to exactly one mailbox"
                )
            exact_target_mailbox = next(iter(mailbox_destinations))
            updated["primary_mailbox"] = exact_target_mailbox
            updated[_ROUTING_EXACT_TARGET_MAILBOX_FIELD] = exact_target_mailbox
            updated["routing_target_labels"] = []
            updated["routing_system_destinations"] = []
        routed.append(updated)
    return routed, excluded_identities


def routing_journal_membership_complete(
    journal_row: Dict[str, Any],
    manifest_row: Dict[str, Any],
) -> bool:
    if not manifest_row.get("routing_active"):
        return True
    required_labels = sorted(
        {str(value) for value in (manifest_row.get("routing_target_labels") or []) if str(value)},
        key=lambda value: (value.casefold(), value),
    )
    required_systems = sorted(
        {str(value) for value in (manifest_row.get("routing_system_destinations") or []) if str(value)}
    )
    return bool(
        journal_row.get("routing_plan_sha256") == manifest_row.get("routing_plan_sha256")
        and journal_row.get("required_gmail_labels") == required_labels
        and journal_row.get("required_gmail_system_destinations") == required_systems
        and journal_row.get("label_membership_verified") is True
    )


def routing_committed_journal_issues(
    journal_rows: List[Dict[str, Any]],
    manifest_rows: List[Dict[str, Any]],
    *,
    target_provider: str,
    target_mailboxes: Optional[List[MailboxInfo]] = None,
) -> List[str]:
    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    issues: List[str] = []
    for (identity, target_mailbox), journal_row in latest_committed_journal_rows(
        journal_rows,
        target_provider=target_provider,
        target_mailboxes=target_mailboxes,
    ).items():
        manifest_row = manifest_by_id.get(identity)
        if manifest_row is None or not manifest_row.get("routing_active"):
            continue
        if not routing_journal_membership_complete(journal_row, manifest_row):
            issues.append(
                f"journal route membership is not verified for {identity} in "
                f"{target_mailbox or '<missing>'} under routing plan "
                f"{manifest_row.get('routing_plan_sha256') or '<missing>'}"
            )
    return issues


def provider_import_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
    routing_plan: Optional[RoutingPlan] = None,
) -> None:
    with _provider_import_lock(
        config,
        account,
        in_root,
        stop_event=stop_event,
    ):
        _provider_import_account_unlocked(
            config,
            account,
            in_root,
            stop_event=stop_event,
            limiter=limiter,
            routing_plan=routing_plan,
        )


def _provider_import_account_unlocked(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
    routing_plan: Optional[RoutingPlan] = None,
) -> None:
    _raise_if_provider_path_symlink(in_root, "import root")
    routing_plan = _effective_provider_routing_plan(
        config,
        in_root,
        routing_plan,
        persist=False,
    )
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
        routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
        routing_enabled=config.migration.routing.enabled,
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
    if routing_plan is not None:
        manifest_rows, excluded_identities = routed_manifest_rows(
            config,
            account,
            manifest_rows,
            routing_plan,
        )
        if excluded_identities:
            logging.info(
                "[provider-import] %s: excluding %d staged message(s) whose source memberships are all excluded",
                account.source_email,
                len(excluded_identities),
            )
    if config.target.provider == "gmail":
        draft_issues = gmail_draft_combination_issues(manifest_rows)
        if draft_issues:
            raise RuntimeError("invalid Gmail Drafts routing/labels: " + "; ".join(draft_issues))
    # Gmail tail repair is initially read-only.  Many-to-one allocation and,
    # when present, live pending-APPEND evidence must be proven from the
    # original bytes before an incomplete crash tail may be removed.
    defer_gmail_journal_tail_repair = config.target.provider == "gmail"
    journal_rows = load_import_journal(
        account_dir,
        account,
        repair_trailing=not defer_gmail_journal_tail_repair,
        defer_trailing_repair=defer_gmail_journal_tail_repair,
    )
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
    journal_content_issues.extend(
        pending_journal_manifest_content_issues(
            journal_rows,
            manifest_rows,
            target_provider=config.target.provider,
        )
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
    merge_group_expected_content_identities_by_id: Dict[
        str, set[Tuple[int, str]]
    ] = {}
    if provider_account_merge_enabled(config):
        def prepare_merge_group(
            current_journal_rows: List[Dict[str, Any]],
            *,
            repair_trailing_journal: bool,
            defer_trailing_journal_repair: bool,
        ) -> Tuple[
            List[
                Tuple[
                    MigrationAccount,
                    Path,
                    List[Dict[str, Any]],
                    List[Dict[str, Any]],
                ]
            ],
            Dict[str, set[Tuple[int, str]]],
        ]:
            stages = validated_merge_group_stages(
                config,
                in_root,
                account,
                manifest_rows,
                current_journal_rows,
                repair_trailing_journal=repair_trailing_journal,
                defer_trailing_journal_repair=defer_trailing_journal_repair,
                routing_plan_sha256=(
                    routing_plan.mapping_digest if routing_plan is not None else None
                ),
                routing_plan=routing_plan,
            )
            require_merge_group_unique_manifest_identities(stages)
            content_identities_by_id = {
                **merge_group_payload_content_identities(stages),
                **expected_content_identities_by_id,
            }
            if routing_plan is not None:
                stages = [
                    (
                        group_account,
                        group_dir,
                        routed_manifest_rows(
                            config,
                            group_account,
                            group_rows,
                            routing_plan,
                        )[0],
                        group_journal,
                    )
                    for group_account, group_dir, group_rows, group_journal in stages
                ]
            if config.target.provider == "gmail":
                merge_draft_issues = [
                    f"{group_account.source_email}: {issue}"
                    for group_account, _group_dir, group_rows, _group_journal in stages
                    for issue in gmail_draft_combination_issues(group_rows)
                ]
                if merge_draft_issues:
                    raise RuntimeError(
                        "invalid Gmail Drafts routing/labels in merge group: "
                        + "; ".join(merge_draft_issues)
                    )
            if config.target.provider == "gmail":
                allocation_classes = (
                    require_merge_group_gmail_destination_allocations_compatible(
                        stages,
                        expected_content_identities_by_id=content_identities_by_id,
                        stop_event=stop_event,
                    )
                )
                allocation_by_source_identity: Dict[
                    Tuple[str, str], Dict[str, Any]
                ] = {}
                for class_index, allocation_class in enumerate(allocation_classes):
                    for (
                        source_email,
                        identity,
                    ), slot_index in allocation_class["allocations"].items():
                        slot_profile = allocation_class["slot_profiles"][slot_index]
                        allocation_by_source_identity[
                            (source_email.casefold(), identity)
                        ] = {
                            "class": class_index,
                            "slot": slot_index,
                            "systems": list(slot_profile["systems"]),
                            "custom_labels": list(slot_profile["custom_labels"]),
                            "target_gmail_msgids": list(
                                slot_profile["target_gmail_msgids"]
                            ),
                        }

                def apply_allocation_metadata(
                    source_email: str,
                    rows: List[Dict[str, Any]],
                ) -> List[Dict[str, Any]]:
                    annotated: List[Dict[str, Any]] = []
                    for row in rows:
                        identity = str(row.get("canonical_id") or "")
                        allocation = allocation_by_source_identity.get(
                            (source_email.casefold(), identity)
                        )
                        if allocation is None:
                            annotated.append(row)
                            continue
                        updated = dict(row)
                        updated["_gmail_duplicate_allocation"] = dict(allocation)
                        annotated.append(updated)
                    return annotated

                stages = [
                    (
                        group_account,
                        group_dir,
                        apply_allocation_metadata(
                            group_account.source_email,
                            group_rows,
                        ),
                        group_journal,
                    )
                    for group_account, group_dir, group_rows, group_journal in stages
                ]
                current_rows = apply_allocation_metadata(
                    account.source_email,
                    manifest_rows,
                )
                for original, annotated in zip(manifest_rows, current_rows):
                    allocation = annotated.get("_gmail_duplicate_allocation")
                    if allocation is not None:
                        original["_gmail_duplicate_allocation"] = allocation
            return stages, content_identities_by_id

        (
            merge_group_stages,
            merge_group_expected_content_identities_by_id,
        ) = prepare_merge_group(
            journal_rows,
            repair_trailing_journal=not defer_gmail_journal_tail_repair,
            defer_trailing_journal_repair=defer_gmail_journal_tail_repair,
        )

    deferred_gmail_pending_tail_repair = False
    if defer_gmail_journal_tail_repair:
        offline_recovery_stages = merge_group_stages or [
            (account, account_dir, manifest_rows, journal_rows)
        ]
        offline_has_unresolved_pending = any(
            status_row.get("status") == "pending"
            for (
                _stage_account,
                _stage_dir,
                _stage_rows,
                stage_journal,
            ) in offline_recovery_stages
            for status_row in latest_journal_rows(
                stage_journal,
                target_provider="gmail",
            ).values()
        )
        if offline_has_unresolved_pending:
            # Keep every current/peer journal byte untouched until the target
            # has supplied one global, read-only pending-APPEND proof.
            deferred_gmail_pending_tail_repair = True
        else:
            # The immutable many-to-one allocation gate (when applicable) has
            # passed and there is no unresolved pending recovery to protect.
            journal_rows = load_import_journal(
                account_dir,
                account,
                repair_trailing=True,
            )
            if merge_group_stages is not None:
                (
                    merge_group_stages,
                    merge_group_expected_content_identities_by_id,
                ) = prepare_merge_group(
                    journal_rows,
                    repair_trailing_journal=True,
                    defer_trailing_journal_repair=False,
                )

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
        if config.target.provider == "gmail":
            target_issues = gmail_target_readiness_issues(
                capabilities,
                target_mailboxes,
            )
            target_issues.extend(
                gmail_all_mail_select_issues(
                    imap,
                    target_mailboxes,
                    role="target",
                )
            )
            target_issues.extend(
                gmail_target_decommission_issues(config.target, account)
            )
            if target_issues:
                raise RuntimeError(
                    "Gmail target is not import-ready: "
                    + "; ".join(target_issues)
                )
        recovery_stages = merge_group_stages or [
            (account, account_dir, manifest_rows, journal_rows)
        ]
        target_mailbox_by_identity = require_recovery_stages_live_integrity(
            recovery_stages,
            target_mailboxes,
            target_provider=config.target.provider,
        )
        recovery_expected_content_identities_by_id = expected_content_identities_by_id
        recovery_capacity_classes: List[Dict[str, Any]] = []
        has_unresolved_pending = any(
            status_row.get("status") == "pending"
            for _stage_account, _stage_dir, _stage_rows, stage_journal in recovery_stages
            for status_row in latest_journal_rows(
                stage_journal,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            ).values()
        )
        if merge_group_stages is not None:
            recovery_expected_content_identities_by_id = (
                merge_group_expected_content_identities_by_id
            )
        if merge_group_stages is not None or has_unresolved_pending:
            # This gate is manifest/journal-only and must precede Gmail journal
            # repair or any target mutation.  In particular, an unresolved
            # pending row without a confirmable date leaves every journal byte
            # untouched.
            recovery_capacity_classes = require_merge_group_pending_internaldates_compatible(
                target_mailboxes,
                recovery_stages,
                target_provider=config.target.provider,
                expected_content_identities_by_id=recovery_expected_content_identities_by_id,
            )

        def reject_unconfirmed_append_internaldate(
            identity: str,
            row: Dict[str, Any],
            target_mailbox: str,
            expected_content_identities: Optional[Iterable[Tuple[int, str]]],
            *,
            recovery: bool,
        ) -> None:
            search_mailboxes = [target_mailbox]
            if config.target.provider == "gmail":
                search_mailboxes = gmail_expected_target_mailboxes_for_row(
                    row,
                    target_mailbox,
                    target_mailboxes,
                )
            observations: List[Tuple[str, str]] = []
            for search_mailbox in search_mailboxes:
                for target_num in target_matching_message_nums(
                    imap,
                    search_mailbox,
                    row,
                    create_if_missing=False,
                    expected_content_identities=expected_content_identities,
                ):
                    observations.append(
                        (
                            search_mailbox,
                            target_message_internaldate(imap, target_num),
                        )
                    )
            if not observations:
                return
            expected_internaldate = _normalized_provider_internaldate(
                row.get("internaldate")
            )
            if any(
                _legacy_internaldates_equal(
                    actual_internaldate,
                    expected_internaldate,
                )
                for _mailbox, actual_internaldate in observations
            ):
                return
            observed = ", ".join(
                sorted(
                    {
                        f"{mailbox}: {actual_internaldate or '<missing>'}"
                        for mailbox, actual_internaldate in observations
                    }
                )
            )
            phase = "pending append recovery" if recovery else "fresh append"
            raise RuntimeError(
                f"cannot confirm {phase} for {identity} in {target_mailbox!r}: "
                f"byte-identical target content has INTERNALDATE {observed}; expected "
                f"{expected_internaldate or '<missing>'}; no committed journal row was written"
            )

        if merge_group_stages is None:
            require_one_to_one_committed_target_evidence(
                imap,
                target_mailboxes,
                manifest_rows,
                journal_rows,
                target_mailbox_by_identity,
                target_provider=config.target.provider,
                target_mode=config.migration.target_mode,
                expected_content_identities_by_id=expected_content_identities_by_id,
            )

        # One read-only gate precedes Gmail journal-ID repair, pending recovery,
        # and every other target/journal mutation.  It validates committed
        # physical allocation, matching-aware pending capacity, and empty-mode
        # contents against the original journal snapshot.
        if merge_group_stages is not None:
            require_merge_group_journals_remote_complete(
                imap,
                target_mailboxes,
                merge_group_stages,
                target_provider=config.target.provider,
                expected_content_identities_by_id=recovery_expected_content_identities_by_id,
                allow_unresolved_pending=True,
            )
        if has_unresolved_pending:
            require_merge_group_pending_target_capacity_compatible(
                imap,
                target_mailboxes,
                recovery_capacity_classes,
                target_provider=config.target.provider,
            )
        if config.migration.target_mode == "empty":
            preflight_rows = manifest_rows
            preflight_journaled = set(
                latest_committed_journal_rows(
                    journal_rows,
                    target_provider=config.target.provider,
                    target_mailboxes=target_mailboxes,
                )
            )
            preflight_journaled.update(
                key
                for key, status_row in latest_journal_rows(
                    journal_rows,
                    target_provider=config.target.provider,
                    target_mailboxes=target_mailboxes,
                ).items()
                if status_row.get("status") == "pending"
            )
            preflight_gmail_msgids = {
                key: committed_row["target_gmail_msgid"]
                for key, committed_row in latest_committed_journal_rows(
                    journal_rows,
                    target_provider=config.target.provider,
                    target_mailboxes=target_mailboxes,
                ).items()
                if config.target.provider == "gmail"
                and is_valid_gmail_msgid(
                    committed_row.get("target_gmail_msgid")
                )
            }
            (
                preflight_rows,
                preflight_journaled,
                preflight_gmail_msgids,
            ) = merge_group_empty_target_context(
                config,
                target_mailboxes,
                recovery_stages,
            )
            enforce_empty_target(
                imap,
                target_mailboxes,
                preflight_rows,
                preflight_journaled,
                target_provider=config.target.provider,
                gmail_journal_msgids=preflight_gmail_msgids,
                expected_content_identities_by_id=recovery_expected_content_identities_by_id,
            )

        if config.target.provider == "gmail":
            require_pending_gmail_append_evidence_safe(
                imap,
                target_mailboxes,
                recovery_stages,
                expected_content_identities_by_id=(
                    recovery_expected_content_identities_by_id
                ),
                stop_event=stop_event,
            )
            if deferred_gmail_pending_tail_repair:
                # The live, global pending proof above is the first operation
                # allowed to precede crash-tail repair.  Re-read every stage
                # without mutation to catch replacement/racing journal state,
                # then repair all current/peer tails and rebuild the stages from
                # their authoritative files before recovery can write.
                complete_journal_by_stage: Dict[
                    Tuple[str, Path], List[Dict[str, Any]]
                ] = {}
                for (
                    stage_account,
                    stage_dir,
                    _stage_rows,
                    stage_journal,
                ) in recovery_stages:
                    stage_key = (stage_account.source_email.casefold(), stage_dir)
                    observed_journal = load_import_journal(
                        stage_dir,
                        stage_account,
                        defer_trailing_repair=True,
                    )
                    if observed_journal != stage_journal:
                        raise ProviderImportIntegrityGateError(
                            "import journal changed while pending Gmail APPEND "
                            f"evidence was being verified: {stage_account.source_email}"
                        )
                    complete_journal_by_stage[stage_key] = stage_journal

                repaired_journal_by_stage: Dict[
                    Tuple[str, Path], List[Dict[str, Any]]
                ] = {}
                for (
                    stage_account,
                    stage_dir,
                    _stage_rows,
                    _stage_journal,
                ) in recovery_stages:
                    stage_key = (stage_account.source_email.casefold(), stage_dir)
                    repaired_stage_journal = load_import_journal(
                        stage_dir,
                        stage_account,
                        repair_trailing=True,
                    )
                    if (
                        repaired_stage_journal
                        != complete_journal_by_stage[stage_key]
                    ):
                        raise ProviderImportIntegrityGateError(
                            "import journal changed during deferred Gmail "
                            f"crash-tail repair: {stage_account.source_email}"
                        )
                    repaired_journal_by_stage[stage_key] = repaired_stage_journal

                current_stage_key = (account.source_email.casefold(), account_dir)
                journal_rows = repaired_journal_by_stage[current_stage_key]
                require_valid_import_journal(journal_rows, account)
                repaired_target_issues = journal_target_endpoint_issues(
                    journal_rows,
                    config=config,
                    account=account,
                )
                if repaired_target_issues:
                    raise ProviderImportIntegrityGateError(
                        "invalid import journal: "
                        + "; ".join(repaired_target_issues)
                    )
                repaired_content_issues = committed_journal_manifest_content_issues(
                    journal_rows,
                    manifest_rows,
                    target_provider="gmail",
                    target_mailboxes=target_mailboxes,
                )
                repaired_content_issues.extend(
                    pending_journal_manifest_content_issues(
                        journal_rows,
                        manifest_rows,
                        target_provider="gmail",
                        target_mailboxes=target_mailboxes,
                    )
                )
                repaired_content_issues.extend(
                    invalid_journal_target_gmail_msgid_issues(
                        journal_rows,
                        manifest_ids=manifest_ids,
                    )
                )
                repaired_content_issues.extend(
                    duplicate_journal_target_gmail_msgid_issues(
                        journal_rows,
                        manifest_ids=manifest_ids,
                        target_mailboxes=target_mailboxes,
                    )
                )
                if repaired_content_issues:
                    raise ProviderImportIntegrityGateError(
                        "invalid import journal: "
                        + "; ".join(repaired_content_issues)
                    )

                if merge_group_stages is not None:
                    (
                        merge_group_stages,
                        merge_group_expected_content_identities_by_id,
                    ) = prepare_merge_group(
                        journal_rows,
                        repair_trailing_journal=False,
                        defer_trailing_journal_repair=False,
                    )
                    recovery_stages = merge_group_stages
                    recovery_expected_content_identities_by_id = (
                        merge_group_expected_content_identities_by_id
                    )
                else:
                    recovery_stages = [
                        (account, account_dir, manifest_rows, journal_rows)
                    ]
                    recovery_expected_content_identities_by_id = (
                        expected_content_identities_by_id
                    )

                target_mailbox_by_identity = require_recovery_stages_live_integrity(
                    recovery_stages,
                    target_mailboxes,
                    target_provider="gmail",
                )
                has_unresolved_pending = any(
                    status_row.get("status") == "pending"
                    for (
                        _stage_account,
                        _stage_dir,
                        _stage_rows,
                        stage_journal,
                    ) in recovery_stages
                    for status_row in latest_journal_rows(
                        stage_journal,
                        target_provider="gmail",
                        target_mailboxes=target_mailboxes,
                    ).values()
                )
                recovery_capacity_classes = (
                    require_merge_group_pending_internaldates_compatible(
                        target_mailboxes,
                        recovery_stages,
                        target_provider="gmail",
                        expected_content_identities_by_id=(
                            recovery_expected_content_identities_by_id
                        ),
                    )
                )
                if merge_group_stages is None:
                    require_one_to_one_committed_target_evidence(
                        imap,
                        target_mailboxes,
                        manifest_rows,
                        journal_rows,
                        target_mailbox_by_identity,
                        target_provider="gmail",
                        target_mode=config.migration.target_mode,
                        expected_content_identities_by_id=(
                            expected_content_identities_by_id
                        ),
                    )
                else:
                    require_merge_group_journals_remote_complete(
                        imap,
                        target_mailboxes,
                        recovery_stages,
                        target_provider="gmail",
                        expected_content_identities_by_id=(
                            recovery_expected_content_identities_by_id
                        ),
                        allow_unresolved_pending=True,
                    )
                if has_unresolved_pending:
                    require_merge_group_pending_target_capacity_compatible(
                        imap,
                        target_mailboxes,
                        recovery_capacity_classes,
                        target_provider="gmail",
                    )
                require_pending_gmail_append_evidence_safe(
                    imap,
                    target_mailboxes,
                    recovery_stages,
                    expected_content_identities_by_id=(
                        recovery_expected_content_identities_by_id
                    ),
                    stop_event=stop_event,
                )
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
                raise ProviderImportIntegrityGateError(
                    "invalid import journal: " + "; ".join(repaired_journal_issues)
                )
        if has_unresolved_pending:
            # A Gmail journal repair may have returned a new list.  Keep the
            # current stage pointed at the authoritative in-memory rows before
            # batch recovery appends resolutions to it.
            recovery_stages = [
                (
                    group_account,
                    group_dir,
                    group_rows,
                    journal_rows
                    if group_account.source_email == account.source_email
                    else group_journal,
                )
                for group_account, group_dir, group_rows, group_journal in recovery_stages
            ]
            recover_merge_group_pending_appends(
                config,
                imap,
                target_mailboxes,
                recovery_stages,
                expected_content_identities_by_id=recovery_expected_content_identities_by_id,
                limiter=limiter,
                stop_event=stop_event,
                allow_unmatched_committed=(
                    merge_group_stages is None
                    and config.target.provider != "gmail"
                    and config.migration.target_mode == "merge"
                ),
            )
        latest_status_rows = latest_journal_rows(
            journal_rows,
            target_provider=config.target.provider,
            target_mailboxes=target_mailboxes,
        )
        pending_rows = {
            key: row
            for key, row in latest_status_rows.items()
            if row.get("status") == "pending"
        }
        pending = set(pending_rows)
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
                recovery_stages,
                target_provider=config.target.provider,
                expected_content_identities_by_id=recovery_expected_content_identities_by_id,
            )
        ordered_manifest_rows = sorted(
            manifest_rows,
            key=lambda item: str(item.get("canonical_id", "")),
        )
        ordinary_specs: Dict[str, Dict[str, Any]] = {}
        priority_committed_identities: set[str] = set()
        must_exist_committed_identities: set[str] = set()
        ordinary_target_mailbox_by_identity: Dict[str, str] = {}
        for row in ordered_manifest_rows:
            identity = str(row.get("canonical_id") or "")
            target_mailbox = target_mailbox_by_identity.get(identity)
            if not target_mailbox:
                target_mailbox = _resolved_target_mailbox_for_row(
                    row,
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
            ordinary_target_mailbox_by_identity[identity] = target_mailbox
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            expected_content_identities = expected_content_identities_by_id.get(identity)
            if key in committed:
                previous_commit = latest_committed.get(key, {})
                legacy_existing_without_date_evidence = (
                    previous_commit.get("action") == "existing"
                    and _existing_content_reuse_target_internaldate(
                        row,
                        previous_commit,
                    )
                    is None
                )
                ordinary_specs[identity] = {
                    "manifest_row": row,
                    "match_row": _committed_target_match_row(row, previous_commit),
                    "target_mailbox": target_mailbox,
                    "target_gmail_msgid": str(previous_commit.get("target_gmail_msgid") or ""),
                    "expected_content_identities": expected_content_identities,
                    # A legacy `existing` commit may predate target-date
                    # provenance.  Match it by content once so the branch below
                    # can record the observed target date.  Every other commit
                    # reserves its effective journal date exactly.
                    "require_internaldate_match": not legacy_existing_without_date_evidence,
                }
                priority_committed_identities.add(identity)
                if config.migration.target_mode == "empty":
                    must_exist_committed_identities.add(identity)
            elif (
                config.migration.target_mode == "merge"
                or provider_account_merge_enabled(config)
                or key in pending
            ):
                pending_journal_row = pending_rows.get(key)
                raw_pre_append_gmail_msgids = (
                    pending_journal_row.get("pre_append_gmail_msgids")
                    if pending_journal_row is not None
                    else None
                )
                pre_append_gmail_msgids = (
                    list(raw_pre_append_gmail_msgids)
                    if isinstance(raw_pre_append_gmail_msgids, list)
                    else None
                )
                ordinary_specs[identity] = {
                    "manifest_row": row,
                    "match_row": row,
                    "target_mailbox": target_mailbox,
                    "target_gmail_msgid": "",
                    "expected_content_identities": expected_content_identities,
                    "require_internaldate_match": key in pending,
                    "pre_append_gmail_msgids": pre_append_gmail_msgids,
                    "require_unique_fresh_append": (
                        key in pending and pre_append_gmail_msgids is not None
                    ),
                }
        ordinary_assignments = _target_row_assignments(
            imap,
            target_mailboxes,
            ordinary_specs,
            target_provider=config.target.provider,
            required_row_keys=priority_committed_identities,
        )
        for identity in sorted(must_exist_committed_identities):
            if identity in ordinary_assignments:
                continue
            target_mailbox = ordinary_target_mailbox_by_identity[identity]
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            journal_target_gmail_msgid = str(
                latest_committed.get(key, {}).get("target_gmail_msgid") or ""
            )
            if config.target.provider == "gmail" and journal_target_gmail_msgid:
                raise ProviderImportIntegrityGateError(
                    f"journal says {identity} is committed to Gmail target message "
                    f"{journal_target_gmail_msgid} in {target_mailbox!r}, but that exact "
                    "target message was not found"
                )
            raise ProviderImportIntegrityGateError(
                f"journal says {identity} is committed to {target_mailbox!r}, "
                "but the target message was not found"
            )
        for occurrence in ordinary_assignments.values():
            used_target_nums.setdefault(
                _target_mailbox_lookup_key(
                    occurrence["mailbox"],
                    "gmail" if config.target.provider == "gmail" else config.target.provider,
                ),
                set(),
            ).add(occurrence["num"])
            if occurrence["gmail_msgid"]:
                used_target_gmail_msgids.add(occurrence["gmail_msgid"])

        for row in ordered_manifest_rows:
            _raise_if_stopped(stop_event, f"provider import {account.target_email}")
            identity = str(row.get("canonical_id") or "")
            target_mailbox = ordinary_target_mailbox_by_identity[identity]
            key = journal_target_key(
                identity,
                target_mailbox,
                target_provider=config.target.provider,
                target_mailboxes=target_mailboxes,
            )
            data = payloads_by_identity[identity]
            expected_content_identities = expected_content_identities_by_id.get(identity)
            if key in committed:
                previous_commit = latest_committed.get(key, {})
                journal_target_gmail_msgid = str(previous_commit.get("target_gmail_msgid") or "")
                committed_occurrence = ordinary_assignments.get(identity)
                committed_mailbox = (
                    committed_occurrence["mailbox"]
                    if committed_occurrence is not None
                    else target_mailbox
                )
                committed_num = (
                    committed_occurrence["num"]
                    if committed_occurrence is not None
                    else None
                )
                if committed_num is None and config.target.provider == "gmail" and journal_target_gmail_msgid:
                    raise ProviderImportIntegrityGateError(
                        f"journal says {identity} is committed to Gmail target message {journal_target_gmail_msgid} "
                        f"in {target_mailbox!r}, but that exact target message was not found"
                    )
                if committed_num is None and config.migration.target_mode == "empty":
                    raise ProviderImportIntegrityGateError(
                        f"journal says {identity} is committed to {target_mailbox!r}, "
                        "but the target message was not found"
                    )
                if committed_num is not None:
                    actual_target_internaldate = str(
                        committed_occurrence.get("internaldate") or ""
                    )
                    expected_source_internaldate = _normalized_provider_internaldate(
                        row.get("internaldate")
                    )
                    if (
                        expected_source_internaldate
                        and not _legacy_internaldates_equal(
                            actual_target_internaldate,
                            expected_source_internaldate,
                        )
                    ):
                        journal_target_internaldate = (
                            _existing_content_reuse_target_internaldate(
                                row,
                                previous_commit,
                            )
                        )
                        if journal_target_internaldate:
                            if not _legacy_internaldates_equal(
                                actual_target_internaldate,
                                journal_target_internaldate,
                            ):
                                raise RuntimeError(
                                    f"journal says {identity} reused an existing target message "
                                    f"with INTERNALDATE {journal_target_internaldate!r}, but the "
                                    f"current target has {actual_target_internaldate!r}"
                                )
                        elif previous_commit.get("action") == "existing":
                            upgraded_commit = _journal_row(
                                row,
                                target_mailbox,
                                "committed",
                                "existing",
                                target_binding=target_binding,
                                target_gmail_msgid=journal_target_gmail_msgid,
                                actual_target_internaldate=actual_target_internaldate,
                            )
                            append_journal(account_dir, account, upgraded_commit)
                            journal_rows.append(upgraded_commit)
                            latest_committed[key] = upgraded_commit
                            previous_commit = upgraded_commit
                        else:
                            raise RuntimeError(
                                f"journal says {identity} is committed to {target_mailbox!r}, "
                                f"but target INTERNALDATE {actual_target_internaldate!r} does not "
                                f"match source {expected_source_internaldate!r} and the commit is "
                                "not an explicitly journaled existing-content reuse"
                            )
                    subscribe_mailbox(imap, target_mailbox)
                    labels_applied: List[str] = []
                    if config.target.provider == "gmail":
                        labels_applied = restore_gmail_labels(
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
                    if row.get("routing_active") and (
                        labels_applied
                        or not routing_journal_membership_complete(previous_commit, row)
                    ):
                        reconciled_row = _journal_row(
                            row,
                            target_mailbox,
                            "committed",
                            "labels-reconciled" if labels_applied else "route-verified",
                            target_binding=target_binding,
                            target_gmail_msgid=journal_target_gmail_msgid,
                            labels_applied=labels_applied,
                            internaldate_evidence_from=previous_commit,
                        )
                        append_journal(account_dir, account, reconciled_row)
                        latest_committed[key] = reconciled_row
                    continue
            matched_num = None
            matched_mailbox = target_mailbox
            matched_gmail_msgid = ""
            recovering_pending_append = key in pending
            if config.migration.target_mode == "merge" or provider_account_merge_enabled(config) or key in pending:
                matched_occurrence = ordinary_assignments.get(identity)
                if matched_occurrence is not None:
                    matched_mailbox = matched_occurrence["mailbox"]
                    matched_num = matched_occurrence["num"]
                    matched_gmail_msgid = matched_occurrence["gmail_msgid"]
            if matched_num is not None:
                actual_target_internaldate = str(
                    matched_occurrence.get("internaldate") or ""
                )
                subscribe_mailbox(imap, target_mailbox)
                labels_applied = []
                if config.target.provider == "gmail":
                    target_gmail_msgid = matched_gmail_msgid or _target_gmail_msgid(imap, matched_num)
                    labels_applied = restore_gmail_labels(
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
                        "appended" if recovering_pending_append else "existing",
                        target_binding=target_binding,
                        target_gmail_msgid=target_gmail_msgid,
                        labels_applied=labels_applied,
                        actual_target_internaldate=actual_target_internaldate,
                    ),
                )
                committed.add(key)
                continue
            if recovering_pending_append:
                reject_unconfirmed_append_internaldate(
                    identity,
                    row,
                    target_mailbox,
                    expected_content_identities,
                    recovery=True,
                )
            ensure_mailbox(imap, target_mailbox)
            pre_append_gmail_msgids: Optional[List[str]] = None
            if config.target.provider == "gmail":
                pre_append_gmail_msgids = _gmail_pre_append_message_ids(
                    imap,
                    target_mailboxes,
                    row,
                    target_mailbox,
                    expected_content_identities=expected_content_identities,
                )
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
                _journal_row(
                    row,
                    target_mailbox,
                    "pending",
                    "append-started",
                    target_binding=target_binding,
                    pre_append_gmail_msgids=pre_append_gmail_msgids,
                ),
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
            appended_occurrence: Optional[Dict[str, Any]] = None
            if config.target.provider == "gmail":
                appended_occurrence = _gmail_confirmed_fresh_append_occurrence(
                    imap,
                    target_mailboxes,
                    row,
                    target_mailbox,
                    pre_append_gmail_msgids or (),
                    expected_content_identities=expected_content_identities,
                )
                appended_num = (
                    appended_occurrence["num"]
                    if appended_occurrence is not None
                    else None
                )
            else:
                appended_num = consume_target_match_num(
                    imap,
                    target_mailbox,
                    row,
                    used_target_nums,
                    create_if_missing=False,
                    expected_content_identities=expected_content_identities,
                    require_internaldate_match=True,
                )
            if appended_num is None:
                reject_unconfirmed_append_internaldate(
                    identity,
                    row,
                    target_mailbox,
                    expected_content_identities,
                    recovery=False,
                )
                raise RuntimeError(f"appended target message not found for {identity} in {target_mailbox!r}")
            actual_target_internaldate = (
                str(appended_occurrence.get("internaldate") or "")
                if appended_occurrence is not None
                else target_message_internaldate(imap, appended_num)
            )
            expected_source_internaldate = _normalized_provider_internaldate(
                row.get("internaldate")
            )
            if not _legacy_internaldates_equal(
                actual_target_internaldate,
                expected_source_internaldate,
            ):
                raise RuntimeError(
                    f"cannot confirm fresh append for {identity} in {target_mailbox!r}: "
                    f"target INTERNALDATE {actual_target_internaldate or '<missing>'!r} does not "
                    f"match source {expected_source_internaldate or '<missing>'!r}; no committed "
                    "journal row was written"
                )
            if config.target.provider == "gmail":
                assert appended_occurrence is not None
                appended_mailbox = str(appended_occurrence["mailbox"])
                target_gmail_msgid = str(appended_occurrence["gmail_msgid"])
                used_target_nums.setdefault(
                    _target_mailbox_lookup_key(appended_mailbox, "gmail"),
                    set(),
                ).add(appended_num)
                used_target_gmail_msgids.add(target_gmail_msgid)
                labels_applied = restore_gmail_labels(
                    imap,
                    appended_mailbox,
                    row,
                    target_num=appended_num,
                    target_mailboxes=target_mailboxes,
                    desired_target_mailbox=target_mailbox,
                )
                restore_gmail_starred_flag(
                    imap,
                    appended_mailbox,
                    row,
                    target_num=appended_num,
                )
            else:
                target_gmail_msgid = ""
                labels_applied = []
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
                    labels_applied=labels_applied,
                    actual_target_internaldate=actual_target_internaldate,
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
    routing_plan: Optional[RoutingPlan] = None,
) -> None:
    max_workers = _require_max_workers(max_workers)
    _raise_if_provider_path_symlink(in_root, "import root")
    routing_plan = _effective_provider_routing_plan(
        config,
        in_root,
        routing_plan,
        persist=False,
    )
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)
    failure_kind_lock = threading.Lock()
    integrity_failures: List[str] = []
    operational_failures: List[str] = []

    def classified_recorded_failure(original: Exception) -> Exception:
        """Classify only after the active worker set has finished draining."""
        if _stop_requested(stop_event):
            return original
        with failure_kind_lock:
            recorded_integrity_failures = tuple(integrity_failures)
            recorded_operational_failures = tuple(operational_failures)
        if recorded_operational_failures:
            if type(original) is RuntimeError:
                return original
            return RuntimeError(
                "provider-import failed for "
                f"{len(recorded_operational_failures)} operational account(s): "
                + "; ".join(recorded_operational_failures)
            )
        if recorded_integrity_failures:
            if isinstance(original, ProviderImportIntegrityGateError):
                return original
            return ProviderImportIntegrityGateError(
                "provider-import integrity gate failed for "
                f"{len(recorded_integrity_failures)} account(s): "
                + "; ".join(recorded_integrity_failures)
            )
        return original

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider import {acc.target_email}")
        try:
            with_retry(
                lambda: provider_import_account(
                    config,
                    acc,
                    in_root,
                    stop_event=stop_event,
                    limiter=limiter,
                    routing_plan=routing_plan,
                ),
                attempts=config.limits.retry_max_attempts,
                label=f"provider import {acc.target_email}",
                stop_event=stop_event,
            )
        except Exception as exc:
            message = f"{acc.email}: {exc}"
            with failure_kind_lock:
                failures = (
                    integrity_failures
                    if isinstance(exc, ProviderImportIntegrityGateError)
                    else operational_failures
                )
                failures.append(message)
            raise

    if provider_account_merge_enabled(config):
        grouped: Dict[Tuple[str, str], List[MigrationAccount]] = {}
        for account in config.accounts:
            grouped.setdefault(target_merge_group_key(config, account), []).append(account)
        group_entries = list(grouped.items())
        group_index_by_representative = {
            id(accounts[0]): index
            for index, (_target_key, accounts) in enumerate(group_entries)
        }

        def group_worker(representative: MigrationAccount) -> Tuple[int, List[str]]:
            group_index = group_index_by_representative[id(representative)]
            target_key, accounts = group_entries[group_index]
            group_errors: List[str] = []
            group_failed = False
            for acc in accounts:
                if group_failed:
                    message = (
                        f"{acc.email}: skipped because an earlier source in target merge group "
                        f"{target_key[0]} failed"
                    )
                    logging.error("[provider-import] %s", message)
                    group_errors.append(message)
                    continue
                try:
                    worker(acc)
                except Exception as exc:
                    message = f"{acc.email}: {exc}"
                    logging.error("[provider-import] %s", message)
                    group_errors.append(message)
                    group_failed = True
                    if not ignore_errors:
                        raise
            return group_index, group_errors

        errors_by_group: Dict[int, List[str]] = {}
        representatives = [accounts[0] for _target_key, accounts in group_entries]
        try:
            for _representative, result in _provider_account_worker_results(
                "provider-import-group",
                representatives,
                max_workers,
                group_worker,
                stop_event,
            ):
                group_index, group_errors = result
                errors_by_group[group_index] = group_errors
        except Exception as exc:
            classified = classified_recorded_failure(exc)
            if classified is exc:
                raise
            raise classified from exc
        errors = [
            message
            for group_index in range(len(group_entries))
            for message in errors_by_group.get(group_index, [])
        ]
        if errors:
            failure = RuntimeError(
                f"provider-import failed for {len(errors)} account(s): " + "; ".join(errors)
            )
            classified = classified_recorded_failure(failure)
            if classified is failure:
                raise failure
            raise classified from failure
        return

    try:
        parallel_process_accounts(
            "provider-import",
            worker,
            config.accounts,
            max_workers,
            stop_on_error=not ignore_errors,
            stop_event=stop_event,
        )
    except Exception as exc:
        classified = classified_recorded_failure(exc)
        if classified is exc:
            raise
        raise classified from exc


def _journal_row(
    row: Dict[str, Any],
    target_mailbox: str,
    status: str,
    action: str,
    *,
    target_binding: Dict[str, Any],
    target_gmail_msgid: str = "",
    labels_applied: Optional[Iterable[str]] = None,
    actual_target_internaldate: Optional[str] = None,
    internaldate_evidence_from: Optional[Dict[str, Any]] = None,
    internaldate_origin_action: str = "",
    pre_append_gmail_msgids: Optional[Iterable[str]] = None,
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
    if internaldate_evidence_from is not None and _existing_content_reuse_internaldate_evidence_present(
        internaldate_evidence_from
    ):
        evidence_issue = _existing_content_reuse_internaldate_evidence_issue(
            row,
            internaldate_evidence_from,
        )
        if evidence_issue:
            raise RuntimeError(
                "refusing to propagate invalid existing-content INTERNALDATE evidence: "
                + evidence_issue
            )
        for field in _EXISTING_CONTENT_REUSE_INTERNALDATE_FIELDS:
            journal_row[field] = internaldate_evidence_from[field]
    elif actual_target_internaldate is not None:
        evidence = _existing_content_reuse_internaldate_fields(
            row,
            actual_target_internaldate,
        )
        if evidence:
            if (
                status != "committed"
                or (
                    action != "existing"
                    and internaldate_origin_action != "existing"
                )
            ):
                raise RuntimeError(
                    "existing-content INTERNALDATE divergence can only be journaled by a "
                    "committed existing reuse"
                )
            journal_row.update(evidence)
    if target_gmail_msgid not in (None, ""):
        if not is_valid_gmail_msgid(target_gmail_msgid):
            raise RuntimeError(
                f"invalid canonical Gmail target message ID: {target_gmail_msgid!r}"
            )
        journal_row["target_gmail_msgid"] = target_gmail_msgid
    if pre_append_gmail_msgids is not None:
        if status != "pending" or action != "append-started":
            raise RuntimeError(
                "pre-APPEND Gmail-ID evidence belongs only on pending append-started rows"
            )
        raw_baseline = list(pre_append_gmail_msgids)
        if any(not is_valid_gmail_msgid(value) for value in raw_baseline):
            raise RuntimeError("invalid pre-APPEND Gmail-ID evidence")
        baseline = set(raw_baseline)
        journal_row["pre_append_gmail_msgids"] = sorted(
            baseline,
            key=lambda value: (len(value), value),
        )
    if row.get("routing_active"):
        journal_row["routing_plan_sha256"] = row.get("routing_plan_sha256")
        journal_row["required_gmail_labels"] = sorted(
            {str(value) for value in (row.get("routing_target_labels") or []) if str(value)},
            key=lambda value: (value.casefold(), value),
        )
        journal_row["required_gmail_system_destinations"] = sorted(
            {str(value) for value in (row.get("routing_system_destinations") or []) if str(value)}
        )
        journal_row["label_membership_verified"] = status == "committed"
        journal_row["labels_applied"] = sorted(
            {str(value) for value in (labels_applied or ()) if str(value)},
            key=lambda value: (value.casefold(), value),
        )
    return journal_row


def _build_provider_account_routing_report(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    plan: RoutingPlan,
) -> Dict[str, Any]:
    """Build one deterministic, read-only account/folder routing report."""

    account_dir = account_export_dir(in_root, account)
    _raise_if_provider_path_symlink(account_dir, "account directory")
    staged_rows = load_manifest(account_dir)
    require_manifest_schema(staged_rows)
    require_unique_manifest_identities(staged_rows)
    require_manifest_accounts(staged_rows, account)
    require_manifest_source_provider(staged_rows, config.source.provider)
    require_manifest_integrity_metadata(staged_rows)
    require_complete_export_state(
        account_dir,
        account=account,
        manifest_rows=staged_rows,
        source_provider=config.source.provider,
        target_provider=config.target.provider,
        source_endpoint=config.source,
        target_endpoint=config.target,
        routing_plan_sha256=plan.mapping_digest,
        routing_enabled=True,
    )
    journal_rows = load_import_journal(account_dir, account)
    require_valid_import_journal(journal_rows, account)
    journal_content_issues = committed_journal_manifest_content_issues(
        journal_rows,
        staged_rows,
        target_provider=config.target.provider,
    )
    journal_content_issues.extend(
        pending_journal_manifest_content_issues(
            journal_rows,
            staged_rows,
            target_provider=config.target.provider,
        )
    )
    if journal_content_issues:
        raise RuntimeError("invalid import journal: " + "; ".join(journal_content_issues))
    if config.target.provider == "gmail":
        manifest_ids = {
            str(row.get("canonical_id") or "")
            for row in staged_rows
            if row.get("canonical_id")
        }
        gmail_id_issues = invalid_journal_target_gmail_msgid_issues(
            journal_rows,
            manifest_ids=manifest_ids,
        )
        gmail_id_issues.extend(
            duplicate_journal_target_gmail_msgid_issues(
                journal_rows,
                manifest_ids=manifest_ids,
            )
        )
        gmail_id_issues.extend(
            missing_journal_target_gmail_msgid_issues(
                journal_rows,
                manifest_ids=manifest_ids,
            )
        )
        if gmail_id_issues:
            raise RuntimeError(
                "invalid import journal: " + "; ".join(gmail_id_issues)
            )
    routed_rows, fully_excluded = routed_manifest_rows(
        config,
        account,
        staged_rows,
        plan,
    )
    routed_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in routed_rows
        if row.get("canonical_id")
    }
    evidence_warnings = _deduplicate_report_warnings(
        {
            "source_account": account.source_email,
            "target_account": account.target_email,
            **warning,
        }
        for warning in existing_content_reuse_internaldate_warnings(
            journal_rows,
            routed_rows,
            target_provider=config.target.provider,
        )
    )

    latest_route_commit_by_id: Dict[str, Dict[str, Any]] = {}
    latest_route_status_by_id: Dict[str, Dict[str, Any]] = {}
    historical_labels_by_id: Dict[str, set[str]] = {}
    historical_existing_labels_by_id: Dict[str, set[str]] = {}
    origin_committed_action_by_id: Dict[str, str] = {}
    for journal_row in journal_rows:
        identity = str(journal_row.get("canonical_id") or "")
        manifest_row = routed_by_id.get(identity)
        if manifest_row is None:
            continue
        if journal_row.get("routing_plan_sha256") != plan.mapping_digest:
            continue
        if journal_row.get("status") in {"pending", "failed", "committed"}:
            latest_route_status_by_id[identity] = journal_row
        if journal_row.get("status") != "committed":
            continue
        if not routing_journal_membership_complete(journal_row, manifest_row):
            continue
        latest_route_commit_by_id[identity] = journal_row
        action = str(journal_row.get("action") or "")
        if action in {"existing", "appended"}:
            origin_committed_action_by_id.setdefault(identity, action)
        raw_labels = journal_row.get("labels_applied") or []
        if not isinstance(raw_labels, list):
            continue
        labels = {
            value for value in raw_labels if isinstance(value, str) and value
        }
        if not labels:
            continue
        historical_labels_by_id.setdefault(identity, set()).update(labels)
        applied_to_existing = action == "existing" or (
            action == "labels-reconciled"
            and origin_committed_action_by_id.get(identity) == "existing"
        )
        if applied_to_existing:
            historical_existing_labels_by_id.setdefault(identity, set()).update(labels)

    committed_target_gmail_msgid_by_id = {
        identity: target_gmail_msgid
        for identity, journal_row in latest_route_commit_by_id.items()
        if is_valid_gmail_msgid(
            target_gmail_msgid := journal_row.get("target_gmail_msgid")
        )
    }

    plan_entries = _routing_plan_entries_for_account(plan, account)
    folder_ids: Dict[str, set[str]] = {name: set() for name in plan_entries}
    routed_folder_ids: Dict[str, set[str]] = {name: set() for name in plan_entries}
    excluded_folder_ids: Dict[str, set[str]] = {name: set() for name in plan_entries}
    for staged_row in staged_rows:
        identity = str(staged_row.get("canonical_id") or "")
        memberships = [
            value
            for value in (staged_row.get("source_mailboxes") or [])
            if isinstance(value, str) and value
        ]
        membership_entries = [
            (folder, _routing_entry_for_folder(plan_entries, folder))
            for folder in memberships
        ]
        membership_entries = [
            (folder, entry) for folder, entry in membership_entries if entry is not None
        ]
        for _folder, entry in membership_entries:
            folder_ids.setdefault(entry.source.name, set()).add(identity)
        for _folder, entry in membership_entries:
            if entry.excluded:
                excluded_folder_ids.setdefault(entry.source.name, set()).add(identity)
            elif entry.destinations:
                routed_folder_ids.setdefault(entry.source.name, set()).add(identity)

    folder_reports: List[Dict[str, Any]] = []
    for folder_name, entry in sorted(
        plan_entries.items(),
        key=lambda item: (item[0].casefold(), item[0]),
    ):
        source_name = entry.source.name
        exported_ids = folder_ids.get(source_name, set())
        routed_ids = routed_folder_ids.get(source_name, set())
        excluded_ids = excluded_folder_ids.get(source_name, set())
        committed_ids = routed_ids & set(latest_route_commit_by_id)
        appended_ids = {
            identity
            for identity in committed_ids
            if origin_committed_action_by_id.get(identity) == "appended"
        }
        matched_existing_ids = {
            identity
            for identity in committed_ids
            if origin_committed_action_by_id.get(identity) == "existing"
        }
        latest_actions: Dict[str, int] = {}
        for identity in sorted(committed_ids):
            action = str(latest_route_commit_by_id[identity].get("action") or "committed")
            latest_actions[action] = latest_actions.get(action, 0) + 1
        label_applications = [
            {
                "canonical_id": identity,
                "target_gmail_msgid": committed_target_gmail_msgid_by_id.get(
                    identity,
                    "",
                ),
                "labels": sorted(
                    historical_labels_by_id[identity],
                    key=lambda value: (value.casefold(), value),
                ),
                "labels_applied_to_existing_match": sorted(
                    historical_existing_labels_by_id.get(identity, set()),
                    key=lambda value: (value.casefold(), value),
                ),
            }
            for identity in sorted(routed_ids & set(historical_labels_by_id))
        ]
        folder_reports.append(
            {
                "source_folder": entry.source.name,
                "detected_role": entry.detected_role,
                "assignment_source": entry.assignment_source,
                "excluded": entry.excluded,
                "destinations": [destination.to_dict() for destination in entry.destinations],
                "shared_destinations": sorted(
                    {
                        destination.name
                        for destination in entry.destinations
                        if destination.merged
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "appears_in_inbox": entry.appears_in_inbox,
                "exported_messages": len(exported_ids),
                "routed_messages": len(routed_ids),
                "excluded_messages": len(excluded_ids),
                "committed_messages": len(committed_ids),
                "appended_source_records": len(appended_ids),
                "imported_source_records": len(appended_ids),
                "appended_canonical_ids": sorted(appended_ids),
                "matched_existing_source_records": len(matched_existing_ids),
                "matched_existing_canonical_ids": sorted(matched_existing_ids),
                "origin_unclassified_source_records": len(
                    committed_ids - appended_ids - matched_existing_ids
                ),
                "missing_messages": len(routed_ids - committed_ids),
                "latest_committed_actions": {
                    key: latest_actions[key] for key in sorted(latest_actions)
                },
                "label_applications": label_applications,
                "warnings": list(entry.warnings),
            }
        )

    routed_ids = set(routed_by_id)
    committed_ids = routed_ids & set(latest_route_commit_by_id)
    appended_ids = {
        identity
        for identity in committed_ids
        if origin_committed_action_by_id.get(identity) == "appended"
    }
    matched_existing_ids = {
        identity
        for identity in committed_ids
        if origin_committed_action_by_id.get(identity) == "existing"
    }
    committed_records = [
        {
            "canonical_id": identity,
            "target_gmail_msgid": committed_target_gmail_msgid_by_id.get(
                identity,
                "",
            ),
            "origin_action": origin_committed_action_by_id.get(
                identity,
                "unclassified",
            ),
            "required_custom_labels": sorted(
                {
                    str(value)
                    for value in (
                        routed_by_id[identity].get("routing_target_labels") or []
                    )
                    if str(value)
                },
                key=lambda value: (value.casefold(), value),
            ),
            "required_system_destinations": sorted(
                {
                    str(value)
                    for value in (
                        routed_by_id[identity].get(
                            "routing_system_destinations"
                        )
                        or []
                    )
                    if str(value)
                }
            ),
            "labels_applied": sorted(
                historical_labels_by_id.get(identity, set()),
                key=lambda value: (value.casefold(), value),
            ),
            "labels_applied_to_existing_match": sorted(
                historical_existing_labels_by_id.get(identity, set()),
                key=lambda value: (value.casefold(), value),
            ),
        }
        for identity in sorted(committed_ids)
    ]
    physical_records_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for record in committed_records:
        target_gmail_msgid = str(record["target_gmail_msgid"])
        if not target_gmail_msgid:
            continue
        physical_records_by_id.setdefault(target_gmail_msgid, []).append(record)
    gmail_physical_messages = []
    for target_gmail_msgid in sorted(
        physical_records_by_id,
        key=lambda value: (len(value), value),
    ):
        records = physical_records_by_id[target_gmail_msgid]
        gmail_physical_messages.append(
            {
                "target_account": account.target_email,
                "target_gmail_msgid": target_gmail_msgid,
                "target_gmail_msgid_ref": {
                    "target_account": account.target_email,
                    "target_gmail_msgid": target_gmail_msgid,
                },
                "source_records": len(records),
                "appended_source_records": sum(
                    record["origin_action"] == "appended" for record in records
                ),
                "matched_existing_source_records": sum(
                    record["origin_action"] == "existing" for record in records
                ),
                "required_custom_labels": sorted(
                    {
                        label
                        for record in records
                        for label in record["required_custom_labels"]
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "required_system_destinations": sorted(
                    {
                        system
                        for record in records
                        for system in record["required_system_destinations"]
                    }
                ),
                "labels_applied": sorted(
                    {
                        label
                        for record in records
                        for label in record["labels_applied"]
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "contributors": [
                    {
                        "source_account": account.source_email,
                        "target_account": account.target_email,
                        **record,
                    }
                    for record in records
                ],
            }
        )
    appended_gmail_physical_ids = sorted(
        {
            committed_target_gmail_msgid_by_id[identity]
            for identity in appended_ids
            if identity in committed_target_gmail_msgid_by_id
        },
        key=lambda value: (len(value), value),
    )
    pending_ids = {
        identity
        for identity, row in latest_route_status_by_id.items()
        if identity not in committed_ids and row.get("status") == "pending"
    }
    failed_ids = {
        identity
        for identity, row in latest_route_status_by_id.items()
        if identity not in committed_ids and row.get("status") == "failed"
    }
    return {
        "source_account": account.source_email,
        "target_account": account.target_email,
        "routing_plan_sha256": plan.mapping_digest,
        "ok": not (routed_ids - committed_ids) and not failed_ids and not pending_ids,
        "exported_messages": len(
            {
                str(row.get("canonical_id") or "")
                for row in staged_rows
                if row.get("canonical_id")
            }
        ),
        "routed_messages": len(routed_ids),
        "fully_excluded_messages": len(set(fully_excluded)),
        "committed_messages": len(committed_ids),
        "provenance_count_semantics": (
            "source manifest records; Gmail physical-message IDs are separately deduplicated"
        ),
        "appended_source_records": len(appended_ids),
        "imported_source_records": len(appended_ids),
        "appended_canonical_ids": sorted(appended_ids),
        "appended_gmail_physical_messages": len(appended_gmail_physical_ids),
        "appended_gmail_physical_message_ids": appended_gmail_physical_ids,
        "matched_existing_source_records": len(matched_existing_ids),
        "matched_existing_canonical_ids": sorted(matched_existing_ids),
        "origin_unclassified_source_records": len(
            committed_ids - appended_ids - matched_existing_ids
        ),
        "committed_records": committed_records,
        "gmail_physical_messages": gmail_physical_messages,
        "missing_messages": sorted(routed_ids - committed_ids),
        "pending_messages": sorted(pending_ids),
        "failed_messages": sorted(failed_ids),
        "labels_applied": [
            {
                "canonical_id": identity,
                "target_gmail_msgid": committed_target_gmail_msgid_by_id.get(
                    identity,
                    "",
                ),
                "labels": sorted(
                    labels,
                    key=lambda value: (value.casefold(), value),
                ),
                "labels_applied_to_existing_match": sorted(
                    historical_existing_labels_by_id.get(identity, set()),
                    key=lambda value: (value.casefold(), value),
                ),
            }
            for identity, labels in sorted(historical_labels_by_id.items())
        ],
        "folders": folder_reports,
        "warnings": evidence_warnings,
    }


def build_provider_routing_report(
    config: ProviderMigrationConfig,
    in_root: Path,
    *,
    routing_plan: Optional[RoutingPlan] = None,
) -> Dict[str, Any]:
    """Build the deterministic provider portion of the final routing report."""

    _raise_if_provider_path_symlink(in_root, "routing report root")
    routing_plan = _effective_provider_routing_plan(
        config,
        in_root,
        routing_plan,
        persist=False,
    )
    if routing_plan is None:
        raise RuntimeError("provider routing report requires migration.routing.enabled=true")
    sorted_accounts = sorted(
        config.accounts,
        key=lambda item: (item.source_email.casefold(), item.source_email),
    )
    account_entries = [
        (
            account,
            _build_provider_account_routing_report(
                config,
                account,
                in_root,
                routing_plan,
            ),
        )
        for account in sorted_accounts
    ]
    accounts = [account_report for _account, account_report in account_entries]
    aggregated_warnings = _deduplicate_report_warnings(
        list(routing_plan.warnings)
        + [
            warning
            for account in accounts
            for warning in account.get("warnings", [])
        ]
    )
    physical_contributors_by_ref: Dict[
        Tuple[Tuple[str, str], str],
        List[Dict[str, Any]],
    ] = {}
    for account, account_report in account_entries:
        merge_group_key = target_merge_group_key(config, account)
        for physical_record in account_report.get(
            "gmail_physical_messages",
            [],
        ):
            target_gmail_msgid = str(
                physical_record.get("target_gmail_msgid") or ""
            )
            if not target_gmail_msgid:
                continue
            contributors = physical_record.get("contributors") or []
            if not isinstance(contributors, list):
                continue
            physical_contributors_by_ref.setdefault(
                (merge_group_key, target_gmail_msgid),
                [],
            ).extend(
                contributor
                for contributor in contributors
                if isinstance(contributor, dict)
            )
    gmail_physical_messages: List[Dict[str, Any]] = []
    for merge_group_key, target_gmail_msgid in sorted(
        physical_contributors_by_ref,
        key=lambda value: (
            value[0][0].casefold(),
            value[0][0],
            value[0][1],
            len(value[1]),
            value[1],
        ),
    ):
        contributors = sorted(
            physical_contributors_by_ref[(merge_group_key, target_gmail_msgid)],
            key=lambda item: (
                str(item.get("source_account") or "").casefold(),
                str(item.get("source_account") or ""),
                str(item.get("canonical_id") or ""),
            ),
        )
        gmail_physical_messages.append(
            {
                "target_account": merge_group_key[0],
                "target_gmail_msgid": target_gmail_msgid,
                "target_gmail_msgid_ref": {
                    "target_account": merge_group_key[0],
                    "target_gmail_msgid": target_gmail_msgid,
                },
                "source_records": len(contributors),
                "source_accounts": sorted(
                    {
                        str(item.get("source_account") or "")
                        for item in contributors
                        if item.get("source_account")
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "appended_source_records": sum(
                    item.get("origin_action") == "appended"
                    for item in contributors
                ),
                "matched_existing_source_records": sum(
                    item.get("origin_action") == "existing"
                    for item in contributors
                ),
                "required_custom_labels": sorted(
                    {
                        str(label)
                        for item in contributors
                        for label in (item.get("required_custom_labels") or [])
                        if str(label)
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "required_system_destinations": sorted(
                    {
                        str(system)
                        for item in contributors
                        for system in (
                            item.get("required_system_destinations") or []
                        )
                        if str(system)
                    }
                ),
                "labels_applied": sorted(
                    {
                        str(label)
                        for item in contributors
                        for label in (item.get("labels_applied") or [])
                        if str(label)
                    },
                    key=lambda value: (value.casefold(), value),
                ),
                "contributors": contributors,
            }
        )
    appended_gmail_physical_refs = sorted(
        {
            (target_merge_group_key(config, account), target_gmail_msgid)
            for account, account_report in account_entries
            for target_gmail_msgid in account_report[
                "appended_gmail_physical_message_ids"
            ]
        },
        key=lambda value: (
            value[0][0].casefold(),
            value[0][0],
            value[0][1],
            len(value[1]),
            value[1],
        ),
    )
    return {
        "version": 1,
        "ok": routing_plan.ok and all(account["ok"] for account in accounts),
        "routing_plan_sha256": routing_plan.mapping_digest,
        "labels": {
            "planned_create": list(routing_plan.labels_to_create),
            "planned_reuse": list(routing_plan.labels_reused),
        },
        "totals": {
            "accounts": len(accounts),
            "exported_messages": sum(account["exported_messages"] for account in accounts),
            "routed_messages": sum(account["routed_messages"] for account in accounts),
            "fully_excluded_messages": sum(
                account["fully_excluded_messages"] for account in accounts
            ),
            "committed_messages": sum(account["committed_messages"] for account in accounts),
            "provenance_count_semantics": (
                "source manifest records summed across accounts; Gmail physical-message IDs "
                "are deduplicated within each target merge group"
            ),
            "appended_source_records": sum(
                account["appended_source_records"] for account in accounts
            ),
            "imported_source_records": sum(
                account["imported_source_records"] for account in accounts
            ),
            "appended_gmail_physical_messages": len(
                appended_gmail_physical_refs
            ),
            "appended_gmail_physical_message_ids": [
                target_gmail_msgid
                for _merge_group_key, target_gmail_msgid in appended_gmail_physical_refs
            ],
            "appended_gmail_physical_message_refs": [
                {
                    "target_account": merge_group_key[0],
                    "target_gmail_msgid": target_gmail_msgid,
                }
                for merge_group_key, target_gmail_msgid in appended_gmail_physical_refs
            ],
            "matched_existing_source_records": sum(
                account["matched_existing_source_records"] for account in accounts
            ),
            "origin_unclassified_source_records": sum(
                account["origin_unclassified_source_records"] for account in accounts
            ),
            "missing_messages": sum(len(account["missing_messages"]) for account in accounts),
            "pending_messages": sum(len(account["pending_messages"]) for account in accounts),
            "failed_messages": sum(len(account["failed_messages"]) for account in accounts),
            "messages_with_labels_applied": sum(
                len(account["labels_applied"]) for account in accounts
            ),
            "messages_with_labels_applied_to_existing_matches": sum(
                1
                for account in accounts
                for item in account["labels_applied"]
                if item["labels_applied_to_existing_match"]
            ),
            "gmail_physical_messages": len(gmail_physical_messages),
            "gmail_physical_message_merges": sum(
                record["source_records"] > 1
                for record in gmail_physical_messages
            ),
            "warnings": sum(len(account.get("warnings", [])) for account in accounts),
        },
        "accounts": accounts,
        "gmail_physical_messages": gmail_physical_messages,
        "warnings": aggregated_warnings,
    }


def provider_audit_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    stop_event: Optional[object] = None,
    routing_plan: Optional[RoutingPlan] = None,
) -> Tuple[str, List[str]]:
    issues: List[str] = []
    _raise_if_stopped(stop_event, f"provider audit {account.email}")
    try:
        _raise_if_provider_path_symlink(in_root, "audit root")
    except RuntimeError as exc:
        return account.email, [str(exc)]
    try:
        routing_plan = _effective_provider_routing_plan(
            config,
            in_root,
            routing_plan,
            persist=False,
        )
    except Exception as exc:
        return account.email, [f"routing plan validation failed: {exc}"]
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
            routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
            routing_enabled=config.migration.routing.enabled,
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
    routed_rows = rows
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
            pending_journal_manifest_content_issues(
                journal_rows,
                rows,
                target_provider=config.target.provider,
            )
        )
        if routing_plan is not None:
            try:
                routed_rows, _excluded_identities = routed_manifest_rows(
                    config,
                    account,
                    rows,
                    routing_plan,
                )
            except Exception as exc:
                issues.append(f"routing plan application failed: {exc}")
                routed_rows = []
        issues.extend(
            offline_journal_target_mailbox_issues(
                journal_rows,
                routed_rows,
                target_provider=config.target.provider,
            )
        )
        if config.target.provider == "gmail":
            issues.extend(invalid_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids))
    if config.target.provider == "gmail":
        issues.extend(gmail_draft_combination_issues(routed_rows))
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
    routing_plan: Optional[RoutingPlan] = None,
) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    try:
        _raise_if_provider_path_symlink(in_root, "audit root")
    except RuntimeError as exc:
        return False, [str(exc)]
    try:
        routing_plan = _effective_provider_routing_plan(
            config,
            in_root,
            routing_plan,
            persist=False,
        )
    except Exception as exc:
        return False, [f"routing plan validation failed: {exc}"]
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> List[str]:
        _raise_if_stopped(stop_event, f"provider audit {acc.email}")
        _name, account_issues = provider_audit_account(
            config,
            acc,
            in_root,
            stop_event=stop_event,
            routing_plan=routing_plan,
        )
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
    include_journal: bool = True,
    stop_event: Optional[object] = None,
    routing_plan: Optional[RoutingPlan] = None,
) -> Tuple[str, Dict[str, Any]]:
    _raise_if_stopped(stop_event, f"provider validate {account.email}")
    account_dir = account_export_dir(in_root, account)
    report: Dict[str, Any] = {
        "account": account.email,
        "missing": [],
        "duplicates": [],
        "failed": [],
        "warnings": [],
        "remote_missing": [],
        "remote_checked": 0,
        "committed": 0,
        "exported": 0,
        "routed": 0,
        "excluded": [],
        "ok": False,
    }
    try:
        _raise_if_provider_path_symlink(in_root, "validate root")
    except RuntimeError as exc:
        report["failed"].append(str(exc))
        return account.email, report
    try:
        routing_plan = _effective_provider_routing_plan(
            config,
            in_root,
            routing_plan,
            persist=False,
        )
    except Exception as exc:
        report["failed"].append(f"routing plan validation failed: {exc}")
        return account.email, report
    try:
        _raise_if_provider_path_symlink(account_dir, "account directory")
        journal_rows = (
            load_import_journal(account_dir, account, repair_trailing=repair_trailing_journal)
            if include_journal
            else []
        )
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
            routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
            routing_enabled=config.migration.routing.enabled,
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

    all_manifest_ids = {
        str(row.get("canonical_id") or "")
        for row in manifest_rows
        if row.get("canonical_id")
    }
    all_identity_issues, _all_manifest_id_counts = manifest_identity_issues(manifest_rows)
    if routing_plan is not None:
        try:
            manifest_rows, excluded_identities = routed_manifest_rows(
                config,
                account,
                manifest_rows,
                routing_plan,
            )
        except Exception as exc:
            report["failed"].append(f"routing plan validation failed: {exc}")
            manifest_rows = []
            excluded_identities = sorted(all_manifest_ids)
        report["excluded"] = sorted(excluded_identities)
    if config.target.provider == "gmail":
        report["failed"].extend(gmail_draft_combination_issues(manifest_rows))
    if routing_plan is not None and manifest_rows and not allow_unresolved_pending:
        report["failed"].extend(
            routing_committed_journal_issues(
                journal_rows,
                manifest_rows,
                target_provider=config.target.provider,
            )
        )

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
        report["failed"].extend(
            pending_journal_manifest_content_issues(
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
        report["warnings"] = existing_content_reuse_internaldate_warnings(
            journal_rows,
            manifest_rows,
            target_provider=config.target.provider,
        )
        report["failed"].extend(
            offline_journal_target_mailbox_issues(
                journal_rows,
                manifest_rows,
                target_provider=config.target.provider,
            )
        )
        append_unresolved_pending_failures()

    _routed_identity_issues, manifest_id_counts = manifest_identity_issues(manifest_rows)
    identity_issues = all_identity_issues
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
    if include_journal and provider_account_merge_enabled(config):
        try:
            merge_group_stages = validated_merge_group_stages(
                config,
                in_root,
                account,
                manifest_rows,
                journal_rows,
                repair_trailing_journal=repair_trailing_journal,
                routing_plan_sha256=(routing_plan.mapping_digest if routing_plan is not None else None),
                routing_plan=routing_plan,
            )
            require_merge_group_unique_manifest_identities(merge_group_stages)
            if routing_plan is not None:
                merge_group_stages = [
                    (
                        group_account,
                        group_dir,
                        routed_manifest_rows(
                            config,
                            group_account,
                            group_rows,
                            routing_plan,
                        )[0],
                        group_journal,
                    )
                    for group_account, group_dir, group_rows, group_journal in merge_group_stages
                ]
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
    report["exported"] = len(all_manifest_ids)
    report["routed"] = len(manifest_ids)

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
                duplicate_capacity_stages = merge_group_stages or [
                    (account, account_dir, manifest_rows, journal_rows)
                ]
                expected_identity_sets_by_target = merge_group_expected_identity_sets_by_target(
                    duplicate_capacity_stages,
                    target_mailboxes,
                    target_provider=config.target.provider,
                    expected_content_identities_by_id=merge_group_expected_content_identities_by_id,
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
                        key: row["target_gmail_msgid"]
                        for key, row in effective_committed_rows.items()
                        if config.target.provider == "gmail"
                        and is_valid_gmail_msgid(row.get("target_gmail_msgid"))
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
                    committed_journal_by_id = {
                        str(committed_row.get("canonical_id") or ""): committed_row
                        for committed_row in effective_committed_rows.values()
                        if committed_row.get("canonical_id")
                    }
                    target_gmail_msgid_by_id = {
                        str(row.get("canonical_id") or ""): row[
                            "target_gmail_msgid"
                        ]
                        for row in effective_committed_rows.values()
                        if is_valid_gmail_msgid(row.get("target_gmail_msgid"))
                    }
                    validation_specs: Dict[str, Dict[str, Any]] = {}
                    for identity, row in by_id.items():
                        target_mailbox = target_by_id.get(identity)
                        committed_journal_row = committed_journal_by_id.get(identity)
                        if not target_mailbox or committed_journal_row is None:
                            continue
                        validation_specs[identity] = {
                            "manifest_row": row,
                            "match_row": _committed_target_match_row(
                                row,
                                committed_journal_row,
                            ),
                            "target_mailbox": target_mailbox,
                            "target_gmail_msgid": target_gmail_msgid_by_id.get(identity, ""),
                            "expected_content_identities": expected_content_identities_by_id.get(identity),
                            "require_internaldate_match": True,
                            # A Gmail physical message in All Mail is not enough:
                            # validation also proves its required primary-label
                            # mailbox membership.
                            "required_mailbox": (
                                target_mailbox
                                if config.target.provider == "gmail"
                                else ""
                            ),
                        }
                    validation_assignments = _target_row_assignments(
                        imap,
                        target_mailboxes,
                        validation_specs,
                        target_provider=config.target.provider,
                        required_row_keys=set(validation_specs),
                    )
                    for occurrence in validation_assignments.values():
                        used_target_nums.setdefault(
                            _target_mailbox_lookup_key(
                                occurrence["mailbox"],
                                "gmail"
                                if config.target.provider == "gmail"
                                else config.target.provider,
                            ),
                            set(),
                        ).add(occurrence["num"])
                        if occurrence["gmail_msgid"]:
                            used_target_gmail_msgids.add(occurrence["gmail_msgid"])
                    for identity, row in by_id.items():
                        _raise_if_stopped(stop_event, f"provider validate {account.email}")
                        target_mailbox = target_by_id.get(identity)
                        if not target_mailbox:
                            continue
                        committed_journal_row = committed_journal_by_id.get(identity)
                        assigned_occurrence = validation_assignments.get(identity)
                        expected_content_identities = expected_content_identities_by_id.get(identity)
                        duplicate_capacity_target_key = (
                            "gmail-physical-message"
                            if config.target.provider == "gmail"
                            else _target_mailbox_lookup_key(
                                target_mailbox,
                                config.target.provider,
                            )
                        )
                        expected_identity_sets_by_source = expected_identity_sets_by_target.get(
                            duplicate_capacity_target_key,
                            [],
                        )
                        current_content_identities = _expected_content_identities(
                            row,
                            expected_content_identities,
                        )
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
                            primary_matching_gmail_msgids = matching_gmail_msgids_for_row(
                                imap,
                                row,
                                [target_mailbox],
                                expected_content_identities=expected_content_identities,
                            )
                            expected_occurrences = _max_group_expected_content_identity_intersections(
                                current_content_identities,
                                expected_identity_sets_by_source,
                            )
                            if len(matching_gmail_msgids) > max(expected_occurrences, 1):
                                report["duplicates"].append({
                                    "canonical_id": identity,
                                    "count": len(matching_gmail_msgids),
                                    "source": "target",
                                })
                            actual_state = None
                            if assigned_occurrence is not None:
                                status, _response = select_mailbox(
                                    imap,
                                    assigned_occurrence["mailbox"],
                                    readonly=True,
                                )
                                if status == "OK":
                                    actual_state = _target_gmail_label_flag_internaldate(
                                        imap,
                                        assigned_occurrence["num"],
                                    )
                            actual_labels = actual_state[0] if actual_state is not None else None
                            actual_flags = actual_state[1] if actual_state is not None else None
                            actual_internaldate = actual_state[2] if actual_state is not None else None
                            if actual_labels is None or actual_flags is None:
                                journal_target_gmail_msgid = target_gmail_msgid_by_id.get(
                                    identity,
                                    "",
                                )
                                wrong_date_msgids = primary_matching_gmail_msgids
                                if journal_target_gmail_msgid:
                                    wrong_date_msgids &= {journal_target_gmail_msgid}
                                available_wrong_date_msgids = sorted(
                                    wrong_date_msgids - used_target_gmail_msgids,
                                    key=lambda value: (len(value), value),
                                )
                                wrong_date_state = (
                                    target_gmail_labels_flags_internaldate_for_msgid(
                                        imap,
                                        row,
                                        [target_mailbox],
                                        available_wrong_date_msgids[0],
                                        expected_content_identities=expected_content_identities,
                                    )
                                    if available_wrong_date_msgids
                                    else None
                                )
                                failure_count = len(report["failed"])
                                if wrong_date_state is not None:
                                    append_target_internaldate_failure(
                                        report["failed"],
                                        identity=identity,
                                        target_mailbox=target_mailbox,
                                        row=row,
                                        actual_internaldate=wrong_date_state[2],
                                        journal_row=committed_journal_row,
                                        warnings=report["warnings"],
                                    )
                                if len(report["failed"]) > failure_count:
                                    continue
                                report["remote_missing"].append(identity)
                                continue
                            append_target_internaldate_failure(
                                report["failed"],
                                identity=identity,
                                target_mailbox=target_mailbox,
                                row=row,
                                actual_internaldate=actual_internaldate or "",
                                journal_row=committed_journal_by_id.get(identity),
                                warnings=report["warnings"],
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
                                expected_occurrences = _max_group_expected_content_identity_matches(
                                    matching_content_identities,
                                    expected_identity_sets_by_source,
                                )
                            else:
                                expected_occurrences = _max_group_expected_content_identity_intersections(
                                    current_content_identities,
                                    expected_identity_sets_by_source,
                                )
                            if len(matching_nums) > max(expected_occurrences, 1):
                                report["duplicates"].append({
                                    "canonical_id": identity,
                                    "count": len(matching_nums),
                                    "source": "target",
                                })
                            target_num = (
                                assigned_occurrence["num"]
                                if assigned_occurrence is not None
                                else None
                            )
                            if target_num is None:
                                mailbox_key = _target_mailbox_lookup_key(target_mailbox)
                                available_wrong_date_nums = [
                                    matching_num
                                    for matching_num in matching_nums
                                    if matching_num not in used_target_nums.get(mailbox_key, set())
                                ]
                                failure_count = len(report["failed"])
                                if available_wrong_date_nums:
                                    append_target_internaldate_failure(
                                        report["failed"],
                                        identity=identity,
                                        target_mailbox=target_mailbox,
                                        row=row,
                                        actual_internaldate=target_message_internaldate(
                                            imap,
                                            available_wrong_date_nums[0],
                                        ),
                                        journal_row=committed_journal_row,
                                        warnings=report["warnings"],
                                    )
                                if len(report["failed"]) > failure_count:
                                    continue
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
                                journal_row=committed_journal_by_id.get(identity),
                                warnings=report["warnings"],
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
    routing_plan: Optional[RoutingPlan] = None,
) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    try:
        _raise_if_provider_path_symlink(in_root, "validate root")
    except RuntimeError as exc:
        return False, [str(exc)]
    try:
        routing_plan = _effective_provider_routing_plan(
            config,
            in_root,
            routing_plan,
            persist=False,
        )
    except Exception as exc:
        return False, [f"routing plan validation failed: {exc}"]
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> Dict[str, Any]:
        _raise_if_stopped(stop_event, f"provider validate {acc.email}")
        _name, report = provider_validate_account(
            config,
            acc,
            in_root,
            check_target=True,
            stop_event=stop_event,
            routing_plan=routing_plan,
        )
        _raise_if_stopped(stop_event, f"provider validate {acc.email}")
        return report

    for _acc, report in _provider_account_worker_results("provider-validate", config.accounts, max_workers, worker, stop_event):
        for warning in report.get("warnings", []):
            if isinstance(warning, dict):
                warning_message = str(warning.get("message") or warning)
            else:
                warning_message = str(warning)
            logging.warning("[provider-validate] %s: %s", report["account"], warning_message)
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


def _routing_source_folders(
    account: MigrationAccount,
    mailboxes: List[MailboxInfo],
    *,
    source_provider: str,
) -> List[SourceFolder]:
    return [
        SourceFolder(
            source_account=account.source_email,
            name=mailbox.name,
            delimiter=mailbox.delimiter,
            attributes=mailbox.attributes,
        )
        for mailbox in mailboxes
        if not is_noselect(mailbox)
        and not should_skip_source_mailbox(source_provider, mailbox, mailboxes)
    ]


def _routing_target_labels_from_imap(
    mailboxes: List[MailboxInfo],
    *,
    target_provider: str,
) -> List[TargetLabel]:
    labels: List[TargetLabel] = []
    for mailbox in mailboxes:
        if is_noselect(mailbox) or is_virtual_target_mailbox(target_provider, mailbox):
            continue
        if target_provider == "gmail":
            system_role = _gmail_system_key_for_mailbox(mailbox)
            labels.append(
                TargetLabel(
                    name=mailbox.name,
                    kind=GMAIL_SYSTEM if system_role else CUSTOM_LABEL,
                    system_role=system_role or None,
                    delimiter=mailbox.delimiter or "/",
                )
            )
        else:
            labels.append(
                TargetLabel(
                    name=mailbox.name,
                    kind=GENERIC_MAILBOX,
                    delimiter=mailbox.delimiter,
                )
            )
    return labels


_GMAIL_API_SYSTEM_ROLE_BY_ID = {
    "INBOX": "inbox",
    "SENT": "sent",
    "DRAFT": "drafts",
    "DRAFTS": "drafts",
    "TRASH": "trash",
    "SPAM": "spam",
    "IMPORTANT": "important",
    "STARRED": "starred",
}
_GMAIL_ROUTING_IMAP_REQUIRED_SYSTEM_ROLES = frozenset(
    {"all", "inbox", "sent", "drafts", "trash", "spam"}
)


def _routing_merge_gmail_api_labels(
    imap_labels: List[TargetLabel],
    api_labels: Iterable[Any],
) -> List[TargetLabel]:
    """Enrich IMAP system labels and merge Gmail API user labels."""

    result = list(imap_labels)
    user_by_name = {
        label.name: index
        for index, label in enumerate(result)
        if label.kind == CUSTOM_LABEL
    }
    system_by_role = {
        str(label.system_role): index
        for index, label in enumerate(result)
        if label.kind == GMAIL_SYSTEM and label.system_role
    }
    for raw in api_labels:
        if isinstance(raw, dict):
            label_id = str(raw.get("id") or "")
            name = str(raw.get("name") or "")
            label_type = str(raw.get("type") or "").lower()
        else:
            label_id = str(getattr(raw, "id", None) or getattr(raw, "label_id", None) or "")
            name = str(getattr(raw, "name", "") or "")
            label_type = str(getattr(raw, "type", None) or getattr(raw, "kind", None) or "").lower()
        if not label_id or not name:
            raise RuntimeError("Gmail API returned a label without a non-empty id and name")
        if label_type == "system":
            system_role = _GMAIL_API_SYSTEM_ROLE_BY_ID.get(label_id.upper())
            if system_role is None:
                continue
            existing_index = system_by_role.get(system_role)
            if existing_index is not None:
                result[existing_index] = dataclasses.replace(
                    result[existing_index],
                    target_id=label_id,
                )
            elif system_role not in _GMAIL_ROUTING_IMAP_REQUIRED_SYSTEM_ROLES:
                system_by_role[system_role] = len(result)
                result.append(
                    TargetLabel(
                        name=name,
                        kind=GMAIL_SYSTEM,
                        system_role=system_role,
                        target_id=label_id,
                    )
                )
            # A Gmail API primary/system mailbox label is not proof that its
            # IMAP SPECIAL-USE mailbox is selectable.  Those roles may only
            # enrich an IMAP finding; metadata-only roles remain API-capable.
            continue
        if label_type != "user":
            raise RuntimeError(f"Gmail API returned label {name!r} with unknown type {label_type!r}")
        label = TargetLabel(
            name=name,
            kind=CUSTOM_LABEL,
            target_id=label_id,
        )
        existing_index = user_by_name.get(name)
        if existing_index is not None:
            result[existing_index] = label
        else:
            user_by_name[name] = len(result)
            result.append(label)
    return result


def provider_discover_routing_plan(
    config: ProviderMigrationConfig,
    *,
    max_workers: int,
    stop_event: Optional[object] = None,
    gmail_api_labels: Optional[Iterable[Any]] = None,
) -> RoutingPlan:
    """Read live source/target discovery and resolve the opt-in route plan."""

    if not config.migration.routing.enabled:
        raise ValueError("provider routing discovery requires migration.routing.enabled=true")
    max_workers = _require_max_workers(max_workers)
    source_folders: List[SourceFolder] = []

    def source_worker(account: MigrationAccount) -> List[SourceFolder]:
        _raise_if_stopped(stop_event, f"routing discovery {account.source_email}")
        with imap_connection(config.source, account, role="source") as source_imap:
            mailboxes = list_mailboxes(source_imap)
        return _routing_source_folders(
            account,
            mailboxes,
            source_provider=config.source.provider,
        )

    for _account, folders in _provider_account_worker_results(
        "provider-routing-discovery",
        config.accounts,
        max_workers,
        source_worker,
        stop_event,
    ):
        source_folders.extend(folders)

    representative = config.accounts[0]
    _raise_if_stopped(stop_event, "routing target discovery")
    with imap_connection(config.target, representative, role="target") as target_imap:
        target_mailboxes = list_mailboxes(target_imap)
    target_labels = _routing_target_labels_from_imap(
        target_mailboxes,
        target_provider=config.target.provider,
    )
    if gmail_api_labels is not None:
        if config.target.provider != "gmail":
            raise ValueError("gmail_api_labels may be supplied only for a Gmail target")
        target_labels = _routing_merge_gmail_api_labels(target_labels, gmail_api_labels)
    plan = resolve_routing_plan(
        config.migration.routing,
        source_folders,
        target_labels,
    )
    return plan


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
                routed_virtual_memberships = config.migration.routing.enabled
                retained_source_mailboxes = _source_mailbox_scan_order(
                    provider_key,
                    [
                        mailbox
                        for mailbox in source_mailboxes
                        if not should_skip_source_mailbox(
                            config.source.provider,
                            mailbox,
                            source_mailboxes,
                        )
                    ],
                    routed_virtual_memberships=routed_virtual_memberships,
                )
                fetch_body_for_identity = (
                    provider_key != "gmail"
                    and any(
                        _is_non_gmail_all_mailbox(provider_key, mailbox)
                        or bool(
                            _non_gmail_foldable_virtual_membership(
                                provider_key,
                                mailbox,
                                routed_memberships=routed_virtual_memberships,
                            )
                        )
                        for mailbox in retained_source_mailboxes
                    )
                )
                ordinary_content_remaining_for_all: Dict[Tuple[int, str], int] = {}
                ordinary_delivery_remaining_for_all: Dict[Tuple[int, str], Dict[_ProviderVirtualDeliveryKey, int]] = {}
                routed_anchor_deliveries_by_content: Dict[
                    Tuple[int, str],
                    List[_ProviderVirtualDeliveryKey],
                ] = {}
                foldable_virtual_anchor_dates_by_content: Dict[
                    Tuple[int, str],
                    List[str],
                ] = {}
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
                    pending_all_sizes_by_content: Dict[
                        Tuple[int, str],
                        List[Tuple[int, _ProviderVirtualDeliveryKey, str]],
                    ] = {}
                    consumed_virtual_anchors_by_content: Dict[
                        Tuple[int, str],
                        set[int],
                    ] = {}
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
                            non_gmail_virtual_source = _non_gmail_foldable_virtual_membership(
                                provider_key,
                                mailbox,
                                routed_memberships=routed_virtual_memberships,
                            )
                            if non_gmail_all_source:
                                if routed_virtual_memberships:
                                    pending_all_sizes_by_content.setdefault(
                                        content_identity,
                                        [],
                                    ).append(
                                        (
                                            size,
                                            _provider_virtual_delivery_key(parsed),
                                            _legacy_internaldate_utc_key(
                                                parsed.get("internaldate")
                                            ),
                                        )
                                    )
                                    continue
                                remaining_ordinary = ordinary_content_remaining_for_all.get(content_identity, 0)
                                if remaining_ordinary > 0:
                                    pending_all_sizes_by_content.setdefault(content_identity, []).append((
                                        size,
                                        _provider_virtual_delivery_key(parsed),
                                        _legacy_internaldate_utc_key(
                                            parsed.get("internaldate")
                                        ),
                                    ))
                                    continue
                                source_total += size
                                foldable_virtual_anchor_dates_by_content.setdefault(
                                    content_identity,
                                    [],
                                ).append(
                                    _legacy_internaldate_utc_key(
                                        parsed.get("internaldate")
                                    )
                                )
                                continue
                            if non_gmail_virtual_source:
                                virtual_date_key = _legacy_internaldate_utc_key(
                                    parsed.get("internaldate")
                                )
                                if not virtual_date_key:
                                    # Export refuses covered virtual-view
                                    # folding without a valid INTERNALDATE, so
                                    # capacity estimation must count it as a
                                    # separate physical payload as well.
                                    source_total += size
                                    continue
                                anchor_dates = foldable_virtual_anchor_dates_by_content.get(
                                    content_identity,
                                    [],
                                )
                                consumed_anchors = (
                                    consumed_virtual_anchors_by_content.setdefault(
                                        content_identity,
                                        set(),
                                    )
                                    if routed_virtual_memberships
                                    else set()
                                )
                                matching_anchor_indices = [
                                    index
                                    for index, anchor_date in enumerate(anchor_dates)
                                    if index not in consumed_anchors
                                    and anchor_date == virtual_date_key
                                ]
                                if len(matching_anchor_indices) == 1:
                                    if routed_virtual_memberships:
                                        consumed_anchors.add(matching_anchor_indices[0])
                                else:
                                    source_total += size
                                continue
                            ordinary_content_remaining_for_all[content_identity] = (
                                ordinary_content_remaining_for_all.get(content_identity, 0) + 1
                            )
                            delivery_key = _provider_virtual_delivery_key(parsed)
                            delivery_remaining = ordinary_delivery_remaining_for_all.setdefault(content_identity, {})
                            delivery_remaining[delivery_key] = delivery_remaining.get(delivery_key, 0) + 1
                            foldable_virtual_anchor_dates_by_content.setdefault(
                                content_identity,
                                [],
                            ).append(
                                _legacy_internaldate_utc_key(
                                    parsed.get("internaldate")
                                )
                            )
                            if routed_virtual_memberships:
                                routed_anchor_deliveries_by_content.setdefault(
                                    content_identity,
                                    [],
                                ).append(delivery_key)
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
                        if routed_virtual_memberships:
                            anchor_deliveries = routed_anchor_deliveries_by_content.get(
                                content_identity,
                                [],
                            )
                            available_by_delivery: Dict[_ProviderVirtualDeliveryKey, int] = {}
                            for anchor_delivery in anchor_deliveries:
                                available_by_delivery[anchor_delivery] = (
                                    available_by_delivery.get(anchor_delivery, 0) + 1
                                )
                            consumed_by_delivery: Dict[_ProviderVirtualDeliveryKey, int] = {}
                            unmatched_sizes: List[
                                Tuple[int, _ProviderVirtualDeliveryKey, str]
                            ] = []
                            for size, delivery_key, internaldate_key in pending_sizes:
                                consumed = consumed_by_delivery.get(delivery_key, 0)
                                if consumed < available_by_delivery.get(delivery_key, 0):
                                    consumed_by_delivery[delivery_key] = consumed + 1
                                else:
                                    unmatched_sizes.append(
                                        (size, delivery_key, internaldate_key)
                                    )
                            if unmatched_sizes:
                                source_total += sum(
                                    size
                                    for size, _delivery_key, _internaldate_key in unmatched_sizes
                                )
                                routed_anchor_deliveries_by_content.setdefault(
                                    content_identity,
                                    [],
                                ).extend(
                                    delivery_key
                                    for _size, delivery_key, _internaldate_key in unmatched_sizes
                                )
                                foldable_virtual_anchor_dates_by_content.setdefault(
                                    content_identity,
                                    [],
                                ).extend(
                                    internaldate_key
                                    for _size, _delivery_key, internaldate_key in unmatched_sizes
                                )
                            continue
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
                        source_total += sum(
                            size
                            for size, _delivery_key, _internaldate_key in pending_sizes
                        )
                        foldable_virtual_anchor_dates_by_content.setdefault(
                            content_identity,
                            [],
                        ).extend(
                            internaldate_key
                            for _size, _delivery_key, internaldate_key in pending_sizes
                        )
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
