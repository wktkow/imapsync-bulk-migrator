from __future__ import annotations

import contextlib
import hashlib
import imaplib
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .executor import parallel_process_accounts
from .models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig, auth_username_identity
from .utils import decode_imap_utf7, encode_imap_utf7, sanitize_for_path


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


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

    def wait_for(self, byte_count: int) -> None:
        if self.max_bytes_per_second <= 0 or byte_count <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                time.sleep(self._next_time - now)
                now = time.monotonic()
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
        value = Path(auth.token_file).read_text(encoding="utf-8")
    elif auth.password_file:
        value = Path(auth.password_file).read_text(encoding="utf-8")
    elif auth.password is not None:
        value = auth.password
    else:
        raise RuntimeError(f"no secret configured for auth method {auth.method}")
    value = value.strip()
    if not value:
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
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(Exception):
        os.chmod(path, PRIVATE_DIR_MODE)


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
        port = int(state["port"])
        use_ssl = bool(state["ssl"])
        starttls = bool(state["starttls"])
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
    if digest == expected_digest:
        return True
    if isinstance(actual_endpoint, dict):
        return digest == _provider_endpoint_state_payload_digest(actual_endpoint)
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


def with_retry(fn: Callable[[], Any], *, attempts: int, label: str) -> Any:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt >= attempts or not is_transient_imap_error(exc):
                raise
            delay = min(60.0, 2.0 ** (attempt - 1))
            logging.warning("%s failed transiently on attempt %d/%d: %s; retrying in %.1fs", label, attempt, attempts, exc, delay)
            time.sleep(delay)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"{label} did not run")


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
    return False


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
    special_desired = {"archive", "sent", "drafts", "deleted messages", "trash", "junk", "spam", "important", "starred", "inbox"}
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


def list_mailboxes(imap: imaplib.IMAP4) -> List[MailboxInfo]:
    status, data = imap.list()
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


def _extract_parenthesized_after(meta_str: str, atom: str) -> str:
    match = re.search(rf"{re.escape(atom)}\s+\(", meta_str, flags=re.IGNORECASE)
    if not match:
        return ""
    start = match.end() - 1
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


def parse_provider_fetch_response(fetch_response: Iterable[Any]) -> Dict[str, Any]:
    msg_bytes: Optional[bytes] = None
    meta_chunks: List[str] = []
    literal_labels: List[str] = []
    label_literal_context = False
    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            meta, body = part
            meta_text = ""
            if isinstance(meta, (bytes, bytearray)):
                meta_text = bytes(meta).decode(errors="ignore")
                meta_chunks.append(meta_text)
                if re.search(r"\bX-GM-LABELS\b[^\r\n]*\{\d+\}", meta_text, flags=re.IGNORECASE):
                    label_literal_context = True
            is_label_literal = bool(
                re.search(r"\bX-GM-LABELS\b[^\r\n]*\{\d+\}", meta_text, flags=re.IGNORECASE)
                or (label_literal_context and re.fullmatch(r"\s*\{\d+\}\s*", meta_text))
            )
            if (
                isinstance(body, (bytes, bytearray))
                and body
                and re.search(r"(?:BODY(?:\.PEEK)?\[\]|(?<![\w.])RFC822(?![\w.]))", meta_text, flags=re.IGNORECASE)
            ):
                msg_bytes = bytes(body) if msg_bytes is None else msg_bytes + bytes(body)
            elif isinstance(body, (bytes, bytearray)) and body and is_label_literal:
                label = decode_imap_utf7(bytes(body).decode("ascii", errors="ignore").strip())
                if label:
                    literal_labels.append(label)
        elif isinstance(part, (bytes, bytearray)):
            meta_text = bytes(part).decode(errors="ignore")
            meta_chunks.append(meta_text)
            if label_literal_context and ")" in meta_text:
                label_literal_context = False
    meta_str = " ".join(meta_chunks)

    def group(pattern: str) -> Optional[str]:
        match = re.search(pattern, meta_str, flags=re.IGNORECASE)
        return match.group(1) if match else None

    size_raw = group(r"RFC822\.SIZE\s+(\d+)")
    labels_raw = _extract_parenthesized_after(meta_str, "X-GM-LABELS")
    labels = _parse_parenthesized_words(labels_raw or "", drop_literal_markers=True)
    for label in literal_labels:
        if label not in labels:
            labels.append(label)
    return {
        "message_bytes": msg_bytes,
        "flags": group(r"FLAGS\s+\((.*?)\)") or "",
        "internaldate": group(r'INTERNALDATE\s+"([^"]+)"') or "",
        "rfc822_size": int(size_raw) if size_raw else (len(msg_bytes) if msg_bytes else 0),
        "gmail_msgid": group(r"X-GM-MSGID\s+(\d+)") or "",
        "gmail_thrid": group(r"X-GM-THRID\s+(\d+)") or "",
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
            return data[0].decode(errors="ignore") if isinstance(data[0], bytes) else str(data[0])
    return ""


def _parse_uid_search_data(data: Any) -> List[int]:
    uids: List[int] = []
    if data and data[0]:
        for token in data[0].split():
            with contextlib.suppress(ValueError):
                uids.append(int(token))
    return sorted(uids)


def fetch_all_uids_and_uidvalidity(imap: imaplib.IMAP4, mailbox: str) -> Tuple[List[int], str]:
    status, response = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        raise RuntimeError(f"failed to select mailbox {mailbox}: {response}")
    uidvalidity = selected_uidvalidity(imap)
    status, data = imap.uid("search", "ALL")
    if status != "OK":
        raise RuntimeError(f"failed to search UIDs in {mailbox}")
    return _parse_uid_search_data(data), uidvalidity


def _message_id_header(msg_bytes: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(msg_bytes)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


def canonical_identity(
    parsed: Dict[str, Any],
    msg_bytes: bytes,
    *,
    mailbox: str = "",
    uidvalidity: str = "",
    uid: Optional[int] = None,
    collapse_fallback: bool = False,
) -> Tuple[str, str, str]:
    sha256 = hashlib.sha256(msg_bytes).hexdigest()
    gmail_msgid = str(parsed.get("gmail_msgid") or "")
    if gmail_msgid:
        return f"gmail-{gmail_msgid}", sha256, _message_id_header(msg_bytes)
    size = int(parsed.get("rfc822_size") or len(msg_bytes))
    message_id = _message_id_header(msg_bytes)
    if collapse_fallback or not mailbox or uid is None:
        seed = f"{message_id}|{sha256}|{size}"
        return f"fallback-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}", sha256, message_id
    seed = f"{mailbox}|{uidvalidity}|{uid}|{sha256}|{size}"
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
    return sanitize_for_path(identity)[:180]


def _atomic_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_private_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
        with contextlib.suppress(Exception):
            os.chmod(path, PRIVATE_FILE_MODE)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def _atomic_bytes(path: Path, payload: bytes) -> None:
    ensure_private_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
        with contextlib.suppress(Exception):
            os.chmod(path, PRIVATE_FILE_MODE)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    ensure_private_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for row in rows:
                json.dump(row, f, ensure_ascii=False, sort_keys=True)
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
        with contextlib.suppress(Exception):
            os.chmod(path, PRIVATE_FILE_MODE)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def account_export_dir(root: Path, account: MigrationAccount) -> Path:
    return root / sanitize_for_path(account.source_email)


def load_manifest(account_dir: Path) -> List[Dict[str, Any]]:
    manifest = account_dir / "manifest.jsonl"
    if not manifest.exists():
        raise RuntimeError(f"manifest not found: {manifest}")
    rows: List[Dict[str, Any]] = []
    with manifest.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
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


def latest_committed_journal_rows(rows: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    latest: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        identity = str(row.get("canonical_id") or "")
        target_mailbox = str(row.get("target_mailbox") or "")
        if not identity or not target_mailbox:
            continue
        key = (identity, target_mailbox)
        if row.get("status") == "committed":
            latest[key] = row
        else:
            latest.pop(key, None)
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
        state = json.loads(state_path.read_text(encoding="utf-8"))
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
        if not isinstance(expected_size, int) or expected_size <= 0:
            issues.append(f"{identity}: missing or invalid rfc822_size")
    return issues


def require_manifest_integrity_metadata(rows: List[Dict[str, Any]]) -> None:
    issues = manifest_integrity_issues(rows)
    if issues:
        raise RuntimeError("invalid manifest integrity metadata: " + "; ".join(issues))


def require_manifest_payload_matches(row: Dict[str, Any], data: bytes) -> None:
    identity = str(row.get("canonical_id") or "<missing>")
    expected_size = row.get("rfc822_size")
    if not isinstance(expected_size, int) or expected_size <= 0:
        raise RuntimeError(f"{identity}: missing or invalid rfc822_size")
    if len(data) != expected_size:
        raise RuntimeError(f"{identity}: rfc822_size mismatch (manifest={expected_size} actual={len(data)})")
    expected_hash = row.get("content_sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
        raise RuntimeError(f"{identity}: missing or invalid content_sha256")
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash.lower() != expected_hash.lower():
        raise RuntimeError(f"{identity}: content_sha256 mismatch")


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
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
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
            elif metadata[key] != row[key]:
                issues.append(f"{identity}: metadata {key} differs from manifest")
    return issues


def journal_row_issues(rows: List[Dict[str, Any]], account: MigrationAccount) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            issues.append(f"journal row {idx} is not an object")
            continue
        status = str(row.get("status") or "")
        if status not in {"pending", "committed"}:
            issues.append(f"journal row {idx} has invalid status: {status or '<missing>'}")
            continue
        identity = str(row.get("canonical_id") or "")
        target_mailbox = str(row.get("target_mailbox") or "")
        target_account = str(row.get("target_account") or "")
        label = identity or f"row {idx}"
        if not identity:
            issues.append(f"journal row {idx} missing canonical_id")
        if not target_mailbox:
            issues.append(f"journal {label} missing target_mailbox")
        if target_account != account.target_email:
            issues.append(
                f"journal {label} target_account does not match config target_email "
                f"{account.target_email}: {target_account or '<missing>'}"
            )
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
) -> List[str]:
    by_msgid: Dict[str, set[str]] = {}
    by_identity: Dict[str, set[str]] = {}
    latest_rows = latest_committed_journal_rows(rows)
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
) -> List[str]:
    issues: List[str] = []
    for (identity, target_mailbox), row in latest_committed_journal_rows(rows).items():
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
) -> List[Dict[str, Any]]:
    manifest_by_id = {
        str(row.get("canonical_id") or ""): row
        for row in manifest_rows
        if row.get("canonical_id")
    }
    repaired_rows = list(rows)
    issues: List[str] = []
    for (identity, target_mailbox), journal_row in latest_committed_journal_rows(repaired_rows).items():
        if not identity or identity not in manifest_by_id or journal_row.get("target_gmail_msgid"):
            continue
        expected_target_mailbox = target_mailbox_by_identity.get(identity)
        if expected_target_mailbox and target_mailbox != expected_target_mailbox:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and is in wrong target mailbox: "
                f"{identity} expected {expected_target_mailbox!r} got {target_mailbox!r}"
            )
            continue
        manifest_row = manifest_by_id[identity]
        matches: Dict[str, bytes] = {}
        for num in target_matching_message_nums(imap, target_mailbox, manifest_row, create_if_missing=False):
            gmail_msgid = _target_gmail_msgid(imap, num)
            if gmail_msgid:
                matches.setdefault(gmail_msgid, num)
        if not matches:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and target message was not found: "
                f"{identity} in {target_mailbox or '<missing>'}"
            )
            continue
        if len(matches) > 1:
            issues.append(
                f"journal committed Gmail target row missing target_gmail_msgid and matched multiple target Gmail messages: "
                f"{identity} in {target_mailbox}: " + ", ".join(sorted(matches))
            )
            continue
        target_gmail_msgid = next(iter(matches))
        repaired = _journal_row(
            manifest_row,
            target_mailbox,
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
) -> List[Dict[str, Any]]:
    by_msgid: Dict[str, set[str]] = {}
    by_identity: Dict[str, set[str]] = {}
    latest_rows = latest_committed_journal_rows(rows)
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
    if not path.exists():
        return rows
    lines = path.read_text(encoding="utf-8").splitlines()
    needs_rewrite = False
    for line_no, line in enumerate(lines, 1):
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        json.dump(row, f, ensure_ascii=False, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    with contextlib.suppress(Exception):
        os.chmod(path, PRIVATE_FILE_MODE)


def _manifest_path(account_dir: Path, row: Dict[str, Any], key: str) -> Path:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: missing {key}")
    rel_path = Path(value)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: unsafe {key}: {value!r}")
    root = account_dir.resolve()
    candidate = (account_dir / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"manifest row {row.get('canonical_id') or '<unknown>'}: unsafe {key}: {value!r}") from exc
    return candidate


def _finalize_export_record(record: Dict[str, Any], folder_map: Dict[str, str]) -> None:
    record["source_mailboxes"] = sorted(str(value) for value in record.get("source_mailboxes", []))
    record["gmail_labels"] = sorted(str(value) for value in record.get("gmail_labels", []))
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


def provider_export_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    out_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
) -> None:
    account_dir = account_export_dir(out_root, account)
    messages: Dict[str, Dict[str, Any]] = {}
    manifest_path = account_dir / "manifest.jsonl"
    preserve_complete_state_until_ready = False
    active_identities: set[str] = set()
    previous_uidvalidities_by_mailbox: Dict[str, set[str]] = {}
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
        try:
            existing_state = json.loads((account_dir / "export-state.json").read_text(encoding="utf-8"))
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

    with imap_connection(config.source, account, role="source") as imap:
        capabilities = get_capabilities(imap)
        gmail_extensions = "X-GM-EXT-1" in capabilities
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
        for mailbox in mailboxes:
            if is_noselect(mailbox):
                logging.info("[provider-export] %s: skipping non-selectable mailbox %s", account.source_email, mailbox.name)
                continue
            if is_virtual_source_mailbox(config.source.provider, mailbox):
                logging.info("[provider-export] %s: skipping virtual source mailbox %s", account.source_email, mailbox.name)
                continue
            _raise_if_stopped(stop_event, f"provider export {account.source_email}")
            uids, uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox.name)
            previous_uidvalidities = previous_uidvalidities_by_mailbox.get(mailbox.name, set())
            if previous_uidvalidities and uidvalidity and uidvalidity not in previous_uidvalidities:
                raise RuntimeError(
                    f"UIDVALIDITY changed since previous export for {mailbox.name}: "
                    f"previous={sorted(previous_uidvalidities)} current={uidvalidity}; "
                    "start a new export directory to avoid duplicate physical identities"
                )
            logging.info("[provider-export] %s: %s -> %d messages", account.source_email, mailbox.name, len(uids))
            for uid in uids:
                _raise_if_stopped(stop_event, f"provider export {account.source_email}")
                status, meta_data = imap.uid(
                    "fetch",
                    str(uid),
                    fetch_items(include_body=False, gmail_extensions=gmail_extensions),
                )
                if status != "OK":
                    raise RuntimeError(f"metadata fetch failed in {mailbox.name} for UID {uid}: {meta_data}")
                pre_parsed = parse_provider_fetch_response(meta_data or [])
                identity_hint = f"gmail-{pre_parsed.get('gmail_msgid')}" if pre_parsed.get("gmail_msgid") else ""
                if identity_hint and identity_hint in messages:
                    try:
                        _manifest_path(account_dir, messages[identity_hint], "eml_path")
                    except Exception:
                        logging.warning("[provider-export] %s: existing manifest row for %s has invalid eml_path; refetching body", account.source_email, identity_hint)
                    else:
                        if _manifest_path(account_dir, messages[identity_hint], "eml_path").exists():
                            update_membership(identity_hint, mailbox, uid, uidvalidity, pre_parsed)
                            persist_export_records(account_dir, active_export_records(), config.migration.folder_map)
                            continue
                limiter.wait_for(int(pre_parsed.get("rfc822_size") or 0))
                status, data = imap.uid(
                    "fetch",
                    str(uid),
                    fetch_items(include_body=True, gmail_extensions=gmail_extensions),
                )
                if status != "OK":
                    raise RuntimeError(f"fetch failed in {mailbox.name} for UID {uid}: {data}")
                parsed = parse_provider_fetch_response(data or [])
                for key, value in pre_parsed.items():
                    if key != "message_bytes" and not parsed.get(key):
                        parsed[key] = value
                if config.source.provider == "gmail" and not parsed.get("gmail_msgid"):
                    raise RuntimeError(
                        f"Gmail source fetch for {account.source_email} UID {uid} in {mailbox.name} "
                        "did not return X-GM-MSGID"
                    )
                msg_bytes = parsed.get("message_bytes")
                if not isinstance(msg_bytes, bytes) or not msg_bytes:
                    raise RuntimeError(f"body fetch returned no message bytes in {mailbox.name} for UID {uid}")
                identity, sha256, message_id = canonical_identity(
                    parsed,
                    msg_bytes,
                    mailbox=mailbox.name,
                    uidvalidity=uidvalidity,
                    uid=uid,
                    collapse_fallback=config.source.provider == "gmail",
                )
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
                        "gmail_msgid": parsed.get("gmail_msgid") or "",
                        "gmail_thrid": parsed.get("gmail_thrid") or "",
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
                    if not (account_dir / eml_rel).exists():
                        _atomic_bytes(account_dir / eml_rel, msg_bytes)
                    record.setdefault("source_provider", config.source.provider)
                    record.setdefault("source_account", account.source_email)
                    record["target_account"] = account.target_email
                    record.setdefault("gmail_msgid", parsed.get("gmail_msgid") or "")
                    record.setdefault("gmail_thrid", parsed.get("gmail_thrid") or "")
                    record.setdefault("message_id_header", message_id)
                    record.setdefault("content_sha256", sha256)
                    record.setdefault("rfc822_size", int(parsed.get("rfc822_size") or len(msg_bytes)))
                    record.setdefault("flags", parsed.get("flags") or "")
                    record.setdefault("internaldate", parsed.get("internaldate") or "")
                    record.setdefault("exported_at", _utc_now())
                record = messages[identity]
                update_membership(identity, mailbox, uid, uidvalidity, parsed)
                persist_export_records(account_dir, active_export_records(), config.migration.folder_map)
            status, response = select_mailbox(imap, mailbox.name, readonly=True)
            if status != "OK":
                raise RuntimeError(f"failed to reselect mailbox {mailbox.name} after export: {response}")
            final_uidvalidity = selected_uidvalidity(imap)
            if uidvalidity and final_uidvalidity and final_uidvalidity != uidvalidity:
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

    final_records = active_export_records()
    persist_export_records(account_dir, final_records, config.migration.folder_map)
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
    out_root.mkdir(parents=True, exist_ok=True)
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider export {acc.source_email}")
        with_retry(
            lambda: provider_export_account(config, acc, out_root, stop_event=stop_event, limiter=limiter),
            attempts=config.limits.retry_max_attempts,
            label=f"provider export {acc.source_email}",
        )

    parallel_process_accounts("provider-export", worker, config.accounts, max_workers, stop_on_error=not ignore_errors)


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
    desired_lower = desired_name.lower()
    desired_key = _target_mailbox_lookup_key(desired, provider)
    gmail_special_desired = {"archive", "sent", "drafts", "deleted messages", "trash", "junk", "spam", "important", "starred"}
    if desired_key in by_name and not (provider == "gmail" and desired_lower in gmail_special_desired):
        return by_name[desired_key].name
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
    }
    special_key = special_key_by_name.get(desired_name)
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
    filtered: List[str] = []
    unsupported: List[str] = []
    wildcard = permanent_flags is not None and "\\*" in permanent_flags
    for token in tokens:
        token = token.strip()
        upper = token.upper()
        if upper == "\\RECENT":
            continue
        if target_provider == "gmail" and upper == "\\DELETED":
            continue
        if upper in portable:
            if permanent_flags is None or upper in permanent_flags:
                filtered.append(token)
            else:
                unsupported.append(token)
            continue
        if not token.startswith("\\") or (permanent_flags is not None and upper in permanent_flags):
            if wildcard or upper in (permanent_flags or set()):
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
    return {
        token.upper()
        for token in _provider_flag_tokens(
            flags,
            target_provider=target_provider,
            permanent_flags=permanent_flags,
        )
    }


def target_message_flag_set(imap: imaplib.IMAP4, num: bytes) -> set[str]:
    status, fetched = imap.fetch(num, "(FLAGS)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch target flags for message {num!r}")
    parsed = parse_provider_fetch_response(fetched or [])
    return {token.upper() for token in str(parsed.get("flags") or "").split()}


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
        return value if value.startswith('"') and value.endswith('"') else f'"{value}"'
    return imaplib.Time2Internaldate(time.time())


def _quote_gmail_label(label: str) -> str:
    if label.startswith("\\"):
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
    status, response = imap.store(num, "+X-GM-LABELS", label_list)
    if status != "OK":
        raise RuntimeError(f"failed to restore Gmail labels for {row.get('canonical_id')}: {response}")


def restore_gmail_starred_flag(imap: imaplib.IMAP4, target_mailbox: str, row: Dict[str, Any], *, target_num: Optional[bytes] = None) -> None:
    if not row_has_gmail_starred(row):
        return
    num = target_num or _first_target_match_num(imap, target_mailbox, row)
    status, _ = select_mailbox(imap, target_mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select target mailbox {target_mailbox!r} to restore Gmail starred flag")
    status, response = imap.store(num, "+FLAGS", "(\\Flagged)")
    if status != "OK":
        raise RuntimeError(f"failed to restore Gmail starred flag for {row.get('canonical_id')}: {response}")


def target_matching_message_nums(imap: imaplib.IMAP4, mailbox: str, manifest_row: Dict[str, Any], *, create_if_missing: bool = True) -> List[bytes]:
    message_id = str(manifest_row.get("message_id_header") or "").strip()
    if create_if_missing:
        ensure_mailbox(imap, mailbox)
    status, _ = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        return []
    if message_id:
        status, data = imap.search(None, "HEADER", "Message-ID", message_id)
    else:
        status, data = imap.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        return []
    expected_size = int(manifest_row.get("rfc822_size") or 0)
    expected_hash = str(manifest_row.get("content_sha256") or "")
    if expected_size <= 0 and not expected_hash and message_id:
        return list(data[0].split())
    matches: List[bytes] = []
    for num in data[0].split():
        status, fetched = imap.fetch(num, "(RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            continue
        for part in fetched or []:
            raw = part[0] if isinstance(part, tuple) else part
            if not isinstance(raw, (bytes, bytearray)):
                continue
            match = re.search(rb"RFC822\.SIZE\s+(\d+)", bytes(raw), flags=re.IGNORECASE)
            if expected_size > 0 and match and int(match.group(1)) != expected_size:
                continue
            if expected_hash and isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
                if hashlib.sha256(bytes(part[1])).hexdigest() == expected_hash:
                    matches.append(num)
                    break
                continue
            if match and not expected_hash:
                matches.append(num)
                break
    return matches


def target_has_message(imap: imaplib.IMAP4, mailbox: str, manifest_row: Dict[str, Any], *, create_if_missing: bool = True) -> bool:
    return bool(target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing))


def _target_gmail_msgid(imap: imaplib.IMAP4, num: bytes) -> str:
    status, fetched = imap.fetch(num, "(X-GM-MSGID)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch Gmail message id for target message {num!r}")
    parsed = parse_provider_fetch_response(fetched or [])
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
) -> Optional[bytes]:
    mailbox_key = _target_mailbox_lookup_key(mailbox)
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing):
        if num not in used:
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
) -> Optional[bytes]:
    if not target_gmail_msgid:
        return None
    mailbox_key = _target_mailbox_lookup_key(mailbox, "gmail")
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing):
        if num in used:
            continue
        gmail_msgid = _target_gmail_msgid(imap, num)
        if gmail_msgid != target_gmail_msgid:
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
) -> Optional[Tuple[str, bytes, str]]:
    for mailbox in mailboxes:
        mailbox_key = _target_mailbox_lookup_key(mailbox, "gmail")
        used = used_by_mailbox.setdefault(mailbox_key, set())
        for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=False):
            if num in used:
                continue
            gmail_msgid = _target_gmail_msgid(imap, num)
            if target_gmail_msgid and gmail_msgid != target_gmail_msgid:
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
) -> bool:
    return consume_target_match_num(
        imap,
        mailbox,
        manifest_row,
        used_by_mailbox,
        create_if_missing=create_if_missing,
        used_gmail_msgids=used_gmail_msgids,
    ) is not None


def _target_gmail_label_keys(imap: imaplib.IMAP4, num: bytes) -> set[str]:
    status, fetched = imap.fetch(num, "(X-GM-LABELS FLAGS)")
    if status != "OK":
        raise RuntimeError(f"failed to fetch Gmail labels for target message {num!r}")
    parsed = parse_provider_fetch_response(fetched or [])
    labels = {_gmail_label_key(str(label)) for label in (parsed.get("gmail_labels") or [])}
    labels.update(_gmail_label_key(token) for token in str(parsed.get("flags") or "").split())
    return {label for label in labels if label}


def consume_target_match_with_gmail_labels(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
    used_gmail_msgids: Optional[set[str]] = None,
) -> Optional[set[str]]:
    mailbox_key = _target_mailbox_lookup_key(mailbox)
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing):
        if num in used:
            continue
        if used_gmail_msgids is not None:
            gmail_msgid = _target_gmail_msgid(imap, num)
            if gmail_msgid and gmail_msgid in used_gmail_msgids:
                continue
            if gmail_msgid:
                used_gmail_msgids.add(gmail_msgid)
        used.add(num)
        return _target_gmail_label_keys(imap, num)
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
) -> set[str]:
    gmail_msgids: set[str] = set()
    used_by_mailbox: Dict[str, set[bytes]] = {}
    for mailbox in mailboxes:
        for num in target_matching_message_nums(imap, mailbox, row, create_if_missing=False):
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
) -> Optional[set[str]]:
    used_by_mailbox: Dict[str, set[bytes]] = {}
    for mailbox in mailboxes:
        for num in target_matching_message_nums(imap, mailbox, row, create_if_missing=False):
            used = used_by_mailbox.setdefault(_target_mailbox_lookup_key(mailbox, "gmail"), set())
            if num in used:
                continue
            used.add(num)
            if _target_gmail_msgid(imap, num) == target_gmail_msgid:
                return _target_gmail_label_keys(imap, num)
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
    flags = {token.lower() for token in str(row.get("flags") or "").split()}
    labels = {str(label).lower() for label in (row.get("gmail_labels") or [])}
    wanted: set[str] = set()
    if "\\flagged" in flags or "\\starred" in labels or "\\flagged" in labels:
        wanted.update({"\\flagged", "\\starred", "starred", "[gmail]/starred", "[googlemail]/starred"})
    if "\\important" in labels or "important" in labels or "\\important" in flags:
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
        key = (identity, target_mailbox)
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
        count = target_message_count(imap, mailbox.name)
        if count <= 0:
            continue
        verified = 0
        used: Dict[str, set[bytes]] = {}
        mailbox_key = _target_mailbox_lookup_key(mailbox.name, target_provider)
        for permitted_row, journal_key in permitted_by_mailbox.get(mailbox_key, []):
            target_gmail_msgid = gmail_journal_msgids.get(journal_key, "") if target_provider == "gmail" else ""
            if target_gmail_msgid:
                matched = consume_target_gmail_msgid_match_num(
                    imap,
                    mailbox.name,
                    permitted_row,
                    target_gmail_msgid,
                    used,
                    create_if_missing=False,
                )
                if matched is not None:
                    verified += 1
                continue
            if consume_target_match(imap, mailbox.name, permitted_row, used, create_if_missing=False):
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
) -> Tuple[Path, List[Dict[str, Any]], List[Dict[str, Any]]]:
    if account is current_account or account.source_email == current_account.source_email:
        account_dir = account_export_dir(in_root, current_account)
        return account_dir, current_manifest_rows, current_journal_rows
    account_dir = account_export_dir(in_root, account)
    manifest_rows = load_manifest(account_dir)
    require_unique_manifest_identities(manifest_rows)
    require_manifest_accounts(manifest_rows, account)
    require_manifest_source_provider(manifest_rows, config.source.provider)
    require_manifest_integrity_metadata(manifest_rows)
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
    journal_rows = load_import_journal(account_dir, account)
    require_valid_import_journal(journal_rows, account)
    journal_target_issues = journal_target_endpoint_issues(journal_rows, config=config, account=account)
    if journal_target_issues:
        raise RuntimeError(
            f"invalid import journal for merge source {account.source_email}: "
            + "; ".join(journal_target_issues)
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
        )
        stages.append((group_account, account_dir, manifest_rows, journal_rows))
    return stages


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


def merge_group_empty_target_context(
    config: ProviderMigrationConfig,
    target_mailboxes: List[MailboxInfo],
    stages: List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]],
) -> Tuple[List[Dict[str, Any]], set[Tuple[str, str]], Dict[Tuple[str, str], str]]:
    permitted_rows: List[Dict[str, Any]] = []
    permitted_keys: set[Tuple[str, str]] = set()
    gmail_journal_msgids: Dict[Tuple[str, str], str] = {}
    for _group_account, _account_dir, manifest_rows, journal_rows in stages:
        latest_committed = latest_committed_journal_rows(journal_rows)
        journaled = set(latest_committed)
        if config.target.provider == "gmail":
            for key, journal_row in latest_committed.items():
                target_gmail_msgid = str(journal_row.get("target_gmail_msgid") or "")
                if target_gmail_msgid:
                    gmail_journal_msgids[key] = target_gmail_msgid
        journaled.update(
            (str(row.get("canonical_id")), str(row.get("target_mailbox")))
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
            key = (identity, target_mailbox)
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
    account_dir = account_export_dir(in_root, account)
    manifest_rows = load_manifest(account_dir)
    require_unique_manifest_identities(manifest_rows)
    require_manifest_accounts(manifest_rows, account)
    require_manifest_source_provider(manifest_rows, config.source.provider)
    require_manifest_integrity_metadata(manifest_rows)
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
    for row in manifest_rows:
        identity = str(row.get("canonical_id") or "")
        eml_path = _manifest_path(account_dir, row, "eml_path")
        if not eml_path.exists():
            raise RuntimeError(f"message file missing for {identity}: {eml_path}")
        data = eml_path.read_bytes()
        require_manifest_payload_matches(row, data)
        payloads_by_identity[identity] = data
    journal_rows = load_import_journal(account_dir, account, repair_trailing=True)
    require_valid_import_journal(journal_rows, account)
    journal_target_issues = journal_target_endpoint_issues(journal_rows, config=config, account=account)
    if journal_target_issues:
        raise RuntimeError("invalid import journal: " + "; ".join(journal_target_issues))
    manifest_ids = {str(row.get("canonical_id") or "") for row in manifest_rows if row.get("canonical_id")}
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
    pending = {
        (str(row.get("canonical_id")), str(row.get("target_mailbox")))
        for row in journal_rows
        if row.get("status") == "pending"
    }
    limiter = limiter or RateLimiter(config.limits.throttle.max_bytes_per_second)
    used_target_nums: Dict[str, set[bytes]] = {}
    used_target_gmail_msgids: set[str] = set()
    target_binding = provider_target_journal_binding(config, account)

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
        merge_group_stages: Optional[List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]]] = None
        if provider_account_merge_enabled(config):
            merge_group_stages = validated_merge_group_stages(
                config,
                in_root,
                account,
                manifest_rows,
                journal_rows,
            )
            require_merge_group_target_translation_safe(
                merge_group_stages,
                target_mailboxes,
                target_provider=config.target.provider,
            )
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=config.target.provider,
        )
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
            )
            repaired_journal_issues = []
            repaired_journal_issues.extend(
                missing_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                )
            )
            repaired_journal_issues.extend(
                duplicate_journal_target_gmail_msgid_issues(
                    journal_rows,
                    manifest_ids=manifest_ids,
                )
            )
            if repaired_journal_issues:
                raise RuntimeError("invalid import journal: " + "; ".join(repaired_journal_issues))
        latest_committed = latest_committed_journal_rows(journal_rows)
        committed = set(latest_committed)
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
            key = (identity, target_mailbox)
            data = payloads_by_identity[identity]
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
                    )
                    if matched is not None:
                        matched_mailbox, matched_num, matched_gmail_msgid = matched
                else:
                    matched_num = consume_target_match_num(
                        imap,
                        target_mailbox,
                        row,
                        used_target_nums,
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
            limiter.wait_for(len(data))
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
                raise RuntimeError(f"append failed for {identity}: {response}")
            appended_num = consume_target_match_num(
                imap,
                target_mailbox,
                row,
                used_target_nums,
                create_if_missing=False,
                used_gmail_msgids=used_target_gmail_msgids if config.target.provider == "gmail" else None,
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
    limiter = RateLimiter(config.limits.throttle.max_bytes_per_second)

    def worker(acc: MigrationAccount) -> None:
        _raise_if_stopped(stop_event, f"provider import {acc.target_email}")
        with_retry(
            lambda: provider_import_account(config, acc, in_root, stop_event=stop_event, limiter=limiter),
            attempts=config.limits.retry_max_attempts,
            label=f"provider import {acc.target_email}",
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

    parallel_process_accounts("provider-import", worker, config.accounts, max_workers, stop_on_error=not ignore_errors)


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
        "rfc822_size": int(row.get("rfc822_size") or 0),
        "timestamp": _utc_now(),
    }
    if target_gmail_msgid:
        journal_row["target_gmail_msgid"] = target_gmail_msgid
    return journal_row


def provider_audit_account(config: ProviderMigrationConfig, account: MigrationAccount, in_root: Path) -> Tuple[str, List[str]]:
    issues: List[str] = []
    account_dir = account_export_dir(in_root, account)
    if not account_dir.exists():
        return account.email, [f"account export directory missing: {account_dir}"]
    try:
        rows = load_manifest(account_dir)
    except Exception as exc:
        return account.email, [f"manifest load failed: {exc}"]
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
    issues.extend(manifest_account_issues(rows, account))
    issues.extend(manifest_source_provider_issues(rows, config.source.provider))
    issues.extend(manifest_integrity_issues(rows))
    issues.extend(metadata_manifest_issues(account_dir, rows, require_present=False))
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
        if not row.get("primary_mailbox"):
            issues.append(f"{identity}: missing primary_mailbox")
        eml_rel = row.get("eml_path")
        eml_path: Optional[Path] = None
        with contextlib.suppress(Exception):
            eml_path = _manifest_path(account_dir, row, "eml_path")
        if eml_rel and eml_path is not None and eml_path.exists():
            try:
                data = eml_path.read_bytes()
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


def provider_audit_all(config: ProviderMigrationConfig, in_root: Path, *, max_workers: int) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> List[str]:
        _name, account_issues = provider_audit_account(config, acc, in_root)
        return [f"{acc.email}: {issue}" for issue in account_issues]

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="provider-audit") as ex:
        for result in ex.map(worker, config.accounts):
            issues.extend(result)
    return len(issues) == 0, issues


def provider_validate_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    in_root: Path,
    *,
    check_target: bool = False,
) -> Tuple[str, Dict[str, Any]]:
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
        journal_rows = load_import_journal(account_dir, account)
        manifest_rows = load_manifest(account_dir)
    except Exception as exc:
        report["failed"].append(str(exc))
        return account.email, report

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
    report["failed"].extend(manifest_source_provider_issues(manifest_rows, config.source.provider))
    report["failed"].extend(manifest_integrity_issues(manifest_rows))
    report["failed"].extend(metadata_manifest_issues(account_dir, manifest_rows))
    report["failed"].extend(gmail_target_decommission_issues(config.target, account))

    journal_issues = journal_row_issues(journal_rows, account)
    report["failed"].extend(journal_issues)
    report["failed"].extend(journal_target_endpoint_issues(journal_rows, config=config, account=account))
    committed_journal_keys = set(latest_committed_journal_rows(journal_rows))
    for row in journal_rows:
        if row.get("status") != "pending":
            continue
        identity = str(row.get("canonical_id") or "")
        target_mailbox = str(row.get("target_mailbox") or "")
        if (identity, target_mailbox) not in committed_journal_keys:
            report["failed"].append(
                f"journal pending identity has no committed resolution: {identity or '<missing>'} in {target_mailbox or '<missing>'}"
            )

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
    journal_gmail_msgid_missing = (
        missing_journal_target_gmail_msgid_issues(journal_rows, manifest_ids=manifest_ids)
        if config.target.provider == "gmail"
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

    def evaluate_journal(expected_target_by_id: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, int], Dict[str, str], List[str]]:
        committed_by_id: Dict[str, int] = {}
        target_by_id: Dict[str, str] = {}
        failures: List[str] = []
        effective_committed = latest_committed_journal_rows(journal_rows)
        for row in effective_committed.values():
            identity = str(row.get("canonical_id") or "")
            if not identity:
                failures.append("journal committed row missing canonical_id")
                continue
            if identity not in manifest_ids:
                failures.append(f"journal committed identity not in manifest: {identity}")
                continue
            target_mailbox = str(row.get("target_mailbox") or "")
            expected_target = expected_target_by_id.get(identity) if expected_target_by_id else None
            if expected_target and target_mailbox != expected_target:
                failures.append(
                    f"journal committed identity in wrong target mailbox: {identity} "
                    f"expected {expected_target!r} got {target_mailbox!r}"
                )
                continue
            committed_by_id[identity] = committed_by_id.get(identity, 0) + 1
            if target_mailbox:
                target_by_id[identity] = target_mailbox
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

    if check_target:
        try:
            with imap_connection(config.target, account, role="target") as imap:
                capabilities: List[str] = []
                if config.target.provider == "gmail":
                    capabilities = get_capabilities(imap)
                    if "X-GM-EXT-1" not in capabilities:
                        raise RuntimeError("target Gmail IMAP server did not advertise X-GM-EXT-1")
                target_mailboxes = list_mailboxes(imap)
                merge_group_stages: Optional[List[Tuple[MigrationAccount, Path, List[Dict[str, Any]], List[Dict[str, Any]]]]] = None
                if provider_account_merge_enabled(config):
                    merge_group_stages = validated_merge_group_stages(
                        config,
                        in_root,
                        account,
                        manifest_rows,
                        journal_rows,
                    )
                    require_merge_group_target_translation_safe(
                        merge_group_stages,
                        target_mailboxes,
                        target_provider=config.target.provider,
                    )
                target_mailbox_by_identity = translated_target_mailboxes_for_rows(
                    manifest_rows,
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
                if config.target.provider == "gmail":
                    report["failed"].extend(gmail_target_system_mailbox_issues(manifest_rows, target_mailboxes))
                expected_target_by_id = {
                    identity: target_mailbox_by_identity[identity]
                    for identity, row in by_id.items()
                }
                committed_by_id, target_by_id, failures = evaluate_journal(expected_target_by_id)
                report["failed"].extend(failures)
                apply_counts(committed_by_id)
                if config.target.provider == "gmail":
                    target_readiness_issues = gmail_target_readiness_issues(capabilities, target_mailboxes)
                    target_readiness_issues.extend(gmail_all_mail_select_issues(imap, target_mailboxes, role="target"))
                    if target_readiness_issues:
                        raise RuntimeError("; ".join(target_readiness_issues))
                if config.migration.target_mode == "empty":
                    empty_target_rows = manifest_rows
                    effective_committed_rows = latest_committed_journal_rows(journal_rows)
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
                        )
                    except Exception as exc:
                        report["failed"].append(f"remote target validation failed: {exc}")
                if not report["missing"]:
                    used_target_nums: Dict[str, set[bytes]] = {}
                    used_target_gmail_msgids: set[str] = set()
                    effective_committed_rows = latest_committed_journal_rows(journal_rows)
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
                        target_mailbox = target_by_id.get(identity)
                        if not target_mailbox:
                            continue
                        report["remote_checked"] += 1
                        if config.target.provider == "gmail":
                            expected_mailboxes = gmail_expected_target_mailboxes_for_row(
                                row,
                                target_mailbox,
                                target_mailboxes,
                            )
                            matching_gmail_msgids = matching_gmail_msgids_for_row(imap, row, expected_mailboxes)
                            journal_target_gmail_msgid = target_gmail_msgid_by_id.get(identity, "")
                            primary_actual_labels: Optional[set[str]] = None
                            if journal_target_gmail_msgid:
                                if journal_target_gmail_msgid not in matching_gmail_msgids:
                                    report["remote_missing"].append(identity)
                                    continue
                                primary_actual_labels = target_gmail_labels_for_msgid(
                                    imap,
                                    row,
                                    [target_mailbox],
                                    journal_target_gmail_msgid,
                                )
                                if primary_actual_labels is None:
                                    report["remote_missing"].append(identity)
                                    continue
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
                            else:
                                actual_labels = consume_target_match_with_gmail_labels(
                                    imap,
                                    target_mailbox,
                                    row,
                                    used_target_nums,
                                    create_if_missing=False,
                                    used_gmail_msgids=used_target_gmail_msgids,
                                )
                            if actual_labels is None:
                                report["remote_missing"].append(identity)
                                continue
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
                        else:
                            target_num = consume_target_match_num(
                                imap,
                                target_mailbox,
                                row,
                                used_target_nums,
                                create_if_missing=False,
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
                            except Exception as exc:
                                report["failed"].append(f"target IMAP flag validation failed for {identity}: {exc}")
                                continue
                            missing_flags = sorted(required_flags - actual_flags)
                            if missing_flags:
                                report["failed"].append(
                                    f"target IMAP flags missing for {identity} in {target_mailbox}: "
                                    + ", ".join(missing_flags)
                                )
        except Exception as exc:
            committed_by_id, _target_by_id, failures = evaluate_journal()
            report["failed"].extend(failures)
            apply_counts(committed_by_id)
            report["failed"].append(f"remote target validation failed: {exc}")
    else:
        committed_by_id, _target_by_id, failures = evaluate_journal()
        report["failed"].extend(failures)
        apply_counts(committed_by_id)

    report["ok"] = not report["missing"] and not report["duplicates"] and not report["failed"]
    if report["remote_missing"]:
        report["ok"] = False
    _atomic_json(account_dir / f"validation-{sanitize_for_path(account.target_email)}.json", report)
    return account.email, report


def provider_validate_all(config: ProviderMigrationConfig, in_root: Path, *, max_workers: int) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> Dict[str, Any]:
        _name, report = provider_validate_account(config, acc, in_root, check_target=True)
        return report

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="provider-validate") as ex:
        for report in ex.map(worker, config.accounts):
            if report.get("ok"):
                logging.info("[provider-validate] %s: OK exported=%s committed=%s", report["account"], report["exported"], report["committed"])
                continue
            prefix = str(report.get("account"))
            for key in ("missing", "duplicates", "remote_missing", "failed"):
                for item in report.get(key, []):
                    issues.append(f"{prefix}: {key}: {item}")
    return len(issues) == 0, issues


def provider_test_accounts(config: ProviderMigrationConfig, *, max_workers: int, roles: Tuple[str, ...] = ("source", "target")) -> None:
    max_workers = _require_max_workers(max_workers)

    def worker(acc: MigrationAccount) -> None:
        if "source" in roles:
            with imap_connection(config.source, acc, role="source"):
                pass
        if "target" in roles:
            with imap_connection(config.target, acc, role="target"):
                pass
        logging.info("[provider-test] %s: OK", acc.email)

    parallel_process_accounts("provider-test", worker, config.accounts, max_workers, stop_on_error=True)


def provider_preflight(config: ProviderMigrationConfig, *, max_workers: int) -> Tuple[bool, List[str]]:
    max_workers = _require_max_workers(max_workers)
    issues: List[str] = []

    def worker(acc: MigrationAccount) -> Tuple[List[str], int]:
        account_issues: List[str] = []
        source_total = 0
        seen_identity: set[str] = set()
        try:
            with imap_connection(config.source, acc, role="source") as source_imap:
                capabilities = get_capabilities(source_imap)
                gmail_extensions = "X-GM-EXT-1" in capabilities
                source_mailboxes = list_mailboxes(source_imap)
                if config.source.provider == "gmail":
                    account_issues.extend(gmail_source_readiness_issues(capabilities, source_mailboxes))
                    account_issues.extend(gmail_all_mail_select_issues(source_imap, source_mailboxes, role="source"))
                    account_issues.extend(gmail_account_decommission_issues(config.source, acc))
                for mailbox in source_mailboxes:
                    if is_noselect(mailbox) or is_virtual_source_mailbox(config.source.provider, mailbox):
                        continue
                    try:
                        uids, _uidvalidity = fetch_all_uids_and_uidvalidity(source_imap, mailbox.name)
                    except Exception as exc:
                        account_issues.append(f"source mailbox {mailbox.name} scan failed: {exc}")
                        continue
                    for uid in uids:
                        status, data = source_imap.uid("fetch", str(uid), fetch_items(include_body=False, gmail_extensions=gmail_extensions))
                        if status != "OK":
                            account_issues.append(f"metadata fetch failed in {mailbox.name} for UID {uid}")
                            continue
                        parsed = parse_provider_fetch_response(data or [])
                        identity = str(parsed.get("gmail_msgid") or f"{mailbox.name}:{uid}")
                        if identity in seen_identity:
                            continue
                        seen_identity.add(identity)
                        source_total += int(parsed.get("rfc822_size") or 0)
        except Exception as exc:
            account_issues.append(f"source preflight failed: {exc}")
        try:
            with imap_connection(config.target, acc, role="target") as target_imap:
                target_capabilities = get_capabilities(target_imap)
                target_mailboxes = list_mailboxes(target_imap)
                if config.target.provider == "gmail":
                    account_issues.extend(gmail_target_readiness_issues(target_capabilities, target_mailboxes))
                    account_issues.extend(gmail_all_mail_select_issues(target_imap, target_mailboxes, role="target"))
                    account_issues.extend(gmail_target_decommission_issues(config.target, acc))
                if not target_mailboxes:
                    account_issues.append("target returned no mailboxes")
        except Exception as exc:
            account_issues.append(f"target preflight failed: {exc}")
        if config.target.available_bytes is None:
            logging.warning("[provider-preflight] %s: target.available_bytes not configured; storage gate skipped", acc.email)
        elif not provider_account_merge_enabled(config) and source_total > config.target.available_bytes:
            account_issues.append(f"estimated source bytes {source_total} exceed target.available_bytes {config.target.available_bytes}")
        logging.info("[provider-preflight] %s: estimated_source_bytes=%d", acc.email, source_total)
        return account_issues, source_total

    import concurrent.futures

    merge_group_source_totals: Dict[Tuple[str, str], int] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="provider-preflight") as ex:
        for acc, (result, source_total) in zip(config.accounts, ex.map(worker, config.accounts)):
            issues.extend(f"{acc.email}: {issue}" for issue in result)
            if provider_account_merge_enabled(config) and config.target.available_bytes is not None:
                target_key = target_merge_group_key(config, acc)
                merge_group_source_totals[target_key] = merge_group_source_totals.get(target_key, 0) + source_total
    if provider_account_merge_enabled(config) and config.target.available_bytes is not None:
        for target_key, source_total in sorted(merge_group_source_totals.items()):
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
