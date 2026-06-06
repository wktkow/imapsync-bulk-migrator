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
from .models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
from .utils import decode_imap_utf7, encode_imap_utf7, sanitize_for_path


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


@contextlib.contextmanager
def imap_connection(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> Iterator[imaplib.IMAP4]:
    if endpoint.ssl:
        imap = imaplib.IMAP4_SSL(host=endpoint.host, port=endpoint.port, ssl_context=ssl.create_default_context())
    else:
        imap = imaplib.IMAP4(host=endpoint.host, port=endpoint.port)
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
    attr_lowers = {attr.lower() for attr in mailbox.attributes}
    if provider_key == "gmail":
        return False
    if provider_key == "icloud" and mailbox.name.lower() == "vip":
        return True
    return bool(attr_lowers & {"\\all", "\\flagged"})


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


def gmail_source_readiness_issues(capabilities: List[str], mailboxes: List[MailboxInfo]) -> List[str]:
    issues: List[str] = []
    if "X-GM-EXT-1" not in capabilities:
        issues.append("Gmail source did not advertise X-GM-EXT-1")
    if not any(
        any(attr.lower() == "\\all" for attr in mailbox.attributes)
        or mailbox.name.lower() in {"[gmail]/all mail", "[googlemail]/all mail", "all mail"}
        for mailbox in mailboxes
    ):
        issues.append(
            "Gmail source All Mail is not visible via IMAP; enable All Mail/labels for IMAP or use OAuth/admin scope that exposes all mail before decommissioning"
        )
    return issues


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


def _parse_parenthesized_words(raw: str) -> List[str]:
    words: List[str] = []
    for match in re.finditer(r'"((?:\\.|[^"])*)"|(\S+)', raw):
        quoted, atom = match.groups()
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
    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            meta, body = part
            meta_text = ""
            if isinstance(meta, (bytes, bytearray)):
                meta_text = bytes(meta).decode(errors="ignore")
                meta_chunks.append(meta_text)
            if (
                isinstance(body, (bytes, bytearray))
                and body
                and re.search(r"(?:BODY(?:\.PEEK)?\[\]|(?<![\w.])RFC822(?![\w.]))", meta_text, flags=re.IGNORECASE)
            ):
                msg_bytes = bytes(body) if msg_bytes is None else msg_bytes + bytes(body)
            elif (
                isinstance(body, (bytes, bytearray))
                and body
                and re.search(r"\bX-GM-LABELS\b[^\r\n]*\{\d+\}", meta_text, flags=re.IGNORECASE)
            ):
                label = decode_imap_utf7(bytes(body).decode("ascii", errors="ignore").strip())
                if label:
                    literal_labels.append(label)
        elif isinstance(part, (bytes, bytearray)):
            meta_chunks.append(bytes(part).decode(errors="ignore"))
    meta_str = " ".join(meta_chunks)

    def group(pattern: str) -> Optional[str]:
        match = re.search(pattern, meta_str, flags=re.IGNORECASE)
        return match.group(1) if match else None

    size_raw = group(r"RFC822\.SIZE\s+(\d+)")
    labels_raw = _extract_parenthesized_after(meta_str, "X-GM-LABELS")
    labels = _parse_parenthesized_words(labels_raw or "")
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


def resolve_primary_mailbox(source_mailboxes: Iterable[str], gmail_labels: Iterable[str], folder_map: Dict[str, str]) -> str:
    source_tokens = [str(value) for value in source_mailboxes if value]
    label_tokens = [str(value) for value in gmail_labels if value]
    tokens = _source_tokens(source_tokens, label_tokens)
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
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    tmp.replace(path)


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(payload)
    tmp.replace(path)


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for row in rows:
            json.dump(row, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    tmp.replace(path)


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


def provider_export_state_issues(
    account_dir: Path,
    *,
    account: Optional[MigrationAccount] = None,
    manifest_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[str]:
    state_path = account_dir / "export-state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"export-state missing or invalid: {exc}"]
    issues: List[str] = []
    if not isinstance(state, dict) or state.get("complete") is not True:
        issues.append(f"export-state is not complete: {state_path}")
        return issues
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
    if manifest_rows is not None:
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


def require_complete_export_state(
    account_dir: Path,
    *,
    account: Optional[MigrationAccount] = None,
    manifest_rows: Optional[List[Dict[str, Any]]] = None,
) -> None:
    issues = provider_export_state_issues(account_dir, account=account, manifest_rows=manifest_rows)
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


def journal_row_issues(rows: List[Dict[str, Any]], account: MigrationAccount) -> List[str]:
    issues: List[str] = []
    for idx, row in enumerate(rows, 1):
        status = str(row.get("status") or "")
        if status not in {"pending", "committed"}:
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


def require_valid_import_journal(rows: List[Dict[str, Any]], account: MigrationAccount) -> None:
    issues = journal_row_issues(rows, account)
    if issues:
        raise RuntimeError("invalid import journal: " + "; ".join(issues))


def _journal_path(account_dir: Path, account: MigrationAccount) -> Path:
    return account_dir / f"import-{sanitize_for_path(account.target_email)}.journal.jsonl"


def load_import_journal(account_dir: Path, account: MigrationAccount) -> List[Dict[str, Any]]:
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
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            if line_no == len(lines):
                logging.warning("[provider-import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise
    if needs_rewrite:
        _write_jsonl(path, rows)
    return rows


def append_journal(account_dir: Path, account: MigrationAccount, row: Dict[str, Any]) -> None:
    path = _journal_path(account_dir, account)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        json.dump(row, f, ensure_ascii=False, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


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
    )


def persist_export_records(account_dir: Path, records: Dict[str, Dict[str, Any]], folder_map: Dict[str, str]) -> None:
    for record in records.values():
        _finalize_export_record(record, folder_map)
        _atomic_json(account_dir / str(record["metadata_path"]), record)
    _write_jsonl(account_dir / "manifest.jsonl", sorted(records.values(), key=lambda row: str(row["canonical_id"])))


def provider_export_account(
    config: ProviderMigrationConfig,
    account: MigrationAccount,
    out_root: Path,
    *,
    stop_event: Optional[object] = None,
    limiter: Optional[RateLimiter] = None,
) -> None:
    account_dir = account_export_dir(out_root, account)
    _atomic_json(
        account_dir / "export-state.json",
        {
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": False,
            "started_at": _utc_now(),
        },
    )
    messages: Dict[str, Dict[str, Any]] = {}
    manifest_path = account_dir / "manifest.jsonl"
    if manifest_path.exists():
        existing_rows = load_manifest(account_dir)
        require_unique_manifest_identities(existing_rows)
        require_manifest_accounts(existing_rows, account)
        for row in existing_rows:
            _manifest_path(account_dir, row, "eml_path")
            _manifest_path(account_dir, row, "metadata_path")
        messages = {
            str(row["canonical_id"]): row
            for row in existing_rows
            if row.get("canonical_id")
        }
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
            if gmail_issues:
                raise RuntimeError(f"Gmail source is not export-ready for {account.source_email}: {'; '.join(gmail_issues)}")
        for mailbox in mailboxes:
            if is_noselect(mailbox):
                logging.info("[provider-export] %s: skipping non-selectable mailbox %s", account.source_email, mailbox.name)
                continue
            if is_virtual_source_mailbox(config.source.provider, mailbox):
                logging.info("[provider-export] %s: skipping virtual source mailbox %s", account.source_email, mailbox.name)
                continue
            _raise_if_stopped(stop_event, f"provider export {account.source_email}")
            uids, uidvalidity = fetch_all_uids_and_uidvalidity(imap, mailbox.name)
            previous_uidvalidities = {
                str((row.get("uidvalidity_by_mailbox") or {}).get(mailbox.name) or "")
                for row in messages.values()
                if isinstance(row.get("uidvalidity_by_mailbox"), dict)
                and (row.get("uidvalidity_by_mailbox") or {}).get(mailbox.name)
            }
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
                            persist_export_records(account_dir, messages, config.migration.folder_map)
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
                persist_export_records(account_dir, messages, config.migration.folder_map)
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

    persist_export_records(account_dir, messages, config.migration.folder_map)
    final_manifest_rows = load_manifest(account_dir)
    _atomic_json(
        account_dir / "export-state.json",
        {
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": True,
            "canonical_messages": len(final_manifest_rows),
            "manifest_sha256": provider_manifest_digest(final_manifest_rows),
            "completed_at": _utc_now(),
        },
    )
    logging.info("[provider-export] %s: completed with %d canonical messages", account.source_email, len(messages))


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


def _target_mailboxes_by_name(mailboxes: List[MailboxInfo]) -> Dict[str, MailboxInfo]:
    return {m.name.lower(): m for m in mailboxes}


def resolve_target_mailbox(desired: str, mailboxes: List[MailboxInfo], *, target_provider: str = "imap") -> str:
    by_name = _target_mailboxes_by_name(mailboxes)
    desired_lower = desired.lower()
    provider = (target_provider or "imap").lower()
    gmail_special_desired = {"archive", "sent", "drafts", "deleted messages", "trash", "junk", "spam", "important", "starred"}
    if desired_lower in by_name and not (provider == "gmail" and desired_lower in gmail_special_desired):
        return by_name[desired.lower()].name
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
    attrs = attr_map.get(desired_lower)
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
    }.get(desired_lower, [desired])
    for candidate in candidates:
        if candidate.lower() in by_name:
            return by_name[candidate.lower()].name
    return desired


def ensure_mailbox(imap: imaplib.IMAP4, mailbox: str) -> None:
    status, _ = select_mailbox(imap, mailbox)
    if status == "OK":
        return
    try:
        create_mailbox(imap, mailbox)
    except Exception as exc:
        logging.warning("[provider-import] failed to create target mailbox %s: %s", mailbox, exc)
    status, _ = select_mailbox(imap, mailbox)
    if status != "OK":
        raise RuntimeError(f"cannot select or create target mailbox {mailbox}")


def _flags_for_append(flags: str) -> str:
    portable = {"\\ANSWERED", "\\FLAGGED", "\\DELETED", "\\SEEN", "\\DRAFT"}
    tokens = [tok for tok in flags.split() if tok.strip()]
    filtered = [tok for tok in tokens if tok.strip().upper() in portable]
    return f"({' '.join(filtered)})" if filtered else ""


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


def _gmail_label_key(label: str) -> str:
    lower = str(label).strip().lower()
    if lower in {"\\important", "important", "[gmail]/important", "[googlemail]/important"}:
        return "important"
    if lower in {"\\starred", "\\flagged", "[gmail]/starred", "[googlemail]/starred"}:
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


def gmail_labels_for_restore(row: Dict[str, Any], target_mailbox: str) -> List[str]:
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
    for raw in row.get("gmail_labels") or []:
        label = str(raw).strip()
        lower = label.lower()
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


def restore_gmail_labels(imap: imaplib.IMAP4, target_mailbox: str, row: Dict[str, Any], *, target_num: Optional[bytes] = None) -> None:
    labels = gmail_labels_for_restore(row, target_mailbox)
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


def consume_target_match_num(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
) -> Optional[bytes]:
    mailbox_key = mailbox.lower()
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing):
        if num not in used:
            used.add(num)
            return num
    return None


def consume_target_match(
    imap: imaplib.IMAP4,
    mailbox: str,
    manifest_row: Dict[str, Any],
    used_by_mailbox: Dict[str, set[bytes]],
    *,
    create_if_missing: bool = True,
) -> bool:
    return consume_target_match_num(
        imap,
        mailbox,
        manifest_row,
        used_by_mailbox,
        create_if_missing=create_if_missing,
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
) -> Optional[set[str]]:
    mailbox_key = mailbox.lower()
    used = used_by_mailbox.setdefault(mailbox_key, set())
    for num in target_matching_message_nums(imap, mailbox, manifest_row, create_if_missing=create_if_missing):
        if num in used:
            continue
        used.add(num)
        return _target_gmail_label_keys(imap, num)
    return None


def target_message_count(imap: imaplib.IMAP4, mailbox: str) -> int:
    status, data = select_mailbox(imap, mailbox, readonly=True)
    if status != "OK":
        return 0
    status, data = imap.search(None, "ALL")
    if status != "OK" or not data:
        return 0
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


def enforce_empty_target(
    imap: imaplib.IMAP4,
    target_mailboxes: List[MailboxInfo],
    manifest_rows: List[Dict[str, Any]],
    journaled: set[Tuple[str, str]],
    *,
    target_provider: str = "imap",
) -> None:
    permitted_by_mailbox: Dict[str, List[Dict[str, Any]]] = {}
    by_name = _target_mailboxes_by_name(target_mailboxes)
    gmail_all_mailboxes = [
        mailbox.name
        for mailbox in target_mailboxes
        if target_provider == "gmail"
        and (
            any(attr.lower() == "\\all" for attr in mailbox.attributes)
            or mailbox.name.lower() in {"[gmail]/all mail", "[googlemail]/all mail", "all mail"}
        )
    ]
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
                for label in gmail_labels_for_restore(row, target_mailbox):
                    mailbox = by_name.get(label.lower())
                    if mailbox is not None:
                        permitted_names.append(mailbox.name)
            for name in permitted_names:
                permitted_by_mailbox.setdefault(name.lower(), []).append(row)
    for mailbox in target_mailboxes:
        if is_noselect(mailbox):
            continue
        count = target_message_count(imap, mailbox.name)
        if count <= 0:
            continue
        verified = 0
        used: Dict[str, set[bytes]] = {}
        for permitted_row in permitted_by_mailbox.get(mailbox.name.lower(), []):
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
        previous_source = translated_sources_by_target.setdefault(target_mailbox.lower(), source_key)
        if previous_source != source_key:
            raise RuntimeError(
                f"target mailbox translation collision for {target_mailbox!r}: "
                f"{previous_source!r} and {source_key!r}"
            )
        if identity:
            result[identity] = target_mailbox
    return result


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
    require_manifest_integrity_metadata(manifest_rows)
    require_complete_export_state(account_dir, account=account, manifest_rows=manifest_rows)
    journal_rows = load_import_journal(account_dir, account)
    require_valid_import_journal(journal_rows, account)
    committed = {
        (str(row.get("canonical_id")), str(row.get("target_mailbox")))
        for row in journal_rows
        if row.get("status") == "committed"
    }
    pending = {
        (str(row.get("canonical_id")), str(row.get("target_mailbox")))
        for row in journal_rows
        if row.get("status") == "pending"
    }
    limiter = limiter or RateLimiter(config.limits.throttle.max_bytes_per_second)
    used_target_nums: Dict[str, set[bytes]] = {}

    with imap_connection(config.target, account, role="target") as imap:
        target_mailboxes = list_mailboxes(imap)
        target_mailbox_by_identity = translated_target_mailboxes_for_rows(
            manifest_rows,
            target_mailboxes,
            target_provider=config.target.provider,
        )
        if config.migration.target_mode == "empty":
            enforce_empty_target(
                imap,
                target_mailboxes,
                manifest_rows,
                committed | pending,
                target_provider=config.target.provider,
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
            if key in committed:
                if config.migration.target_mode == "empty" and not consume_target_match(imap, target_mailbox, row, used_target_nums, create_if_missing=False):
                    raise RuntimeError(
                        f"journal says {identity} is committed to {target_mailbox!r}, "
                        "but the target message was not found"
                    )
                continue
            eml_path = _manifest_path(account_dir, row, "eml_path")
            if not eml_path.exists():
                raise RuntimeError(f"message file missing for {identity}: {eml_path}")
            matched_num = None
            if config.migration.target_mode == "merge" or key in pending:
                matched_num = consume_target_match_num(imap, target_mailbox, row, used_target_nums)
            if matched_num is not None:
                if config.target.provider == "gmail":
                    restore_gmail_labels(imap, target_mailbox, row, target_num=matched_num)
                    restore_gmail_starred_flag(imap, target_mailbox, row, target_num=matched_num)
                append_journal(account_dir, account, _journal_row(row, target_mailbox, "committed", "existing"))
                committed.add(key)
                continue
            ensure_mailbox(imap, target_mailbox)
            data = eml_path.read_bytes()
            require_manifest_payload_matches(row, data)
            limiter.wait_for(len(data))
            append_journal(account_dir, account, _journal_row(row, target_mailbox, "pending", "append-started"))
            status, response = append_message(
                imap,
                target_mailbox,
                _flags_for_append(str(row.get("flags") or "")),
                _internaldate_for_append(str(row.get("internaldate") or "")),
                data,
            )
            if status != "OK":
                raise RuntimeError(f"append failed for {identity}: {response}")
            appended_num = consume_target_match_num(imap, target_mailbox, row, used_target_nums, create_if_missing=False)
            if appended_num is None:
                raise RuntimeError(f"appended target message not found for {identity} in {target_mailbox!r}")
            if config.target.provider == "gmail":
                restore_gmail_labels(imap, target_mailbox, row, target_num=appended_num)
                restore_gmail_starred_flag(imap, target_mailbox, row, target_num=appended_num)
            append_journal(account_dir, account, _journal_row(row, target_mailbox, "committed", "appended"))
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

    parallel_process_accounts("provider-import", worker, config.accounts, max_workers, stop_on_error=not ignore_errors)


def _journal_row(row: Dict[str, Any], target_mailbox: str, status: str, action: str) -> Dict[str, Any]:
    return {
        "canonical_id": row.get("canonical_id"),
        "target_account": row.get("target_account"),
        "target_mailbox": target_mailbox,
        "status": status,
        "action": action,
        "flags": row.get("flags") or "",
        "internaldate": row.get("internaldate") or "",
        "rfc822_size": int(row.get("rfc822_size") or 0),
        "timestamp": _utc_now(),
    }


def provider_audit_account(config: ProviderMigrationConfig, account: MigrationAccount, in_root: Path) -> Tuple[str, List[str]]:
    issues: List[str] = []
    account_dir = account_export_dir(in_root, account)
    if not account_dir.exists():
        return account.email, [f"account export directory missing: {account_dir}"]
    try:
        rows = load_manifest(account_dir)
    except Exception as exc:
        return account.email, [f"manifest load failed: {exc}"]
    issues.extend(provider_export_state_issues(account_dir, account=account, manifest_rows=rows))
    identities = set()
    issues.extend(manifest_account_issues(rows, account))
    issues.extend(manifest_integrity_issues(rows))
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
        meta_rel = row.get("metadata_path")
        meta_path: Optional[Path] = None
        with contextlib.suppress(Exception):
            meta_path = _manifest_path(account_dir, row, "metadata_path")
        if meta_rel and meta_path is not None and meta_path.exists():
            try:
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
                for key in ("canonical_id", "content_sha256", "rfc822_size", "primary_mailbox"):
                    if metadata.get(key) != row.get(key):
                        issues.append(f"{identity}: metadata {key} differs from manifest")
            except Exception as exc:
                issues.append(f"{identity}: failed to read metadata json: {exc}")
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

    report["failed"].extend(provider_export_state_issues(account_dir, account=account, manifest_rows=manifest_rows))

    try:
        require_manifest_accounts(manifest_rows, account)
    except Exception as exc:
        report["failed"].append(str(exc))
    report["failed"].extend(manifest_integrity_issues(manifest_rows))

    journal_issues = journal_row_issues(journal_rows, account)
    report["failed"].extend(journal_issues)
    committed_journal_keys = {
        (str(row.get("canonical_id") or ""), str(row.get("target_mailbox") or ""))
        for row in journal_rows
        if row.get("status") == "committed"
    }
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
    report["exported"] = len(manifest_ids)

    def evaluate_journal(expected_target_by_id: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, int], Dict[str, str], List[str]]:
        committed_by_id: Dict[str, int] = {}
        target_by_id: Dict[str, str] = {}
        failures: List[str] = []
        for row in journal_rows:
            if row.get("status") != "committed":
                continue
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
        report["committed"] = sum(1 for identity in manifest_ids if committed_by_id.get(identity, 0) > 0)

    if check_target:
        try:
            with imap_connection(config.target, account, role="target") as imap:
                target_mailboxes = list_mailboxes(imap)
                target_mailbox_by_identity = translated_target_mailboxes_for_rows(
                    manifest_rows,
                    target_mailboxes,
                    target_provider=config.target.provider,
                )
                expected_target_by_id = {
                    identity: target_mailbox_by_identity[identity]
                    for identity, row in by_id.items()
                }
                committed_by_id, target_by_id, failures = evaluate_journal(expected_target_by_id)
                report["failed"].extend(failures)
                apply_counts(committed_by_id)
                if not report["missing"]:
                    used_target_nums: Dict[str, set[bytes]] = {}
                    for identity, row in by_id.items():
                        target_mailbox = target_by_id.get(identity)
                        if not target_mailbox:
                            continue
                        report["remote_checked"] += 1
                        if config.target.provider == "gmail":
                            actual_labels = consume_target_match_with_gmail_labels(
                                imap,
                                target_mailbox,
                                row,
                                used_target_nums,
                                create_if_missing=False,
                            )
                            if actual_labels is None:
                                report["remote_missing"].append(identity)
                                continue
                            expected_labels = {
                                _gmail_label_key(label)
                                for label in gmail_labels_for_restore(row, target_mailbox)
                            }
                            if row_has_gmail_starred(row):
                                expected_labels.add("starred")
                            missing_labels = sorted(expected_labels - actual_labels)
                            if missing_labels:
                                report["failed"].append(
                                    f"target Gmail labels missing for {identity} in {target_mailbox}: "
                                    + ", ".join(missing_labels)
                                )
                        elif not consume_target_match(imap, target_mailbox, row, used_target_nums, create_if_missing=False):
                            report["remote_missing"].append(identity)
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

    def worker(acc: MigrationAccount) -> List[str]:
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
                target_mailboxes = list_mailboxes(target_imap)
                if not target_mailboxes:
                    account_issues.append("target returned no mailboxes")
        except Exception as exc:
            account_issues.append(f"target preflight failed: {exc}")
        if config.target.available_bytes is None:
            logging.warning("[provider-preflight] %s: target.available_bytes not configured; storage gate skipped", acc.email)
        elif source_total > config.target.available_bytes:
            account_issues.append(f"estimated source bytes {source_total} exceed target.available_bytes {config.target.available_bytes}")
        logging.info("[provider-preflight] %s: estimated_source_bytes=%d", acc.email, source_total)
        return account_issues

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="provider-preflight") as ex:
        for acc, result in zip(config.accounts, ex.map(worker, config.accounts)):
            issues.extend(f"{acc.email}: {issue}" for issue in result)
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
