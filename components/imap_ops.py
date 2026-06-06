import contextlib
import hashlib
import json
import logging
import os
import re
import ssl
import time
from contextlib import AbstractContextManager
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

import imaplib

from .models import Account, ServerConfig
from .utils import decode_imap_utf7, encode_imap_utf7, sanitize_for_path


def quote_mailbox_name(mailbox: str) -> str:
    if mailbox.upper() == "INBOX":
        return "INBOX"
    encoded = encode_imap_utf7(mailbox)
    escaped = encoded.replace("\\", "\\\\").replace('"', r"\"")
    return f'"{escaped}"'


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


def list_all_mailboxes(imap: imaplib.IMAP4) -> List[str]:
    """Return a stable, de-duplicated, sorted list of mailbox names.

    Prefers a quoted name at the end of LIST lines; falls back to the last atom.
    INBOX is sorted first.
    """
    status, data = imap.list()
    if status != "OK":
        raise RuntimeError("Failed to list mailboxes")
    mailboxes: List[str] = []
    for raw in data or []:
        if raw is None:
            continue
        with contextlib.suppress(Exception):
            from .provider_ops import is_noselect, parse_list_entry

            info = parse_list_entry(raw)
            if info is not None:
                if not is_noselect(info):
                    mailboxes.append(info.name)
                continue
        if not isinstance(raw, (bytes, bytearray)):
            continue
        line = raw.decode(errors="ignore").strip()
        attrs_raw = line[1 : line.find(")")] if line.startswith("(") and ")" in line else ""
        if any(attr.lower() in {"\\noselect", "\\nonexistent"} for attr in attrs_raw.split()):
            continue
        m = re.findall(r'"([^"]+)"\s*$', line)
        if m:
            mailboxes.append(decode_imap_utf7(m[0].replace(r"\"", '"').replace(r"\\", "\\")))
        else:
            parts = line.rsplit(" ", 1)
            if parts:
                candidate = parts[-1].strip().strip('"')
                if candidate:
                    mailboxes.append(decode_imap_utf7(candidate))
    unique = []
    seen = set()
    for mb in mailboxes:
        if mb not in seen:
            seen.add(mb)
            unique.append(mb)
    unique.sort(key=lambda x: (0 if x.upper() == "INBOX" else 1, x.lower()))
    return unique


def fetch_all_uids(imap: imaplib.IMAP4, mailbox: str) -> List[int]:
    """Select a mailbox and return all message UIDs in ascending order."""
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Failed to select mailbox {mailbox}")
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
    # Ensure stable ascending order
    uids.sort()
    return uids


def _legacy_import_journal_path(account_dir: Path) -> Path:
    return account_dir / "import.journal.jsonl"


def _stop_requested(stop_event: Optional[object]) -> bool:
    return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())


def _raise_if_stopped(stop_event: Optional[object], label: str) -> None:
    if _stop_requested(stop_event):
        raise RuntimeError(f"{label}: stop requested before completion")


def archive_legacy_import_journal_for_reset(account_dir: Path) -> Optional[Path]:
    path = _legacy_import_journal_path(account_dir)
    if not path.exists():
        return None
    stamp = int(time.time())
    for idx in range(1000):
        suffix = f"reset-{stamp}" if idx == 0 else f"reset-{stamp}-{idx}"
        archive_path = account_dir / f"import.journal.{suffix}.jsonl"
        if not archive_path.exists():
            path.replace(archive_path)
            return archive_path
    raise RuntimeError(f"unable to archive import journal for reset: {path}")


def _legacy_import_target_id(server: ServerConfig, account: Account) -> str:
    seed = {
        "host": server.host,
        "port": server.port,
        "ssl": server.ssl,
        "starttls": server.starttls,
        "account": account.email,
    }
    return hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()


def _legacy_import_key(account_dir: Path, eml_path: Path, mailbox: str, data: bytes) -> str:
    rel_path = eml_path.relative_to(account_dir).as_posix()
    digest = hashlib.sha256(data).hexdigest()
    seed = f"{mailbox}\0{rel_path}\0{len(data)}\0{digest}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _load_legacy_import_journal(account_dir: Path) -> List[Dict[str, str]]:
    path = _legacy_import_journal_path(account_dir)
    rows: List[Dict[str, str]] = []
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
            if line_no == len(lines):
                logging.warning("[import] ignoring incomplete trailing journal row: %s", path)
                needs_rewrite = True
                break
            raise
        if isinstance(row, dict):
            rows.append({str(k): str(v) for k, v in row.items()})
    if needs_rewrite:
        _write_legacy_import_journal(account_dir, rows)
    return rows


def _write_legacy_import_journal(account_dir: Path, rows: List[Dict[str, str]]) -> None:
    path = _legacy_import_journal_path(account_dir)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for row in rows:
            json.dump(row, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    tmp.replace(path)


def _append_legacy_import_journal(account_dir: Path, row: Dict[str, str]) -> None:
    path = _legacy_import_journal_path(account_dir)
    with path.open("a", encoding="utf-8") as f:
        json.dump(row, f, ensure_ascii=False, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def _parse_fetch_response_for_uid(fetch_response: List[bytes]) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Parse a FETCH response into payload bytes and metadata.

    Returns (msg_bytes, flags, internaldate). Any of them can be None.
    """
    if not fetch_response:
        return None, None, None
    msg_bytes: Optional[bytes] = None
    flags: Optional[str] = None
    internaldate: Optional[str] = None
    joinable: List[bytes] = []
    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            meta = part[0]
            body = part[1]
            if body and isinstance(body, (bytes, bytearray)):
                joinable.append(bytes(body))
            if meta and isinstance(meta, (bytes, bytearray)):
                meta_str = meta.decode(errors="ignore")
                m_flags = re.search(r"FLAGS \((.*?)\)", meta_str)
                if m_flags:
                    flags = m_flags.group(1)
                m_int = re.search(r"INTERNALDATE \"([^\"]+)\"", meta_str)
                if m_int:
                    internaldate = m_int.group(1)
        elif isinstance(part, (bytes, bytearray)):
            meta_str = part.decode(errors="ignore")
            m_flags = re.search(r"FLAGS \((.*?)\)", meta_str)
            if m_flags:
                flags = m_flags.group(1)
            m_int = re.search(r"INTERNALDATE \"([^\"]+)\"", meta_str)
            if m_int:
                internaldate = m_int.group(1)
    if joinable:
        msg_bytes = b"".join(joinable)
    return msg_bytes, flags, internaldate


def export_account(account: Account, server: ServerConfig, out_root: Path, ignore_errors: bool, *, stop_event: Optional[object] = None) -> None:
    """Export all messages for an account into `out_root/<email>/<folder>/`.

    Writes one .eml per message and a .json with mailbox/uid/flags/internaldate.
    """
    account_dir = out_root / sanitize_for_path(account.email)
    account_dir.mkdir(parents=True, exist_ok=True)
    logging.info("[export] %s: starting", account.email)
    state_path = account_dir / "export-state.json"
    tmp_state = state_path.with_suffix(".json.tmp")
    with open(tmp_state, "w", encoding="utf-8") as f:
        json.dump(
            {
                "schema_version": 1,
                "account": account.email,
                "complete": False,
                "started_at": int(time.time()),
                "mailboxes": [],
            },
            f,
            ensure_ascii=False,
            sort_keys=True,
        )
        f.write("\n")
    tmp_state.replace(state_path)
    mailbox_errors: List[str] = []
    export_state_mailboxes: List[Dict[str, object]] = []
    with imap_connection(server, account) as imap:
        mailboxes = list_all_mailboxes(imap)

        # Detect sanitize_for_path collisions before writing any data.
        # Two distinct mailbox names that map to the same directory would
        # silently overwrite each other's messages.
        seen_paths: Dict[str, str] = {}  # sanitized_name -> original mailbox
        for mb in mailboxes:
            key = sanitize_for_path(mb)
            if key in seen_paths and seen_paths[key] != mb:
                raise RuntimeError(
                    f"Mailbox name collision for account {account.email}: "
                    f"'{seen_paths[key]}' and '{mb}' both map to directory '{key}'. "
                    f"Cannot export without data loss."
                )
            seen_paths[key] = mb

        for mailbox in mailboxes:
            _raise_if_stopped(stop_event, f"legacy export {account.email}")
            try:
                uids = fetch_all_uids(imap, mailbox)
                logging.info("[export] %s: %s -> %d messages", account.email, mailbox, len(uids))
                export_state_mailboxes.append({
                    "mailbox": mailbox,
                    "path": sanitize_for_path(mailbox),
                    "message_count": len(uids),
                })
                if not uids:
                    folder_dir = account_dir / sanitize_for_path(mailbox)
                    folder_dir.mkdir(parents=True, exist_ok=True)
                    with open(folder_dir / ".mailbox.json", "w", encoding="utf-8") as f:
                        json.dump({"mailbox": mailbox, "message_count": 0}, f, ensure_ascii=False)
                    continue

                folder_dir = account_dir / sanitize_for_path(mailbox)
                folder_dir.mkdir(parents=True, exist_ok=True)
                with open(folder_dir / ".mailbox.json", "w", encoding="utf-8") as f:
                    json.dump({"mailbox": mailbox, "message_count": len(uids)}, f, ensure_ascii=False)

                batch_size = 200
                for i in range(0, len(uids), batch_size):
                    _raise_if_stopped(stop_event, f"legacy export {account.email}")
                    batch = uids[i : i + batch_size]
                    for uid in batch:
                        _raise_if_stopped(stop_event, f"legacy export {account.email}")
                        status, data = imap.uid("fetch", str(uid), "(BODY.PEEK[] FLAGS INTERNALDATE)")
                        if status != "OK":
                            raise RuntimeError(f"fetch failed in {mailbox} for UID {uid}")
                        msg_bytes, flags, internaldate = _parse_fetch_response_for_uid(list(data or []))
                        if not msg_bytes:
                            raise RuntimeError(f"fetch returned no message bytes in {mailbox} for UID {uid}")
                        with contextlib.suppress(Exception):
                            _ = BytesParser(policy=default_policy).parsebytes(msg_bytes)
                        # Zero-pad UID so lexicographic order matches numeric order
                        base = f"u{int(uid):010d}"
                        eml_path = folder_dir / f"{base}.eml"
                        meta_path = folder_dir / f"{base}.json"
                        with open(eml_path, "wb") as f:
                            f.write(msg_bytes)
                        meta = {
                            "mailbox": mailbox,
                            "uid": int(uid),
                            "flags": flags or "",
                            "internaldate": internaldate or "",
                            "rfc822_size": len(msg_bytes),
                            "content_sha256": hashlib.sha256(msg_bytes).hexdigest(),
                        }
                        with open(meta_path, "w", encoding="utf-8") as f:
                            json.dump(meta, f, ensure_ascii=False)
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
    with open(tmp_state, "w", encoding="utf-8") as f:
        json.dump(
            {
                "schema_version": 1,
                "account": account.email,
                "complete": True,
                "completed_at": int(time.time()),
                "mailboxes": export_state_mailboxes,
            },
            f,
            ensure_ascii=False,
            sort_keys=True,
        )
        f.write("\n")
    tmp_state.replace(state_path)
    logging.info("[export] %s: completed", account.email)


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
) -> None:
    """Import all messages for an account from `in_root/<email>/...`.

    If a provisioning context is provided and initial login fails, a one-time
    lazy POP account creation is attempted before retrying login.
    """
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    logging.info("[import] %s: starting", account.email)
    target_id = _legacy_import_target_id(server, account)
    journal_rows = _load_legacy_import_journal(account_dir)
    committed_keys = {
        row.get("key", "")
        for row in journal_rows
        if row.get("status") == "committed" and row.get("key") and row.get("target") == target_id
    }
    pending_keys = {
        row.get("key", "")
        for row in journal_rows
        if row.get("status") == "pending" and row.get("key") and row.get("target") == target_id
    }

    # Build worklist before opening IMAP connection
    per_folder: Dict[str, List[Tuple[Path, str, Optional[str]]]] = {}
    for folder_dir in sorted([p for p in account_dir.iterdir() if p.is_dir()]):
        _raise_if_stopped(stop_event, f"legacy import {account.email}")
        mailbox_meta = folder_dir.name
        marker = folder_dir / ".mailbox.json"
        if marker.exists():
            with contextlib.suppress(Exception):
                marker_meta = json.loads(marker.read_text(encoding="utf-8"))
                marker_mailbox = marker_meta.get("mailbox")
                if isinstance(marker_mailbox, str) and marker_mailbox.strip():
                    mailbox_meta = marker_mailbox
            per_folder.setdefault(mailbox_meta, [])
        default_mailbox = mailbox_meta
        for eml_path in sorted(folder_dir.glob("*.eml")):
            meta_path = eml_path.with_suffix(".json")
            flags = ""
            internaldate = None
            mailbox_meta = default_mailbox
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    flags = str(meta.get("flags", ""))
                    internaldate = meta.get("internaldate") or None
                    mbox = meta.get("mailbox")
                    if isinstance(mbox, str) and mbox.strip():
                        mailbox_meta = mbox
            per_folder.setdefault(mailbox_meta, []).append((eml_path, flags, internaldate))

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
    with _imap_ctx() as imap:
        for folder, entries in per_folder.items():
            _raise_if_stopped(stop_event, f"legacy import {account.email}")
            mailbox = folder
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
                logging.info("[import] %s: %s <- %d messages", account.email, mailbox, len(entries))
                for eml_path, flags, internaldate in entries:
                    _raise_if_stopped(stop_event, f"legacy import {account.email}")
                    with open(eml_path, "rb") as f:
                        data = f.read()
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
                    import_key = _legacy_import_key(account_dir, eml_path, mailbox, data)
                    if import_key in committed_keys:
                        logging.info("[import] %s: skipping already committed %s", account.email, eml_path)
                        continue
                    if import_key in pending_keys:
                        raise RuntimeError(
                            f"legacy import journal has pending append for {eml_path}; "
                            "target state is uncertain, inspect the mailbox before retrying"
                        )
                    rel_path = eml_path.relative_to(account_dir).as_posix()
                    _append_legacy_import_journal(account_dir, {
                        "key": import_key,
                        "status": "pending",
                        "target": target_id,
                        "mailbox": mailbox,
                        "path": rel_path,
                        "timestamp": str(int(time.time())),
                    })
                    status, _ = imap.append(quote_mailbox_name(mailbox), flags_str, date_time, data)
                    if status != "OK":
                        raise RuntimeError(f"append failed for {eml_path}")
                    _append_legacy_import_journal(account_dir, {
                        "key": import_key,
                        "status": "committed",
                        "target": target_id,
                        "mailbox": mailbox,
                        "path": rel_path,
                        "timestamp": str(int(time.time())),
                    })
                    pending_keys.discard(import_key)
                    committed_keys.add(import_key)
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
