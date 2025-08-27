import contextlib
import json
import logging
import re
import ssl
import time
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import imaplib

from .models import Account, ServerConfig
from .utils import sanitize_for_path


@contextlib.contextmanager
def imap_connection(server: ServerConfig, account: Account) -> Iterable[imaplib.IMAP4]:
    """Context-managed IMAP connection.

    Handles SSL/STARTTLS negotiation and ensures logout on exit.
    """
    if server.ssl:
        imap = imaplib.IMAP4_SSL(host=server.host, port=server.port)
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
        line = raw.decode(errors="ignore").strip()
        m = re.findall(r'"([^"]+)"\s*$', line)
        if m:
            mailboxes.append(m[0])
        else:
            parts = line.rsplit(" ", 1)
            if parts:
                candidate = parts[-1].strip().strip('"')
                if candidate:
                    mailboxes.append(candidate)
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
    status, _ = imap.select(mailbox, readonly=True)
    if status != "OK":
        raise RuntimeError(f"Failed to select mailbox {mailbox}")
    status, data = imap.uid("search", None, "ALL")
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
    with imap_connection(server, account) as imap:
        mailboxes = list_all_mailboxes(imap)
        for mailbox in mailboxes:
            if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                logging.info("[export] %s: stop requested, exiting", account.email)
                return
            try:
                status, _ = imap.select(mailbox, readonly=True)
                if status != "OK":
                    raise RuntimeError(f"select failed: {mailbox}")
                uids = fetch_all_uids(imap, mailbox)
                logging.info("[export] %s: %s -> %d messages", account.email, mailbox, len(uids))
                if not uids:
                    continue

                folder_dir = account_dir / sanitize_for_path(mailbox)
                folder_dir.mkdir(parents=True, exist_ok=True)

                batch_size = 200
                for i in range(0, len(uids), batch_size):
                    if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                        logging.info("[export] %s: stop requested during UID batching, exiting", account.email)
                        return
                    batch = uids[i : i + batch_size]
                    for uid in batch:
                        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                            logging.info("[export] %s: stop requested during UID loop, exiting", account.email)
                            return
                        status, data = imap.uid("fetch", str(uid), "(RFC822 FLAGS INTERNALDATE)")
                        if status != "OK":
                            raise RuntimeError(f"fetch failed in {mailbox} for UID {uid}")
                        msg_bytes, flags, internaldate = _parse_fetch_response_for_uid(list(data or []))
                        if not msg_bytes:
                            continue
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
                        }
                        with open(meta_path, "w", encoding="utf-8") as f:
                            json.dump(meta, f, ensure_ascii=False)
            except Exception as exc:
                logging.exception("[export] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                if not ignore_errors:
                    raise
    logging.info("[export] %s: completed", account.email)


def import_account(
    account: Account,
    server: ServerConfig,
    in_root: Path,
    ignore_errors: bool,
    *,
    create_folder: bool = True,
    imap_factory=None,
    stop_event: Optional[object] = None,
    da_context: Optional[Tuple[object, int]] = None,
) -> None:
    """Import all messages for an account from `in_root/<email>/...`.

    If `da_context=(client, quota_mb)` is provided and initial login fails,
    a one-time lazy POP account creation is attempted before retrying login.
    """
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    logging.info("[import] %s: starting", account.email)

    # Build worklist before opening IMAP connection
    per_folder: Dict[str, List[Tuple[Path, str, Optional[str]]]] = {}
    for folder_dir in sorted([p for p in account_dir.iterdir() if p.is_dir()]):
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            logging.info("[import] %s: stop requested while scanning folders, exiting", account.email)
            return
        for eml_path in sorted(folder_dir.glob("*.eml")):
            meta_path = eml_path.with_suffix(".json")
            flags = ""
            internaldate = None
            mailbox_meta = folder_dir.name
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
    def _imap_ctx():
        return imap_factory(server, account) if callable(imap_factory) else imap_connection(server, account)

    # Try login; if it fails and DA context is provided, create mailbox and retry once
    def _try_login_only() -> None:
        with _imap_ctx():
            pass

    login_ok = False
    try:
        _try_login_only()
        login_ok = True
    except Exception as first_exc:
        if da_context is not None:
            client, quota_mb = da_context
            try:
                if "@" in account.email:
                    local, domain = account.email.split("@", 1)
                else:
                    raise ValueError("invalid email address for DA provisioning")
                # Create mailbox then retry login
                client.create_pop_account(domain, local, account.password, quota_mb=quota_mb)  # type: ignore[attr-defined]
                logging.info("[da][lazy] Created mailbox: %s, retrying login", account.email)
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
    with _imap_ctx() as imap:
        for folder, entries in per_folder.items():
            if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                logging.info("[import] %s: stop requested before processing folder %s, exiting", account.email, folder)
                return
            mailbox = folder
            try:
                status, _ = imap.select(mailbox)
                if status != "OK":
                    if create_folder:
                        with contextlib.suppress(Exception):
                            imap.create(mailbox)
                        status, _ = imap.select(mailbox)
                    if status != "OK":
                        raise RuntimeError(f"cannot select or create mailbox {mailbox}")
                logging.info("[import] %s: %s <- %d messages", account.email, mailbox, len(entries))
                for eml_path, flags, internaldate in entries:
                    if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                        logging.info("[import] %s: stop requested during message loop, exiting", account.email)
                        return
                    with open(eml_path, "rb") as f:
                        data = f.read()
                    flags_tuple = None
                    if flags:
                        raw_tokens = [tok for tok in (flags.split()) if tok and tok.strip()]
                        # \RECENT is a read-only system flag; servers reject setting it on APPEND
                        filtered_tokens = [t for t in raw_tokens if t.strip().upper() != "\\RECENT"]
                        if filtered_tokens:
                            flags_norm = "(" + " ".join(filtered_tokens) + ")"
                            flags_tuple = flags_norm
                    # Build IMAP INTERNALDATE value. If missing, use current time (RFC3501 format).
                    if isinstance(internaldate, str) and internaldate.strip():
                        dt_str = internaldate.strip()
                        if not (dt_str.startswith("\"") and dt_str.endswith("\"")):
                            dt_str = f'"{dt_str}"'
                        date_time = dt_str
                    else:
                        import imaplib as _imaplib
                        date_time = _imaplib.Time2Internaldate(time.time())
                    status, _ = imap.append(mailbox, flags_tuple, date_time, data)
                    if status != "OK":
                        raise RuntimeError(f"append failed for {eml_path}")
            except Exception as exc:
                logging.exception("[import] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                if not ignore_errors:
                    raise
    logging.info("[import] %s: completed", account.email)


