import contextlib
import hashlib
import json
import re
from email.parser import BytesParser
from email.policy import compat32 as compat32_policy
from email.policy import default as default_policy
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from .models import Account, Config, ServerConfig
from .imap_ops import imap_connection, legacy_server_endpoint, legacy_server_endpoint_digest, list_all_mailboxes, quote_mailbox_name
from .utils import quote_imap_search_value, sanitize_for_path


def _message_id_header(data: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


def _remote_has_message(imap, mailbox: str, data: bytes, used_nums: Optional[Set[bytes]] = None) -> bool:
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


def _folder_mailbox_name(folder_dir: Path) -> str:
    marker_path = folder_dir / ".mailbox.json"
    if not marker_path.exists():
        return folder_dir.name
    with contextlib.suppress(Exception):
        raw = json.loads(marker_path.read_text(encoding="utf-8"))
        mailbox = raw.get("mailbox") if isinstance(raw, dict) else None
        if isinstance(mailbox, str) and mailbox.strip():
            return mailbox
    return folder_dir.name


def _legacy_export_state_issues(
    account: Account,
    account_dir: Path,
    folder_dirs: List[Path],
    *,
    require_state: bool,
    expected_source_server: Optional[ServerConfig] = None,
) -> List[str]:
    issues: List[str] = []
    state_path = account_dir / "export-state.json"
    if not state_path.exists():
        if require_state:
            issues.append(f"{account.email}: export-state missing; rerun legacy export before destructive reset")
        return issues
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{account.email}: export-state missing or invalid: {exc}"]
    if not isinstance(state, dict):
        return [f"{account.email}: export-state is not an object"]
    if state.get("complete") is not True:
        issues.append(f"{account.email}: export-state is not complete")
    if state.get("account") not in {None, account.email}:
        issues.append(f"{account.email}: export-state account mismatch ({state.get('account')})")
    source_server = state.get("source_server")
    source_server_sha256 = state.get("source_server_sha256")
    if expected_source_server is not None:
        expected_endpoint = legacy_server_endpoint(expected_source_server)
        expected_digest = legacy_server_endpoint_digest(expected_source_server)
        if not isinstance(source_server, dict):
            issues.append(f"{account.email}: export-state source_server missing; rerun legacy export with current version")
        elif source_server != expected_endpoint:
            issues.append(
                f"{account.email}: export-state source_server does not match config source_server "
                f"(state={source_server} config={expected_endpoint})"
            )
        if source_server_sha256 != expected_digest:
            issues.append(f"{account.email}: export-state source_server_sha256 does not match config source_server")
    elif require_state:
        issues.append(f"{account.email}: config source_server missing; cannot bind staged export to source endpoint")
    raw_mailboxes = state.get("mailboxes")
    if not isinstance(raw_mailboxes, list):
        issues.append(f"{account.email}: export-state mailboxes is missing or invalid")
        return issues
    staged_by_path = {folder_dir.name: folder_dir for folder_dir in folder_dirs}
    state_paths: set[str] = set()
    state_mailbox_by_path: Dict[str, str] = {}
    for idx, raw in enumerate(raw_mailboxes, 1):
        if not isinstance(raw, dict):
            issues.append(f"{account.email}: export-state mailbox entry {idx} is not an object")
            continue
        mailbox = raw.get("mailbox")
        path = raw.get("path")
        message_count = raw.get("message_count")
        if not isinstance(mailbox, str) or not mailbox:
            issues.append(f"{account.email}: export-state mailbox entry {idx} missing mailbox")
            continue
        expected_path = sanitize_for_path(mailbox)
        if not isinstance(path, str) or path != expected_path:
            issues.append(f"{account.email}: export-state mailbox {mailbox!r} path mismatch")
            path = expected_path
        if type(message_count) is not int or message_count < 0:
            issues.append(f"{account.email}: export-state mailbox {mailbox!r} has invalid message_count")
            continue
        previous_mailbox = state_mailbox_by_path.get(path)
        if previous_mailbox is not None:
            issues.append(
                f"{account.email}: export-state mailbox path collision after sanitizing: "
                f"{previous_mailbox!r} and {mailbox!r} both map to {path!r}"
            )
            continue
        state_mailbox_by_path[path] = mailbox
        state_paths.add(path)
        folder_dir = staged_by_path.get(path)
        if folder_dir is None:
            issues.append(f"{account.email}: export-state mailbox {mailbox!r} missing staged folder {path}")
            continue
        eml_count = len(list(folder_dir.glob("*.eml")))
        if eml_count != message_count:
            issues.append(
                f"{account.email}:{path}: export-state count mismatch "
                f"(state={message_count} eml={eml_count})"
            )
    extra_paths = sorted(set(staged_by_path) - state_paths)
    for path in extra_paths:
        issues.append(f"{account.email}:{path}: staged folder missing from export-state")
    return issues


def _audit_eml_file(eml_path: Path, expected_folder_name: str) -> List[str]:
    """Perform lightweight sanity checks on a single exported .eml file."""
    issues: List[str] = []
    try:
        data = eml_path.read_bytes()
    except Exception as exc:
        return [f"{eml_path}: failed to read: {exc}"]
    if not data:
        issues.append(f"{eml_path}: empty file")
        return issues
    try:
        msg = BytesParser(policy=compat32_policy).parsebytes(data)
    except Exception as exc:
        issues.append(f"{eml_path}: failed to parse RFC822: {exc}")
        msg = None
    wrapper_regions = data[:512] + b"\n" + data[-512:]
    if re.search(
        rb"(?:^|\n)\s*(?:\*+\s+)?\d+\s+\(.*(?:FLAGS \(|INTERNALDATE \")",
        wrapper_regions,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        issues.append(f"{eml_path}: suspicious raw IMAP metadata present in payload (possible concatenation)")
    if msg is not None:
        header_keys = ["From", "To", "Subject", "Date", "Message-Id", "MIME-Version", "Content-Type", "Received"]
        def _safe_get(h: str) -> bool:
            try:
                return bool(msg.get(h))
            except Exception:
                return False
        present = sum(1 for k in header_keys if _safe_get(k))
        if present < 2:
            issues.append(f"{eml_path}: sparse headers (found {present}/8 common headers)")
        if msg.is_multipart():
            parts = [p for p in msg.walk()]
            if len(parts) <= 1:
                issues.append(f"{eml_path}: declared multipart but no parts found")
    return issues


def audit_account(
    account: Account,
    in_root: Path,
    server: Optional[ServerConfig],
    check_remote: bool = True,
    *,
    require_integrity_metadata: bool = False,
    expected_source_server: Optional[ServerConfig] = None,
) -> Tuple[str, List[str]]:
    """Audit a single account directory and optionally compare to remote counts."""
    issues: List[str] = []
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        issues.append(f"account directory missing: {account_dir}")
        return account.email, issues
    folder_dirs = [p for p in account_dir.iterdir() if p.is_dir()]
    if not folder_dirs:
        issues.append(f"{account.email}: no mailbox folders found")
    issues.extend(
        _legacy_export_state_issues(
            account,
            account_dir,
            folder_dirs,
            require_state=require_integrity_metadata,
            expected_source_server=expected_source_server,
        )
    )
    for folder_dir in folder_dirs:
        folder = folder_dir.name
        emls = list(folder_dir.glob("*.eml"))
        jsons = [p for p in folder_dir.glob("*.json") if p.name != ".mailbox.json"]
        mailbox_marker = folder_dir / ".mailbox.json"
        if not emls and not mailbox_marker.exists():
            issues.append(f"{account.email}:{folder}: no .eml files found")
        if mailbox_marker.exists():
            try:
                marker = json.loads(mailbox_marker.read_text(encoding="utf-8"))
                expected_count = marker.get("message_count") if isinstance(marker, dict) else None
                if type(expected_count) is not int or expected_count < 0:
                    issues.append(f"{account.email}:{folder}: mailbox marker has invalid message_count")
                elif expected_count != len(emls):
                    issues.append(f"{account.email}:{folder}: mailbox marker count mismatch (marker={expected_count} eml={len(emls)})")
                mailbox_name = marker.get("mailbox") if isinstance(marker, dict) else None
                if isinstance(mailbox_name, str) and mailbox_name and sanitize_for_path(mailbox_name) != folder:
                    issues.append(f"{account.email}:{folder}: mailbox marker name mismatch (marker={mailbox_name})")
            except Exception as exc:
                issues.append(f"{account.email}:{folder}: failed to parse mailbox marker: {exc}")
        eml_stems = {p.stem for p in emls}
        json_stems = {p.stem for p in jsons}
        missing_meta = eml_stems - json_stems
        missing_eml = json_stems - eml_stems
        if missing_meta:
            issues.append(f"{account.email}:{folder}: {len(missing_meta)} message(s) missing .json metadata")
        if missing_eml:
            issues.append(f"{account.email}:{folder}: {len(missing_eml)} metadata file(s) without .eml counterpart")
        for eml_path in emls:
            issues.extend(_audit_eml_file(eml_path, folder))
            stem = eml_path.stem
            meta_path = eml_path.with_suffix(".json")
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception as exc:
                issues.append(f"{account.email}:{folder}:{eml_path.name}: failed to parse message metadata: {exc}")
                continue
            if not isinstance(meta, dict):
                issues.append(f"{account.email}:{folder}:{eml_path.name}: message metadata is not an object")
                continue
            mailbox_meta = meta.get("mailbox")
            if not isinstance(mailbox_meta, str) or not mailbox_meta.strip():
                issues.append(f"{account.email}:{folder}:{eml_path.name}: missing mailbox metadata")
            elif sanitize_for_path(mailbox_meta) != folder:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: mailbox metadata mismatch "
                    f"(folder={folder} meta={mailbox_meta})"
                )
            if stem.startswith("u") and stem[1:].isdigit():
                uid_in_name = int(stem[1:])
                uid_meta = meta.get("uid")
                if isinstance(uid_meta, int) and uid_meta != uid_in_name:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: uid mismatch (name={uid_in_name} meta={uid_meta})")
            if require_integrity_metadata:
                expected_hash = meta.get("content_sha256")
                expected_size = meta.get("rfc822_size")
                if not isinstance(expected_hash, str) or not expected_hash:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: missing content_sha256 metadata")
                if not isinstance(expected_size, int):
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: missing rfc822_size metadata")
                if isinstance(expected_hash, str) and expected_hash and isinstance(expected_size, int):
                    try:
                        data = eml_path.read_bytes()
                        actual_hash = hashlib.sha256(data).hexdigest()
                        if actual_hash != expected_hash:
                            issues.append(f"{account.email}:{folder}:{eml_path.name}: content_sha256 mismatch")
                        if len(data) != expected_size:
                            issues.append(
                                f"{account.email}:{folder}:{eml_path.name}: rfc822_size mismatch "
                                f"(metadata={expected_size} actual={len(data)})"
                            )
                    except Exception as exc:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: failed integrity read: {exc}")
    if check_remote and server is not None:
        try:
            with imap_connection(server, account) as imap:
                remote_mailboxes = list_all_mailboxes(imap)
                remote_counts: Dict[str, int] = {}
                remote_mailbox_by_key: Dict[str, str] = {}
                count_mismatched = set()
                for mbox in remote_mailboxes:
                    status, _ = imap.select(quote_mailbox_name(mbox), readonly=True)
                    key = sanitize_for_path(mbox)
                    if status != "OK":
                        count_mismatched.add(key)
                        issues.append(f"{account.email}:{key}: remote mailbox could not be selected: {mbox!r}")
                        continue
                    status, data = imap.uid("search", "ALL")
                    if status != "OK":
                        count_mismatched.add(key)
                        issues.append(f"{account.email}:{key}: remote mailbox UID search failed: {mbox!r}")
                        continue
                    num = len((data[0] or b"").split()) if data else 0
                    previous = remote_mailbox_by_key.get(key)
                    if previous is not None and previous != mbox:
                        count_mismatched.add(key)
                        issues.append(
                            f"{account.email}:{key}: remote mailbox name collision after sanitizing: "
                            f"{previous!r} and {mbox!r}"
                        )
                        continue
                    remote_counts[key] = num
                    remote_mailbox_by_key[key] = mbox
                identity_candidates: List[Tuple[Path, str, str]] = []
                for folder_dir in folder_dirs:
                    folder = folder_dir.name
                    local_count = len(list(folder_dir.glob("*.eml")))
                    remote_count = remote_counts.get(folder, -1)
                    if remote_count < 0 and local_count > 0:
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: missing remotely or not selectable but local has {local_count} messages")
                    elif remote_count >= 0 and local_count != remote_count:
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: local={local_count} remote={remote_count} mismatch")
                    elif local_count > 0:
                        mailbox = remote_mailbox_by_key.get(folder, _folder_mailbox_name(folder_dir))
                        for eml_path in sorted(folder_dir.glob("*.eml")):
                            identity_candidates.append((eml_path, folder, mailbox))
                for folder_name, rcount in remote_counts.items():
                    if rcount > 0 and not (account_dir / folder_name).exists():
                        count_mismatched.add(folder_name)
                        issues.append(f"{account.email}:{folder_name}: missing locally but remote has {rcount} messages")
                used_remote_nums_by_folder: Dict[str, Set[bytes]] = {}
                for eml_path, folder, mailbox in identity_candidates:
                    if folder in count_mismatched:
                        continue
                    try:
                        data = eml_path.read_bytes()
                        used_remote_nums = used_remote_nums_by_folder.setdefault(folder, set())
                        if not _remote_has_message(imap, mailbox, data, used_remote_nums):
                            issues.append(f"{account.email}:{folder}:{eml_path.name}: remote message identity missing")
                    except Exception as exc:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: remote identity check failed: {exc}")
        except Exception as exc:
            issues.append(f"remote check failed: {exc}")
    return account.email, issues


def audit_export(
    in_root: Path,
    config: Config,
    max_workers: int,
    check_remote: bool = True,
    *,
    require_integrity_metadata: bool = False,
) -> Tuple[bool, List[str]]:
    """Audit all accounts concurrently and aggregate issues.

    Returns (ok, issues) where `ok` is True when no issues were found.
    """
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    issues_accum: List[str] = []
    expected_source_server = config.source_server if config.source_server is not None else None
    if expected_source_server is None and not require_integrity_metadata:
        expected_source_server = config.server

    def worker(acc: Account) -> List[str]:
        _email, issues = audit_account(
            acc,
            in_root,
            config.server if check_remote else None,
            check_remote=check_remote,
            require_integrity_metadata=require_integrity_metadata,
            expected_source_server=expected_source_server,
        )
        if not issues:
            return []
        return [f"{acc.email}: {msg}" if not msg.startswith(acc.email) else msg for msg in issues]

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit") as ex:
        results = list(ex.map(worker, config.accounts))
    for lst in results:
        if lst:
            issues_accum.extend(lst)
    ok = len(issues_accum) == 0
    return ok, issues_accum
