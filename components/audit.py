import contextlib
import json
from email.parser import BytesParser
from email.policy import compat32 as compat32_policy
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Account, Config, ServerConfig
from .imap_ops import imap_connection, list_all_mailboxes
from .utils import sanitize_for_path


def _audit_eml_file(eml_path: Path, expected_folder_name: str) -> List[str]:
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
    if b"FLAGS (" in data or b"INTERNALDATE \"" in data:
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


def audit_account(account: Account, in_root: Path, server: Optional[ServerConfig], check_remote: bool = True) -> Tuple[str, List[str]]:
    issues: List[str] = []
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        issues.append(f"account directory missing: {account_dir}")
        return account.email, issues
    for folder_dir in [p for p in account_dir.iterdir() if p.is_dir()]:
        folder = folder_dir.name
        emls = list(folder_dir.glob("*.eml"))
        jsons = list(folder_dir.glob("*.json"))
        if not emls:
            issues.append(f"{account.email}:{folder}: no .eml files found")
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
            if stem.startswith("u") and stem[1:].isdigit():
                uid_in_name = int(stem[1:])
                meta_path = eml_path.with_suffix(".json")
                with contextlib.suppress(Exception):
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    uid_meta = meta.get("uid")
                    if isinstance(uid_meta, int) and uid_meta != uid_in_name:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: uid mismatch (name={uid_in_name} meta={uid_meta})")
    if check_remote and server is not None:
        try:
            with imap_connection(server, account) as imap:
                remote_mailboxes = list_all_mailboxes(imap)
                remote_counts: Dict[str, int] = {}
                for mbox in remote_mailboxes:
                    status, _ = imap.select(mbox, readonly=True)
                    if status != "OK":
                        continue
                    status, data = imap.uid("search", None, "ALL")
                    if status != "OK":
                        continue
                    num = len((data[0] or b"").split()) if data else 0
                    remote_counts[sanitize_for_path(mbox)] = num
        except Exception as exc:
            issues.append(f"remote check failed: {exc}")
            remote_counts = {}
        for folder_dir in [p for p in account_dir.iterdir() if p.is_dir()]:
            folder = folder_dir.name
            local_count = len(list(folder_dir.glob("*.eml")))
            remote_count = remote_counts.get(folder, -1)
            if remote_count >= 0 and local_count != remote_count:
                issues.append(f"{account.email}:{folder}: local={local_count} remote={remote_count} mismatch")
        for folder_name, rcount in remote_counts.items():
            if not (account_dir / folder_name).exists() and rcount > 0:
                issues.append(f"{account.email}:{folder_name}: missing locally but remote has {rcount} messages")
    return account.email, issues


def audit_export(in_root: Path, config: Config, max_workers: int, check_remote: bool = True) -> Tuple[bool, List[str]]:
    issues_accum: List[str] = []

    def worker(acc: Account) -> List[str]:
        _email, issues = audit_account(acc, in_root, config.server if check_remote else None, check_remote=check_remote)
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


