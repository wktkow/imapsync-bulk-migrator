import contextlib
import concurrent.futures
import hashlib
import json
import re
from email.parser import BytesParser
from email.policy import compat32 as compat32_policy
from email.policy import default as default_policy
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from .content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_issue
from .models import Account, Config, ServerConfig
from .imap_ops import (
    _imap_append_wire_bytes,
    _is_legacy_all_source_view,
    _is_legacy_flagged_source_view,
    _legacy_flags_from_fetch_response,
    _legacy_symlink_component,
    _legacy_hierarchy_metadata,
    _legacy_missing_target_flags,
    _legacy_uidvalidity_metadata,
    _list_selectable_mailbox_entries,
    _read_file_no_symlink,
    _require_legacy_payload_integrity,
    _legacy_validate_path_segments,
    _should_skip_legacy_source_view,
    _validate_legacy_delivery_metadata,
    _validate_legacy_sidecar_integrity,
    imap_connection,
    legacy_reserved_mailbox_path_issue,
    legacy_server_endpoint,
    legacy_server_endpoint_digest,
    quote_mailbox_name,
)
from .utils import (
    canonical_imap_mailbox_name,
    canonical_mailbox_alias_key,
    canonical_mailbox_path_key,
    quote_imap_search_value,
    sanitize_for_path,
    sanitized_path_key,
)


def _stop_requested(stop_event: Optional[object]) -> bool:
    return bool(stop_event is not None and getattr(stop_event, "is_set", lambda: False)())


def _raise_if_stopped(stop_event: Optional[object], label: str) -> None:
    if _stop_requested(stop_event):
        raise RuntimeError(f"{label}: stop requested before completion")


def _message_id_header(data: bytes) -> str:
    with contextlib.suppress(Exception):
        msg = BytesParser(policy=default_policy).parsebytes(data)
        return str(msg.get("Message-ID") or msg.get("Message-Id") or "").strip()
    return ""


def _read_staged_artifact(path: Path, label: str) -> bytes:
    return _read_file_no_symlink(path, label, reject_hard_links=True)


def _read_bound_legacy_message(eml_path: Path, *, require_integrity_metadata: bool) -> Tuple[bytes, str]:
    meta_path = eml_path.with_suffix(".json")
    if not meta_path.exists():
        if not require_integrity_metadata:
            return _read_staged_artifact(eml_path, "legacy message file"), ""
        raise RuntimeError(f"{meta_path}: missing message metadata")
    meta = json.loads(_read_staged_artifact(meta_path, "legacy message metadata").decode("utf-8"))
    if not isinstance(meta, dict):
        if not require_integrity_metadata:
            return _read_staged_artifact(eml_path, "legacy message file"), ""
        raise RuntimeError(f"{meta_path}: message metadata is not an object")
    integrity_keys_present = any(key in meta for key in ("content_sha256", "rfc822_size", CONTENT_BINDING_FIELD))
    flags = str(meta.get("flags") or "") if isinstance(meta.get("flags", ""), str) else ""
    if not require_integrity_metadata and not integrity_keys_present:
        return _read_staged_artifact(eml_path, "legacy message file"), flags
    expected_size, expected_hash = _validate_legacy_sidecar_integrity(meta_path, meta)
    data = _read_staged_artifact(eml_path, "legacy message file")
    _require_legacy_payload_integrity(eml_path, data, expected_size, expected_hash)
    return data, flags


def _content_identity_variants(data: bytes) -> Set[Tuple[int, str]]:
    variants = {data}
    append_data = _imap_append_wire_bytes(data)
    variants.add(append_data)
    return {(len(candidate), hashlib.sha256(candidate).hexdigest()) for candidate in variants}


def _is_legacy_virtual_source_attrs(attributes: Tuple[str, ...]) -> bool:
    return _is_legacy_all_source_view(attributes) or _is_legacy_flagged_source_view(attributes)


def _identity_variant_slots_cover(
    remote_slots: List[Set[Tuple[int, str]]],
    local_slots: List[Set[Tuple[int, str]]],
) -> bool:
    if len(remote_slots) > len(local_slots):
        return False
    edges: List[List[int]] = []
    for remote_identities in remote_slots:
        matches = [
            idx
            for idx, local_identities in enumerate(local_slots)
            if remote_identities & local_identities
        ]
        if not matches:
            return False
        edges.append(matches)
    match_for_local: Dict[int, int] = {}

    def assign(remote_idx: int, seen: Set[int]) -> bool:
        for local_idx in edges[remote_idx]:
            if local_idx in seen:
                continue
            seen.add(local_idx)
            previous_remote = match_for_local.get(local_idx)
            if previous_remote is None or assign(previous_remote, seen):
                match_for_local[local_idx] = remote_idx
                return True
        return False

    for remote_idx in sorted(range(len(remote_slots)), key=lambda idx: len(edges[idx])):
        if not assign(remote_idx, set()):
            return False
    return True


def _remote_mailbox_content_covered(imap, mailbox: str, local_identity_slots: List[Set[Tuple[int, str]]]) -> bool:
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    status, search_data = imap.search(None, "ALL")
    if status != "OK":
        return False
    nums = search_data[0].split() if search_data and search_data[0] else []
    remote_slots: List[Set[Tuple[int, str]]] = []
    for num in nums:
        status, fetched = imap.fetch(num, "(RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            return False
        remote_identities: Set[Tuple[int, str]] = set()
        for part in fetched or []:
            if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
                continue
            remote_identities.update(_content_identity_variants(bytes(part[1])))
        if not remote_identities:
            return False
        remote_slots.append(remote_identities)
    return _identity_variant_slots_cover(remote_slots, local_identity_slots)


def _remote_has_message(
    imap,
    mailbox: str,
    data: bytes,
    used_nums: Optional[Set[bytes]] = None,
    expected_flags: str = "",
) -> bool:
    status, _ = imap.select(quote_mailbox_name(mailbox), readonly=True)
    if status != "OK":
        return False
    message_id = _message_id_header(data)
    variants = [data]
    append_data = _imap_append_wire_bytes(data)
    if append_data != data:
        variants.append(append_data)
    expected_identities = {
        (len(candidate), hashlib.sha256(candidate).hexdigest())
        for candidate in variants
    }
    if message_id:
        status, search_data = imap.search(None, "HEADER", "Message-ID", quote_imap_search_value(message_id))
    else:
        status, search_data = imap.search(None, "ALL")
    if status != "OK" or not search_data or not search_data[0]:
        return False
    flag_mismatches: List[List[str]] = []
    for num in search_data[0].split():
        if used_nums is not None and num in used_nums:
            continue
        status, fetched = imap.fetch(num, "(RFC822.SIZE FLAGS BODY.PEEK[])")
        if status != "OK":
            continue
        missing_flags = _legacy_missing_target_flags(
            expected_flags,
            _legacy_flags_from_fetch_response(list(fetched or [])),
        )
        for part in fetched or []:
            if not (isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray))):
                continue
            body = bytes(part[1])
            body_identity = (len(body), hashlib.sha256(body).hexdigest())
            if body_identity in expected_identities:
                if missing_flags:
                    flag_mismatches.append(missing_flags)
                    continue
                if used_nums is not None:
                    used_nums.add(num)
                return True
    if flag_mismatches:
        missing = sorted({flag for flags in flag_mismatches for flag in flags}, key=str.upper)
        raise RuntimeError("remote flags missing: " + ", ".join(missing))
    return False


def _folder_mailbox_name(folder_dir: Path) -> str:
    marker_path = folder_dir / ".mailbox.json"
    if marker_path.is_symlink():
        return folder_dir.name
    if not marker_path.exists():
        return folder_dir.name
    with contextlib.suppress(Exception):
        raw = json.loads(_read_staged_artifact(marker_path, "legacy mailbox marker").decode("utf-8"))
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
    require_source_server_binding: bool = True,
) -> List[str]:
    issues: List[str] = []
    state_path = account_dir / "export-state.json"
    if state_path.is_symlink():
        return [f"{account.email}: export-state is a symlink"]
    if not state_path.exists():
        if require_state:
            issues.append(f"{account.email}: export-state missing; rerun legacy export before destructive reset")
        return issues
    try:
        state = json.loads(_read_staged_artifact(state_path, "legacy export-state").decode("utf-8"))
    except Exception as exc:
        return [f"{account.email}: export-state missing or invalid: {exc}"]
    if not isinstance(state, dict):
        return [f"{account.email}: export-state is not an object"]
    if state.get("complete") is not True:
        issues.append(f"{account.email}: export-state is not complete")
    state_account = state.get("account")
    if require_state and state_account != account.email:
        issues.append(f"{account.email}: export-state account mismatch ({state_account})")
    elif not require_state and state_account not in {None, account.email}:
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
    elif require_state and require_source_server_binding:
        issues.append(f"{account.email}: config source_server missing; cannot bind staged export to source endpoint")
    raw_mailboxes = state.get("mailboxes")
    if not isinstance(raw_mailboxes, list):
        issues.append(f"{account.email}: export-state mailboxes is missing or invalid")
        return issues
    staged_by_path = {folder_dir.name: folder_dir for folder_dir in folder_dirs}
    state_paths: set[str] = set()
    state_mailbox_by_path: Dict[str, Tuple[str, str]] = {}
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
        reserved_issue = legacy_reserved_mailbox_path_issue(mailbox, path)
        if reserved_issue is not None:
            issues.append(f"{account.email}: export-state {reserved_issue}")
        if type(message_count) is not int or message_count < 0:
            issues.append(f"{account.email}: export-state mailbox {mailbox!r} has invalid message_count")
            continue
        try:
            state_hierarchy = _legacy_hierarchy_metadata(
                raw,
                mailbox,
                f"{account.email}: export-state mailbox {mailbox!r}",
            )
        except RuntimeError as exc:
            issues.append(str(exc))
            state_hierarchy = ("", ())
        try:
            state_uidvalidity = _legacy_uidvalidity_metadata(
                raw,
                f"{account.email}: export-state mailbox {mailbox!r}",
            )
        except RuntimeError as exc:
            issues.append(str(exc))
            state_uidvalidity = ""
        collision_key = sanitized_path_key(mailbox)
        previous_mailbox = state_mailbox_by_path.get(collision_key)
        if previous_mailbox is not None:
            issues.append(
                f"{account.email}: export-state mailbox path collision after sanitizing: "
                f"{previous_mailbox[0]!r} -> {previous_mailbox[1]!r} and {mailbox!r} -> {path!r} "
                "alias on case-insensitive filesystems"
            )
            continue
        state_mailbox_by_path[collision_key] = (mailbox, path)
        state_paths.add(path)
        folder_dir = staged_by_path.get(path)
        if folder_dir is None:
            issues.append(f"{account.email}: export-state mailbox {mailbox!r} missing staged folder {path}")
            continue
        marker_path = folder_dir / ".mailbox.json"
        if marker_path.exists() and not marker_path.is_symlink():
            try:
                marker = json.loads(_read_staged_artifact(marker_path, "legacy mailbox marker").decode("utf-8"))
            except Exception as exc:
                issues.append(f"{account.email}:{path}: failed to parse mailbox marker for export-state comparison: {exc}")
            else:
                if isinstance(marker, dict) and marker.get("mailbox") == mailbox:
                    try:
                        marker_hierarchy = _legacy_hierarchy_metadata(
                            marker,
                            mailbox,
                            f"{account.email}:{path}: mailbox marker",
                        )
                    except RuntimeError as exc:
                        issues.append(str(exc))
                    else:
                        if marker_hierarchy != state_hierarchy:
                            issues.append(
                                f"{account.email}:{path}: mailbox marker source_path_segments mismatch with export-state"
                            )
                        try:
                            marker_uidvalidity = _legacy_uidvalidity_metadata(
                                marker,
                                f"{account.email}:{path}: mailbox marker",
                            )
                        except RuntimeError as exc:
                            issues.append(str(exc))
                        else:
                            if marker_uidvalidity != state_uidvalidity:
                                issues.append(
                                    f"{account.email}:{path}: mailbox marker uidvalidity mismatch with export-state"
                                )
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
    if eml_path.is_symlink():
        return [f"{eml_path}: message file is a symlink"]
    try:
        data = _read_staged_artifact(eml_path, "legacy message file")
    except Exception as exc:
        return [f"{eml_path}: failed to read: {exc}"]
    if not data:
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
    stop_event: Optional[object] = None,
) -> Tuple[str, List[str]]:
    """Audit a single account directory and optionally compare to remote counts."""
    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
    issues: List[str] = []
    remote_safe = True
    account_dir = in_root / sanitize_for_path(account.email)
    if account_dir.is_symlink():
        issues.append(f"{account.email}: account directory is a symlink: {account_dir}")
        return account.email, issues
    if not account_dir.exists():
        issues.append(f"account directory missing: {account_dir}")
        return account.email, issues
    if not account_dir.is_dir():
        issues.append(f"{account.email}: account path is not a directory: {account_dir}")
        return account.email, issues
    provider_manifest = account_dir / "manifest.jsonl"
    if provider_manifest.exists() or provider_manifest.is_symlink():
        issues.append(f"{account.email}: provider manifest present in legacy account directory: {provider_manifest}")
        remote_safe = False
    folder_dirs: List[Path] = []
    for child in account_dir.iterdir():
        _raise_if_stopped(stop_event, f"legacy audit {account.email}")
        if child.is_symlink():
            issues.append(f"{account.email}:{child.name}: mailbox path is a symlink")
            remote_safe = False
            continue
        if child.is_dir():
            reserved_issue = legacy_reserved_mailbox_path_issue(child.name, child.name)
            if reserved_issue is not None:
                issues.append(f"{account.email}:{child.name}: {reserved_issue}")
                remote_safe = False
            folder_dirs.append(child)
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
        _raise_if_stopped(stop_event, f"legacy audit {account.email}")
        folder = folder_dir.name
        emls = list(folder_dir.glob("*.eml"))
        jsons = [p for p in folder_dir.glob("*.json") if p.name != ".mailbox.json"]
        mailbox_marker = folder_dir / ".mailbox.json"
        mailbox_marker_present = mailbox_marker.exists() or mailbox_marker.is_symlink()
        marker_mailbox: Optional[str] = None
        marker_hierarchy: Tuple[str, Tuple[str, ...]] = ("", ())
        marker_uidvalidity = ""
        folder_uidvalidity: Optional[str] = None
        if not emls and not mailbox_marker.exists():
            issues.append(f"{account.email}:{folder}: no .eml files found")
        if mailbox_marker.is_symlink():
            issues.append(f"{account.email}:{folder}: mailbox marker is a symlink")
            remote_safe = False
        elif mailbox_marker.exists():
            try:
                marker = json.loads(_read_staged_artifact(mailbox_marker, "legacy mailbox marker").decode("utf-8"))
                expected_count = marker.get("message_count") if isinstance(marker, dict) else None
                if type(expected_count) is not int or expected_count < 0:
                    issues.append(f"{account.email}:{folder}: mailbox marker has invalid message_count")
                elif expected_count != len(emls):
                    issues.append(f"{account.email}:{folder}: mailbox marker count mismatch (marker={expected_count} eml={len(emls)})")
                mailbox_name = marker.get("mailbox") if isinstance(marker, dict) else None
                if not isinstance(mailbox_name, str) or not mailbox_name.strip():
                    issues.append(f"{account.email}:{folder}: mailbox marker missing mailbox")
                elif sanitize_for_path(mailbox_name) != folder:
                    issues.append(f"{account.email}:{folder}: mailbox marker name mismatch (marker={mailbox_name})")
                else:
                    marker_mailbox = mailbox_name
                    try:
                        marker_hierarchy = _legacy_hierarchy_metadata(
                            marker,
                            marker_mailbox,
                            f"{account.email}:{folder}: mailbox marker",
                        )
                    except RuntimeError as exc:
                        issues.append(str(exc))
                    try:
                        marker_uidvalidity = _legacy_uidvalidity_metadata(
                            marker,
                            f"{account.email}:{folder}: mailbox marker",
                        )
                    except RuntimeError as exc:
                        issues.append(str(exc))
                    else:
                        if marker_uidvalidity:
                            folder_uidvalidity = marker_uidvalidity
            except Exception as exc:
                issues.append(f"{account.email}:{folder}: failed to parse mailbox marker: {exc}")
                remote_safe = False
        eml_stems = {p.stem for p in emls}
        json_stems = {p.stem for p in jsons}
        missing_meta = eml_stems - json_stems
        missing_eml = json_stems - eml_stems
        if missing_meta:
            issues.append(f"{account.email}:{folder}: {len(missing_meta)} message(s) missing .json metadata")
        if missing_eml:
            issues.append(f"{account.email}:{folder}: {len(missing_eml)} metadata file(s) without .eml counterpart")
        symlink_jsons = {p for p in jsons if p.is_symlink()}
        for json_path in sorted(symlink_jsons):
            _raise_if_stopped(stop_event, f"legacy audit {account.email}")
            issues.append(f"{account.email}:{folder}:{json_path.name}: message metadata is a symlink")
            remote_safe = False
        for eml_path in emls:
            _raise_if_stopped(stop_event, f"legacy audit {account.email}")
            eml_is_symlink = eml_path.is_symlink()
            if eml_is_symlink:
                remote_safe = False
            issues.extend(_audit_eml_file(eml_path, folder))
            stem = eml_path.stem
            meta_path = eml_path.with_suffix(".json")
            if not meta_path.exists():
                continue
            if meta_path.is_symlink():
                if meta_path not in symlink_jsons:
                    issues.append(f"{account.email}:{folder}:{meta_path.name}: message metadata is a symlink")
                continue
            try:
                meta = json.loads(_read_staged_artifact(meta_path, "legacy message metadata").decode("utf-8"))
            except Exception as exc:
                issues.append(f"{account.email}:{folder}:{eml_path.name}: failed to parse message metadata: {exc}")
                continue
            if not isinstance(meta, dict):
                issues.append(f"{account.email}:{folder}:{eml_path.name}: message metadata is not an object")
                continue
            account_meta = meta.get("account")
            if not isinstance(account_meta, str) or not account_meta.strip():
                if require_integrity_metadata:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: missing account metadata")
            elif account_meta != account.email:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: account metadata mismatch "
                    f"(account={account.email} meta={account_meta})"
                )
            mailbox_meta = meta.get("mailbox")
            if not isinstance(mailbox_meta, str) or not mailbox_meta.strip():
                issues.append(f"{account.email}:{folder}:{eml_path.name}: missing mailbox metadata")
            elif sanitize_for_path(mailbox_meta) != folder:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: mailbox metadata mismatch "
                    f"(folder={folder} meta={mailbox_meta})"
                )
            elif marker_mailbox is not None and mailbox_meta != marker_mailbox:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: mailbox metadata mismatch "
                    f"(marker={marker_mailbox} meta={mailbox_meta})"
                )
            elif not mailbox_marker_present and mailbox_meta != folder:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: missing mailbox marker "
                    f"for original mailbox {mailbox_meta}"
                )
            if isinstance(mailbox_meta, str) and mailbox_meta.strip():
                try:
                    message_hierarchy = _legacy_hierarchy_metadata(
                        meta,
                        mailbox_meta,
                        f"{account.email}:{folder}:{eml_path.name}",
                    )
                except RuntimeError as exc:
                    issues.append(str(exc))
                    message_hierarchy = ("", ())
                else:
                    if marker_mailbox is not None and message_hierarchy != marker_hierarchy:
                        issues.append(
                            f"{account.email}:{folder}:{eml_path.name}: "
                            "source_path_segments mismatch with mailbox marker"
                        )
            try:
                message_uidvalidity = _legacy_uidvalidity_metadata(
                    meta,
                    f"{account.email}:{folder}:{eml_path.name}",
                )
            except RuntimeError as exc:
                issues.append(str(exc))
                message_uidvalidity = ""
            if marker_mailbox is not None and message_uidvalidity != marker_uidvalidity:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: uidvalidity mismatch with mailbox marker"
                )
            elif folder_uidvalidity is None:
                folder_uidvalidity = message_uidvalidity
            elif message_uidvalidity != folder_uidvalidity:
                issues.append(
                    f"{account.email}:{folder}:{eml_path.name}: uidvalidity mismatch within mailbox"
                )
            if stem.startswith("u") and stem[1:].isdigit():
                uid_in_name = int(stem[1:])
                uid_meta = meta.get("uid")
                if "uid" in meta and type(uid_meta) is not int:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: invalid uid metadata")
                elif isinstance(uid_meta, int) and uid_meta != uid_in_name:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: uid mismatch (name={uid_in_name} meta={uid_meta})")
            try:
                _validate_legacy_delivery_metadata(meta, f"{account.email}:{folder}:{eml_path.name}")
            except RuntimeError as exc:
                issues.append(str(exc))
            integrity_keys_present = any(key in meta for key in ("content_sha256", "rfc822_size", CONTENT_BINDING_FIELD))
            if require_integrity_metadata or integrity_keys_present:
                expected_hash_raw = meta.get("content_sha256")
                expected_size_raw = meta.get("rfc822_size")
                expected_hash: Optional[str] = None
                expected_size: Optional[int] = None
                if expected_hash_raw is None:
                    if require_integrity_metadata:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: missing content_sha256 metadata")
                elif not isinstance(expected_hash_raw, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash_raw):
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: invalid content_sha256 metadata")
                else:
                    expected_hash = expected_hash_raw.lower()
                if expected_size_raw is None:
                    if require_integrity_metadata:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: missing rfc822_size metadata")
                elif type(expected_size_raw) is not int or expected_size_raw < 0:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: invalid rfc822_size metadata")
                else:
                    expected_size = expected_size_raw
                binding_issue = legacy_content_binding_issue(meta, required=require_integrity_metadata)
                if binding_issue:
                    issues.append(f"{account.email}:{folder}:{eml_path.name}: {binding_issue}")
                if not eml_is_symlink and (expected_hash is not None or expected_size is not None):
                    try:
                        data = _read_staged_artifact(eml_path, "legacy message file")
                        if expected_hash is not None and hashlib.sha256(data).hexdigest() != expected_hash:
                            issues.append(f"{account.email}:{folder}:{eml_path.name}: content_sha256 mismatch")
                        if expected_size is not None and len(data) != expected_size:
                            issues.append(
                                f"{account.email}:{folder}:{eml_path.name}: rfc822_size mismatch "
                                f"(metadata={expected_size} actual={len(data)})"
                            )
                    except Exception as exc:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: failed integrity read: {exc}")
    if check_remote and server is not None and remote_safe:
        try:
            _raise_if_stopped(stop_event, f"legacy audit {account.email}")
            with imap_connection(server, account) as imap:
                remote_entries = _list_selectable_mailbox_entries(imap)
                remote_mailboxes = [
                    name
                    for name, attrs in remote_entries
                    if not _should_skip_legacy_source_view(name, attrs, remote_entries)
                ]
                remote_counts: Dict[str, int] = {}
                remote_mailbox_by_key: Dict[str, Tuple[str, str]] = {}
                remote_mailbox_by_path: Dict[str, str] = {}
                remote_attrs_by_path: Dict[str, Tuple[str, ...]] = {
                    canonical_mailbox_path_key(name): attrs
                    for name, attrs in remote_entries
                }
                count_mismatched = set()
                for mbox in remote_mailboxes:
                    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                    status, _ = imap.select(quote_mailbox_name(mbox), readonly=True)
                    path = canonical_mailbox_path_key(mbox)
                    key = canonical_mailbox_alias_key(mbox)
                    if status != "OK":
                        count_mismatched.add(path)
                        issues.append(f"{account.email}:{path}: remote mailbox could not be selected: {mbox!r}")
                        continue
                    status, data = imap.uid("search", "ALL")
                    if status != "OK":
                        count_mismatched.add(path)
                        issues.append(f"{account.email}:{path}: remote mailbox UID search failed: {mbox!r}")
                        continue
                    num = len((data[0] or b"").split()) if data else 0
                    previous = remote_mailbox_by_key.get(key)
                    if (
                        previous is not None
                        and canonical_imap_mailbox_name(previous[0])
                        != canonical_imap_mailbox_name(mbox)
                    ):
                        count_mismatched.update({previous[1], path})
                        issues.append(
                            f"{account.email}:{key}: remote mailbox name collision after sanitizing: "
                            f"{previous[0]!r} -> {previous[1]!r} and {mbox!r} -> {path!r} "
                            "alias on case-insensitive filesystems"
                        )
                        continue
                    remote_counts[path] = num
                    remote_mailbox_by_key[key] = (mbox, path)
                    remote_mailbox_by_path[path] = mbox
                identity_candidates: List[Tuple[Path, str, str, bytes, str]] = []
                local_content_identity_slots: List[Set[Tuple[int, str]]] = []
                local_folder_info: Dict[str, Tuple[str, int]] = {}
                for folder_dir in folder_dirs:
                    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                    folder = canonical_mailbox_path_key(folder_dir.name)
                    if folder_dir.is_symlink():
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: mailbox path is a symlink")
                        continue
                    if not folder_dir.is_dir():
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: mailbox path is not a directory")
                        continue
                    local_mailbox = _folder_mailbox_name(folder_dir)
                    eml_paths = sorted(folder_dir.glob("*.eml"))
                    local_count = len(eml_paths)
                    local_folder_info[folder] = (local_mailbox, local_count)
                    for eml_path in eml_paths:
                        _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                        if eml_path.is_symlink():
                            continue
                        try:
                            data, expected_flags = _read_bound_legacy_message(
                                eml_path,
                                require_integrity_metadata=require_integrity_metadata,
                            )
                        except Exception as exc:
                            issues.append(f"{account.email}:{folder}:{eml_path.name}: remote identity check failed: {exc}")
                            continue
                        local_content_identity_slots.append(_content_identity_variants(data))
                        identity_candidates.append((eml_path, folder, local_mailbox, data, expected_flags))
                for folder, (local_mailbox, local_count) in local_folder_info.items():
                    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                    remote_count = remote_counts.get(folder, -1)
                    remote_mailbox = remote_mailbox_by_path.get(folder)
                    if remote_count < 0:
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: missing remotely or not selectable but local has {local_count} messages")
                    elif remote_count >= 0 and local_count != remote_count:
                        remote_attrs = remote_attrs_by_path.get(folder, ())
                        if (
                            _is_legacy_virtual_source_attrs(remote_attrs)
                            and _remote_mailbox_content_covered(
                                imap,
                                remote_mailbox or local_mailbox,
                                local_content_identity_slots,
                            )
                        ):
                            continue
                        count_mismatched.add(folder)
                        issues.append(f"{account.email}:{folder}: local={local_count} remote={remote_count} mismatch")
                    elif (
                        remote_mailbox is not None
                        and canonical_imap_mailbox_name(remote_mailbox)
                        != canonical_imap_mailbox_name(local_mailbox)
                    ):
                        count_mismatched.add(folder)
                        issues.append(
                            f"{account.email}:{folder}: remote mailbox name mismatch for sanitized path "
                            f"(local={local_mailbox!r} remote={remote_mailbox!r})"
                        )
                for folder_name, rcount in remote_counts.items():
                    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                    if folder_name not in local_folder_info:
                        attrs = remote_attrs_by_path.get(folder_name, ())
                        remote_mailbox = remote_mailbox_by_path.get(folder_name, folder_name)
                        if (
                            rcount >= 0
                            and _is_legacy_virtual_source_attrs(attrs)
                            and _remote_mailbox_content_covered(imap, remote_mailbox, local_content_identity_slots)
                        ):
                            continue
                        count_mismatched.add(folder_name)
                        issues.append(f"{account.email}:{folder_name}: missing locally but remote has {rcount} messages")
                used_remote_nums_by_folder: Dict[str, Set[bytes]] = {}
                for eml_path, folder, mailbox, data, expected_flags in identity_candidates:
                    _raise_if_stopped(stop_event, f"legacy audit {account.email}")
                    if folder in count_mismatched:
                        continue
                    try:
                        used_remote_nums = used_remote_nums_by_folder.setdefault(folder, set())
                        if not _remote_has_message(imap, mailbox, data, used_remote_nums, expected_flags):
                            issues.append(f"{account.email}:{folder}:{eml_path.name}: remote message identity missing")
                    except Exception as exc:
                        issues.append(f"{account.email}:{folder}:{eml_path.name}: remote identity check failed: {exc}")
        except Exception as exc:
            if _stop_requested(stop_event):
                raise
            issues.append(f"remote check failed: {exc}")
    return account.email, issues


def audit_export(
    in_root: Path,
    config: Config,
    max_workers: int,
    check_remote: bool = True,
    *,
    require_integrity_metadata: bool = False,
    stop_event: Optional[object] = None,
) -> Tuple[bool, List[str]]:
    """Audit all accounts concurrently and aggregate issues.

    Returns (ok, issues) where `ok` is True when no issues were found.
    """
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    _raise_if_stopped(stop_event, "legacy audit")
    if _legacy_symlink_component(in_root) is not None:
        return False, [f"audit root is a symlink: {in_root}"]
    issues_accum: List[str] = []
    expected_source_server = config.source_server if config.source_server is not None else None
    if expected_source_server is None and not require_integrity_metadata:
        expected_source_server = config.server
    remote_server = config.source_server or config.server

    def worker(acc: Account) -> List[str]:
        _raise_if_stopped(stop_event, f"legacy audit {acc.email}")
        _email, issues = audit_account(
            acc,
            in_root,
            remote_server if check_remote else None,
            check_remote=check_remote,
            require_integrity_metadata=require_integrity_metadata,
            expected_source_server=expected_source_server,
            stop_event=stop_event,
        )
        _raise_if_stopped(stop_event, f"legacy audit {acc.email}")
        if not issues:
            return []
        return [f"{acc.email}: {msg}" if not msg.startswith(acc.email) else msg for msg in issues]

    results: List[List[str]] = []
    account_iter = iter(config.accounts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit") as ex:
        futures: Dict[concurrent.futures.Future[List[str]], Account] = {}

        def submit_next() -> bool:
            if _stop_requested(stop_event):
                return False
            try:
                acc = next(account_iter)
            except StopIteration:
                return False
            futures[ex.submit(worker, acc)] = acc
            return True

        def cancel_and_drain_pending() -> None:
            for pending in futures:
                pending.cancel()
            for fut in concurrent.futures.as_completed(list(futures)):
                try:
                    fut.result()
                except concurrent.futures.CancelledError:
                    pass
            futures.clear()

        for _ in range(min(max_workers, len(config.accounts))):
            submit_next()

        wait_timeout = 0.2 if stop_event is not None else None
        while futures:
            if _stop_requested(stop_event):
                cancel_and_drain_pending()
                _raise_if_stopped(stop_event, "legacy audit")
            done, _pending = concurrent.futures.wait(
                futures,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            completed_successfully = 0
            for fut in done:
                futures.pop(fut, None)
                try:
                    results.append(fut.result())
                except Exception:
                    cancel_and_drain_pending()
                    raise
                else:
                    completed_successfully += 1
            if _stop_requested(stop_event):
                cancel_and_drain_pending()
                _raise_if_stopped(stop_event, "legacy audit")
            for _ in range(completed_successfully):
                submit_next()
    _raise_if_stopped(stop_event, "legacy audit")
    for lst in results:
        if lst:
            issues_accum.extend(lst)
    ok = len(issues_accum) == 0
    return ok, issues_accum
