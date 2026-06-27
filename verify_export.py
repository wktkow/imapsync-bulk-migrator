#!/usr/bin/env python3
"""
Export verification script - checks exported emails for completeness,
including attachments, message integrity, and folder structure.
"""

import json
import hashlib
import os
import sys
from pathlib import Path
from email.parser import BytesParser
from email.policy import default as default_policy
import re

from components.content_binding import legacy_content_binding_issue, provider_content_binding_issue
from components.imap_ops import _valid_legacy_flag_token, _valid_legacy_internaldate
from components.provider_ops import (
    _manifest_path,
    _provider_artifact_orphan_issues,
    load_manifest,
    manifest_integrity_issues,
    manifest_payload_issues,
    manifest_schema_issues,
    metadata_manifest_issues,
    provider_delivery_metadata_issues,
    provider_export_state_issues,
)
from components.utils import sanitize_for_path, sanitized_path_key


def _has_later_rfc822_header_block(msg_text):
    lines = msg_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    try:
        first_blank = next(idx for idx, line in enumerate(lines) if line == '')
    except StopIteration:
        return False
    idx = first_blank + 1
    while idx < len(lines):
        line = lines[idx]
        if not re.match(r'^(?:Return-Path|Message-ID):', line, flags=re.IGNORECASE):
            idx += 1
            continue
        context = '\n'.join(lines[max(first_blank + 1, idx - 3):idx]).lower()
        if 'forwarded' in context:
            idx += 1
            continue
        header_names = set()
        end = idx
        while end < len(lines) and lines[end] != '':
            match = re.match(r'^([A-Za-z][A-Za-z0-9-]*):', lines[end])
            if match:
                header_names.add(match.group(1).lower())
            end += 1
        if 'message-id' in header_names and (
            'return-path' in header_names
            or 'from' in header_names
            or 'to' in header_names
            or 'date' in header_names
        ):
            return True
        idx = max(end + 1, idx + 1)
    return False


def _starts_with_rfc822_header_block(msg_text):
    lines = msg_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    idx = 0
    while idx < len(lines) and lines[idx] == '':
        idx += 1
    header_names = set()
    while idx < len(lines) and lines[idx] != '':
        match = re.match(r'^([A-Za-z][A-Za-z0-9-]*):', lines[idx])
        if match:
            header_names.add(match.group(1).lower())
        elif not lines[idx].startswith((' ', '\t')):
            return False
        idx += 1
    return 'message-id' in header_names and (
        'return-path' in header_names
        or 'from' in header_names
        or 'to' in header_names
        or 'date' in header_names
    )


def _decoded_text_payload(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload if isinstance(raw_payload, str) else ''
    charset = part.get_content_charset() or 'utf-8'
    try:
        return payload.decode(charset, errors='ignore')
    except LookupError:
        return payload.decode('utf-8', errors='ignore')


def _non_encapsulated_text_has_rfc822_header_block(part):
    if part.get_content_type() == 'message/rfc822':
        return False
    if part.is_multipart():
        return any(_non_encapsulated_text_has_rfc822_header_block(child) for child in part.iter_parts())
    if part.get_content_maintype() != 'text':
        return False
    return _has_later_rfc822_header_block('\n\n' + _decoded_text_payload(part))


def analyze_message(
    eml_path,
    json_path,
    *,
    require_metadata=True,
    folder_name=None,
    expected_account=None,
    content_binding="legacy",
    mailbox_marker_present=True,
    mailbox_marker_mailbox=None,
):
    """Analyze a single exported message"""
    try:
        eml_path = Path(eml_path)
        json_path = Path(json_path)
        if eml_path.is_symlink():
            return None, 'message file is a symlink'
        # Read the email
        with open(eml_path, 'rb') as f:
            msg_bytes = f.read()
        if not msg_bytes and content_binding != "provider":
            return None, 'empty file'
        
        # Check for multiple messages concatenated (look for multiple RFC822 headers).
        # Only count headers in the top-level header block (before the first blank line)
        # to avoid false positives from forwarded/attached messages in the body.
        msg_text = msg_bytes.decode('utf-8', errors='ignore').replace('\r\n', '\n')
        header_section = msg_text.split('\n\n', 1)[0] if '\n\n' in msg_text else msg_text
        return_path_count = len(re.findall(r'(?im)^Return-Path:', header_section))
        message_id_count = len(re.findall(r'(?im)^Message-ID:', header_section))
        
        # Parse the email
        msg = BytesParser(policy=default_policy).parsebytes(msg_bytes)
        parts = list(msg.walk()) if msg.is_multipart() else [msg]
        has_encapsulated_rfc822 = any(part.get_content_type() == 'message/rfc822' for part in parts)
        later_rfc822_header_block = _has_later_rfc822_header_block(msg_text)
        if has_encapsulated_rfc822:
            later_rfc822_header_block = (
                _starts_with_rfc822_header_block(msg.epilogue or '')
                or _non_encapsulated_text_has_rfc822_header_block(msg)
            )
        
        # Read metadata
        if not json_path.exists():
            if require_metadata:
                return None, 'missing metadata sidecar'
            metadata = {}
        elif json_path.is_symlink():
            return None, 'metadata sidecar is a symlink'
        else:
            with open(json_path, 'r') as f:
                metadata = json.load(f)
            if not isinstance(metadata, dict):
                return None, 'metadata json is not an object'
        
        integrity_errors = []
        expected_hash = metadata.get('content_sha256')
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_hash):
                integrity_errors.append('invalid content_sha256 metadata')
            else:
                actual_hash = hashlib.sha256(msg_bytes).hexdigest()
                if actual_hash != expected_hash.lower():
                    integrity_errors.append('content_sha256 mismatch')
        elif require_metadata:
            integrity_errors.append('missing content_sha256 metadata')
        expected_size = metadata.get('rfc822_size')
        if expected_size is not None:
            min_size = 0 if content_binding == "provider" else 1
            if type(expected_size) is not int or expected_size < min_size:
                integrity_errors.append('invalid rfc822_size metadata')
            elif len(msg_bytes) != expected_size:
                integrity_errors.append(f'rfc822_size mismatch (metadata={expected_size} actual={len(msg_bytes)})')
        elif require_metadata:
            integrity_errors.append('missing rfc822_size metadata')
        if content_binding == "provider":
            binding_issue = provider_content_binding_issue(metadata, required=require_metadata)
        else:
            binding_issue = legacy_content_binding_issue(metadata, required=require_metadata)
        if binding_issue:
            integrity_errors.append(binding_issue)
        if content_binding == "legacy" and expected_account is not None:
            account_meta = metadata.get('account')
            if not isinstance(account_meta, str) or not account_meta.strip():
                integrity_errors.append('missing account metadata')
            elif account_meta != expected_account:
                integrity_errors.append(f'account metadata mismatch (account={expected_account} meta={account_meta})')
        if 'uid' in metadata:
            uid = metadata.get('uid')
            if type(uid) is not int:
                integrity_errors.append('invalid uid metadata')
            else:
                stem = Path(eml_path).stem
                if stem.startswith('u') and stem[1:].isdigit() and uid != int(stem[1:]):
                    integrity_errors.append(f'uid mismatch (name={int(stem[1:])} meta={uid})')
        if 'flags' in metadata:
            flags = metadata.get('flags')
            if not isinstance(flags, str):
                integrity_errors.append('invalid flags metadata')
            elif any(not _valid_legacy_flag_token(token) for token in flags.split()):
                integrity_errors.append('invalid flags metadata')
        if 'internaldate' in metadata:
            internaldate = metadata.get('internaldate')
            if not isinstance(internaldate, str):
                integrity_errors.append('invalid internaldate metadata')
            elif internaldate.strip():
                stripped = internaldate.strip()
                parse_value = stripped[1:-1] if stripped.startswith('"') and stripped.endswith('"') else stripped
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in parse_value):
                    integrity_errors.append('invalid internaldate metadata')
                elif not _valid_legacy_internaldate(parse_value):
                    integrity_errors.append('invalid internaldate metadata')
        if folder_name is not None:
            if 'mailbox' not in metadata:
                integrity_errors.append('missing mailbox metadata')
            else:
                mailbox = metadata.get('mailbox')
                if not isinstance(mailbox, str) or not mailbox.strip():
                    integrity_errors.append('missing mailbox metadata')
                elif sanitize_for_path(mailbox) != folder_name:
                    integrity_errors.append(f'mailbox metadata mismatch (folder={folder_name} meta={mailbox})')
                elif mailbox_marker_mailbox is not None and mailbox != mailbox_marker_mailbox:
                    integrity_errors.append(f'mailbox metadata mismatch (marker={mailbox_marker_mailbox} meta={mailbox})')
                elif not mailbox_marker_present and mailbox != folder_name:
                    integrity_errors.append(f'missing mailbox marker for original mailbox {mailbox}')
        if integrity_errors:
            return None, '; '.join(integrity_errors)

        # Analyze message
        analysis = {
            'size_bytes': len(msg_bytes),
            'has_attachments': False,
            'attachment_count': 0,
            'attachment_names': [],
            'is_multipart': msg.is_multipart(),
            'subject': msg.get('Subject', ''),
            'from': msg.get('From', ''),
            'date': msg.get('Date', ''),
            'flags': metadata.get('flags', ''),
            'mailbox': metadata.get('mailbox', ''),
            'content_types': [],
            'multiple_messages_detected': (
                return_path_count > 1
                or message_id_count > 1
                or later_rfc822_header_block
            ),
            'return_path_count': return_path_count,
            'message_id_count': message_id_count
        }
        
        # Check for attachments and content types
        if msg.is_multipart():
            for part in parts:
                content_type = part.get_content_type()
                analysis['content_types'].append(content_type)
                
                # Check if it's an attachment
                disposition = part.get('Content-Disposition', '')
                if 'attachment' in disposition or part.get_filename():
                    analysis['has_attachments'] = True
                    analysis['attachment_count'] += 1
                    filename = part.get_filename() or 'unnamed'
                    analysis['attachment_names'].append(filename)
        else:
            analysis['content_types'].append(msg.get_content_type())
        
        return analysis, None
        
    except Exception as e:
        return None, str(e)


def analyze_mailbox_marker(marker_path, folder_name, eml_count):
    if Path(marker_path).is_symlink():
        return [f"{folder_name}: mailbox marker is a symlink"]
    try:
        with open(marker_path, 'r') as f:
            marker = json.load(f)
    except Exception as e:
        return [f"{folder_name}: failed to parse mailbox marker: {e}"]
    if not isinstance(marker, dict):
        return [f"{folder_name}: mailbox marker json is not an object"]
    issues = []
    mailbox = marker.get('mailbox')
    if not isinstance(mailbox, str) or not mailbox.strip():
        issues.append(f"{folder_name}: mailbox marker missing mailbox")
    elif sanitize_for_path(mailbox) != folder_name:
        issues.append(f"{folder_name}: mailbox marker name mismatch (marker={mailbox})")
    message_count = marker.get('message_count')
    if type(message_count) is not int or message_count < 0:
        issues.append(f"{folder_name}: mailbox marker has invalid message_count")
    elif message_count != eml_count:
        issues.append(f"{folder_name}: mailbox marker count mismatch (marker={message_count} eml={eml_count})")
    return issues


def analyze_export_state(account_path, folder_counts):
    state_path = account_path / "export-state.json"
    if state_path.is_symlink():
        return ["export-state is a symlink"]
    if not state_path.exists():
        return ["export-state missing"]
    try:
        with open(state_path, 'r') as f:
            state = json.load(f)
    except Exception as e:
        return [f"export-state failed to parse: {e}"]
    if not isinstance(state, dict):
        return ["export-state json is not an object"]

    issues = []
    if state.get("complete") is not True:
        issues.append("export-state is not complete")
    account = state.get("account")
    if not isinstance(account, str) or (account != account_path.name and sanitize_for_path(account) != account_path.name):
        issues.append(f"export-state account mismatch (state={account!r} path={account_path.name!r})")
    mailboxes = state.get("mailboxes")
    if not isinstance(mailboxes, list):
        issues.append("export-state mailboxes is not a list")
        return issues

    seen_paths = {}
    state_paths = set()
    for idx, entry in enumerate(mailboxes, 1):
        if not isinstance(entry, dict):
            issues.append(f"export-state mailbox entry {idx} is not an object")
            continue
        mailbox = entry.get("mailbox")
        path = entry.get("path")
        message_count = entry.get("message_count")
        label = mailbox if isinstance(mailbox, str) and mailbox else f"entry {idx}"
        if not isinstance(mailbox, str) or not mailbox.strip():
            issues.append(f"export-state mailbox {idx} missing mailbox")
        if not isinstance(path, str) or not path.strip():
            issues.append(f"export-state mailbox {label!r} missing path")
            continue
        path_key = sanitized_path_key(path)
        previous_path = seen_paths.get(path_key)
        if previous_path is not None:
            issues.append(f"export-state mailbox path collision: {previous_path} and {path}")
            continue
        seen_paths[path_key] = path
        state_paths.add(path)
        if isinstance(mailbox, str) and mailbox.strip() and sanitize_for_path(mailbox) != path:
            issues.append(f"export-state mailbox {mailbox!r} path mismatch (path={path})")
        if type(message_count) is not int or message_count < 0:
            issues.append(f"export-state mailbox {label!r} has invalid message_count")
        elif path in folder_counts and message_count != folder_counts[path]:
            issues.append(
                f"export-state mailbox {label!r} count mismatch "
                f"(state={message_count} eml={folder_counts[path]})"
            )
        if path not in folder_counts:
            issues.append(f"export-state mailbox {label!r} path missing from folders: {path}")

    for folder_name in sorted(set(folder_counts) - state_paths):
        issues.append(f"export-state missing mailbox folder: {folder_name}")
    return issues


def expected_legacy_account_for_sidecars(account_path):
    state_path = account_path / "export-state.json"
    if state_path.is_symlink() or not state_path.exists():
        return account_path.name
    try:
        with open(state_path, 'r') as f:
            state = json.load(f)
    except Exception:
        return account_path.name
    if not isinstance(state, dict):
        return account_path.name
    account = state.get("account")
    if isinstance(account, str) and account and (
        account == account_path.name or sanitize_for_path(account) == account_path.name
    ):
        return account
    return account_path.name


def provider_account_directory_binding_issues(account_path, rows):
    account_name = account_path.name

    def matches_directory(value):
        return isinstance(value, str) and value and (
            value == account_name or sanitize_for_path(value) == account_name
        )

    issues = []
    for idx, row in enumerate(rows, 1):
        identity = str(row.get("canonical_id") or f"row {idx}")
        source_account = row.get("source_account")
        if not matches_directory(source_account):
            label = source_account if isinstance(source_account, str) and source_account else "<missing>"
            issues.append(
                f"{identity}: source_account {label} does not match provider account directory {account_name}"
            )

    state_path = account_path / "export-state.json"
    if state_path.exists() and not state_path.is_symlink():
        try:
            with open(state_path, 'r') as f:
                state = json.load(f)
        except Exception:
            state = None
        if isinstance(state, dict) and "source_account" in state and not matches_directory(state.get("source_account")):
            label = state.get("source_account")
            label = label if isinstance(label, str) and label else "<missing>"
            issues.append(
                f"export-state source_account {label} does not match provider account directory {account_name}"
            )
    return issues


def verify_provider_account(account_path):
    """Verify a provider-layout account export."""
    account_name = account_path.name
    print(f"\n=== Verifying {account_name} (provider layout) ===")

    errors = []
    total_messages = 0
    total_with_attachments = 0
    total_attachments = 0
    multiple_message_files = []
    provider_mailboxes = set()

    try:
        rows = load_manifest(account_path)
    except Exception as exc:
        errors.append(f"manifest load failed: {exc}")
        rows = []

    if rows:
        errors.extend(provider_account_directory_binding_issues(account_path, rows))
        errors.extend(provider_export_state_issues(account_path, manifest_rows=rows))
        errors.extend(manifest_schema_issues(rows))
        errors.extend(manifest_integrity_issues(rows))
        errors.extend(provider_delivery_metadata_issues(rows))
        errors.extend(metadata_manifest_issues(account_path, rows))
        errors.extend(manifest_payload_issues(account_path, rows))
        errors.extend(_provider_artifact_orphan_issues(account_path, rows))
    else:
        errors.extend(provider_export_state_issues(account_path, manifest_rows=[]))
        errors.extend(_provider_artifact_orphan_issues(account_path, []))

    for row in rows:
        identity = str(row.get("canonical_id") or "<missing>")
        if row.get("primary_mailbox"):
            provider_mailboxes.add(str(row.get("primary_mailbox")))
        try:
            eml_path = _manifest_path(account_path, row, "eml_path")
            metadata_path = _manifest_path(account_path, row, "metadata_path")
        except Exception as exc:
            errors.append(f"{identity}: invalid provider paths: {exc}")
            continue
        if not eml_path.exists() or not metadata_path.exists():
            continue

        analysis, error = analyze_message(
            eml_path,
            metadata_path,
            content_binding="provider",
        )
        if error:
            errors.append(f"{identity}: {error}")
            continue
        total_messages += 1
        if analysis["has_attachments"]:
            total_with_attachments += 1
            total_attachments += analysis["attachment_count"]
        if analysis["multiple_messages_detected"]:
            multiple_message_files.append(
                f"{row.get('eml_path')} (Return-Path: {analysis['return_path_count']}, "
                f"Message-ID: {analysis['message_id_count']})"
            )

    print(f"Total messages: {total_messages}")
    print(f"Messages with attachments: {total_with_attachments}")
    print(f"Total attachments: {total_attachments}")

    if multiple_message_files:
        print(f"\n🚨 CRITICAL: {len(multiple_message_files)} files contain multiple messages!")
        for file_info in multiple_message_files[:10]:
            print(f"  {file_info}")
        if len(multiple_message_files) > 10:
            print(f"  ... and {len(multiple_message_files) - 10} more files")

    if errors:
        print(f"\n⚠️  {len(errors)} errors found:")
        for error in errors[:10]:
            print(f"  {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")

    return {
        'account': account_name,
        'total_messages': total_messages,
        'messages_with_attachments': total_with_attachments,
        'total_attachments': total_attachments,
        'folders': len(provider_mailboxes),
        'errors': len(errors),
        'multiple_message_files': len(multiple_message_files)
    }


def verify_account(account_path):
    """Verify all messages in an account"""
    if account_path.is_symlink():
        account_name = account_path.name
        print(f"\n=== Verifying {account_name} ===")
        print(f"\n⚠️  1 errors found:")
        print(f"  account path is a symlink: {account_path}")
        return {
            'account': account_name,
            'total_messages': 0,
            'messages_with_attachments': 0,
            'total_attachments': 0,
            'folders': 0,
            'errors': 1,
            'multiple_message_files': 0,
        }
    if (account_path / "manifest.jsonl").exists():
        return verify_provider_account(account_path)

    account_name = account_path.name
    expected_account = expected_legacy_account_for_sidecars(account_path)
    print(f"\n=== Verifying {account_name} ===")
    
    total_messages = 0
    total_with_attachments = 0
    total_attachments = 0
    errors = []
    folder_stats = {}
    multiple_message_files = []
    mailbox_folders_found = 0
    folder_counts = {}
    
    # Walk through all folders
    for folder_path in account_path.iterdir():
        if folder_path.is_symlink():
            errors.append(f"{folder_path.name}: mailbox path is a symlink")
            continue
        if not folder_path.is_dir():
            continue
        mailbox_folders_found += 1
            
        folder_name = folder_path.name
        folder_messages = 0
        folder_attachments = 0
        folder_errors = 0
        mailbox_marker = folder_path / ".mailbox.json"
        mailbox_marker_present = mailbox_marker.exists() or mailbox_marker.is_symlink()
        mailbox_marker_mailbox = None
        if mailbox_marker.exists() and not mailbox_marker.is_symlink():
            try:
                marker = json.loads(mailbox_marker.read_text(encoding="utf-8"))
                mailbox = marker.get("mailbox") if isinstance(marker, dict) else None
                if isinstance(mailbox, str) and mailbox.strip() and sanitize_for_path(mailbox) == folder_name:
                    mailbox_marker_mailbox = mailbox
            except Exception:
                pass
        
        # Process all .eml files in folder
        eml_files = list(folder_path.glob("*.eml"))
        folder_counts[folder_name] = len(eml_files)
        json_files = [path for path in folder_path.glob("*.json") if path.name != ".mailbox.json"]
        eml_stems = {path.stem for path in eml_files}
        json_stems = {path.stem for path in json_files}
        symlink_jsons = {path for path in json_files if path.is_symlink()}
        orphan_metadata = sorted(json_stems - eml_stems)
        if orphan_metadata:
            errors.append(f"{folder_name}: {len(orphan_metadata)} metadata file(s) without .eml counterpart")
            folder_errors += 1
        for json_file in sorted(symlink_jsons):
            errors.append(f"{folder_name}/{json_file.name}: metadata sidecar is a symlink")
            folder_errors += 1
        for eml_file in eml_files:
            json_file = eml_file.with_suffix('.json')
            if eml_file.is_symlink():
                errors.append(f"{folder_name}/{eml_file.name}: message file is a symlink")
                folder_errors += 1
                continue
            if json_file.is_symlink():
                if json_file not in symlink_jsons:
                    errors.append(f"{folder_name}/{json_file.name}: metadata sidecar is a symlink")
                    folder_errors += 1
                continue
            
            analysis, error = analyze_message(
                eml_file,
                json_file,
                folder_name=folder_name,
                expected_account=expected_account,
                mailbox_marker_present=mailbox_marker_present,
                mailbox_marker_mailbox=mailbox_marker_mailbox,
            )
            
            if error:
                errors.append(f"{folder_name}/{eml_file.name}: {error}")
                folder_errors += 1
                continue
            
            folder_messages += 1
            total_messages += 1
            
            if analysis['has_attachments']:
                total_with_attachments += 1
                folder_attachments += analysis['attachment_count']
                total_attachments += analysis['attachment_count']
            
            # Check for multiple messages in single file
            if analysis['multiple_messages_detected']:
                multiple_message_files.append(f"{folder_name}/{eml_file.name} (Return-Path: {analysis['return_path_count']}, Message-ID: {analysis['message_id_count']})")
        if mailbox_marker.is_symlink() or mailbox_marker.exists():
            marker_errors = analyze_mailbox_marker(mailbox_marker, folder_name, len(eml_files))
            errors.extend(marker_errors)
            folder_errors += len(marker_errors)
        if not eml_files and not mailbox_marker.exists():
            errors.append(f"{folder_name}: no .eml files found and no mailbox marker present")
            folder_errors += 1
        
        if folder_messages > 0:
            folder_stats[folder_name] = {
                'messages': folder_messages,
                'attachments': folder_attachments,
                'errors': folder_errors
            }

    if mailbox_folders_found == 0:
        errors.append("no mailbox folders found")
    state_errors = analyze_export_state(account_path, folder_counts)
    errors.extend(state_errors)
    
    # Print summary
    print(f"Total messages: {total_messages}")
    print(f"Messages with attachments: {total_with_attachments}")
    print(f"Total attachments: {total_attachments}")
    
    if folder_stats:
        print("\nFolder breakdown:")
        for folder, stats in sorted(folder_stats.items()):
            print(f"  {folder}: {stats['messages']} messages, {stats['attachments']} attachments")
            if stats['errors'] > 0:
                print(f"    ⚠️  {stats['errors']} errors")
    
    if multiple_message_files:
        print(f"\n🚨 CRITICAL: {len(multiple_message_files)} files contain multiple messages!")
        print("These files may have concatenated messages:")
        for file_info in multiple_message_files[:10]:
            print(f"  {file_info}")
        if len(multiple_message_files) > 10:
            print(f"  ... and {len(multiple_message_files) - 10} more files")
    
    if errors:
        print(f"\n⚠️  {len(errors)} errors found:")
        for error in errors[:10]:  # Show first 10 errors
            print(f"  {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")
    
    return {
        'account': account_name,
        'total_messages': total_messages,
        'messages_with_attachments': total_with_attachments,
        'total_attachments': total_attachments,
        'folders': len(folder_stats),
        'errors': len(errors),
        'multiple_message_files': len(multiple_message_files)
    }

def main():
    export_dir = Path("exported")
    
    if export_dir.is_symlink():
        print("❌ Export directory 'exported' is a symlink!")
        return 1

    if not export_dir.exists():
        print("❌ Export directory 'exported' not found!")
        return 1
    
    print("🔍 Verifying exported email data...")
    print("Checking message integrity, attachments, and folder structure...")
    
    all_stats = []
    total_messages = 0
    total_attachments = 0
    total_errors = 0
    total_multiple_message_files = 0

    # Process each account
    for account_path in sorted(export_dir.iterdir()):
        if account_path.is_symlink():
            print(f"\n=== Verifying {account_path.name} ===")
            print(f"\n⚠️  1 errors found:")
            print(f"  account path is a symlink: {account_path}")
            all_stats.append({
                'account': account_path.name,
                'total_messages': 0,
                'messages_with_attachments': 0,
                'total_attachments': 0,
                'folders': 0,
                'errors': 1,
                'multiple_message_files': 0,
            })
            total_errors += 1
            continue
        if not account_path.is_dir():
            continue
        
        stats = verify_account(account_path)
        all_stats.append(stats)
        total_messages += stats['total_messages']
        total_attachments += stats['total_attachments']
        total_errors += stats['errors']
        total_multiple_message_files += stats['multiple_message_files']
    if not all_stats:
        print("⚠️  No account directories found in exported/")
        total_errors += 1
    
    # Overall summary
    print(f"\n{'='*50}")
    print("📊 EXPORT VERIFICATION SUMMARY")
    print(f"{'='*50}")
    print(f"Accounts processed: {len(all_stats)}")
    print(f"Total messages: {total_messages}")
    print(f"Total attachments: {total_attachments}")
    print(f"Total errors: {total_errors}")
    print(f"Files with multiple messages: {total_multiple_message_files}")
    
    if total_errors == 0 and total_multiple_message_files == 0:
        print("✅ All messages verified successfully!")
        print("✅ All attachments appear to be intact!")
    else:
        print("⚠️  Found export integrity issues - check individual account reports above")
    
    return 0 if total_errors == 0 and total_multiple_message_files == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
