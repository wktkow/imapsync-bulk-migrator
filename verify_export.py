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

def analyze_message(eml_path, json_path):
    """Analyze a single exported message"""
    try:
        # Read the email
        with open(eml_path, 'rb') as f:
            msg_bytes = f.read()
        
        # Check for multiple messages concatenated (look for multiple RFC822 headers).
        # Only count headers in the top-level header block (before the first blank line)
        # to avoid false positives from forwarded/attached messages in the body.
        msg_text = msg_bytes.decode('utf-8', errors='ignore').replace('\r\n', '\n')
        header_section = msg_text.split('\n\n', 1)[0] if '\n\n' in msg_text else msg_text
        return_path_count = len(re.findall(r'(?im)^Return-Path:', header_section))
        message_id_count = len(re.findall(r'(?im)^Message-ID:', header_section))
        
        # Parse the email
        msg = BytesParser(policy=default_policy).parsebytes(msg_bytes)
        
        # Read metadata
        metadata = {}
        if json_path.exists():
            with open(json_path, 'r') as f:
                metadata = json.load(f)
        
        integrity_errors = []
        expected_hash = metadata.get('content_sha256')
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_hash):
                integrity_errors.append('invalid content_sha256 metadata')
            else:
                actual_hash = hashlib.sha256(msg_bytes).hexdigest()
                if actual_hash != expected_hash.lower():
                    integrity_errors.append('content_sha256 mismatch')
        expected_size = metadata.get('rfc822_size')
        if expected_size is not None:
            if not isinstance(expected_size, int):
                integrity_errors.append('invalid rfc822_size metadata')
            elif len(msg_bytes) != expected_size:
                integrity_errors.append(f'rfc822_size mismatch (metadata={expected_size} actual={len(msg_bytes)})')
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
            'multiple_messages_detected': return_path_count > 1 or message_id_count > 1 or _has_later_rfc822_header_block(msg_text),
            'return_path_count': return_path_count,
            'message_id_count': message_id_count
        }
        
        # Check for attachments and content types
        if msg.is_multipart():
            for part in msg.walk():
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

def verify_account(account_path):
    """Verify all messages in an account"""
    account_name = account_path.name
    print(f"\n=== Verifying {account_name} ===")
    
    total_messages = 0
    total_with_attachments = 0
    total_attachments = 0
    errors = []
    folder_stats = {}
    multiple_message_files = []
    mailbox_folders_found = 0
    
    # Walk through all folders
    for folder_path in account_path.iterdir():
        if not folder_path.is_dir():
            continue
        mailbox_folders_found += 1
            
        folder_name = folder_path.name
        folder_messages = 0
        folder_attachments = 0
        folder_errors = 0
        
        # Process all .eml files in folder
        for eml_file in folder_path.glob("*.eml"):
            json_file = eml_file.with_suffix('.json')
            
            analysis, error = analyze_message(eml_file, json_file)
            
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
        
        if folder_messages > 0:
            folder_stats[folder_name] = {
                'messages': folder_messages,
                'attachments': folder_attachments,
                'errors': folder_errors
            }

    if mailbox_folders_found == 0:
        errors.append("no mailbox folders found")
    
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
        if not account_path.is_dir():
            continue
        
        stats = verify_account(account_path)
        all_stats.append(stats)
        total_messages += stats['total_messages']
        total_attachments += stats['total_attachments']
        total_errors += stats['errors']
        total_multiple_message_files += stats['multiple_message_files']
    
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
