#!/usr/bin/env python3
"""
Read-only cPanel UAPI mailbox indexer.

Lists email accounts visible to one cPanel user and writes an
export.pass.config.json-compatible legacy IMAP config.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from components.cpanel_client import CPanelClient
from directadmin_indexer import build_config, prompt_select_from_list, read_secret_file, write_json


@dataclass
class ServerSettings:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


def _resolve_one_secret(args: argparse.Namespace, prefix: str, label: str) -> Optional[str]:
    value = getattr(args, prefix, None)
    file_value = getattr(args, f"{prefix}_file", None)
    env_value = getattr(args, f"{prefix}_env", None)
    sources = [name for name, item in ((prefix, value), (f"{prefix}_file", file_value), (f"{prefix}_env", env_value)) if item]
    if len(sources) > 1:
        raise ValueError(f"{label} must be provided by only one source")
    if file_value:
        return read_secret_file(str(file_value), label=f"{label} file")
    if env_value:
        env_name = str(env_value)
        secret = os.environ.get(env_name, "").strip()
        if not secret:
            raise ValueError(f"{label} environment variable is unset or empty: {env_name}")
        return secret
    if value:
        print(f"Warning: --{prefix.replace('_', '-')} can expose secrets via shell history/process arguments; prefer file/env", file=sys.stderr)
        return str(value)
    return None


def resolve_cpanel_auth(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    password = _resolve_one_secret(args, "password", "cPanel password")
    token = _resolve_one_secret(args, "token", "cPanel API token")
    if bool(password) == bool(token):
        raise ValueError("Provide exactly one cPanel authentication source: password or API token")
    return password, token


def resolve_default_password(args: argparse.Namespace) -> str:
    secret = _resolve_one_secret(args, "default_password", "Default mailbox password")
    return secret or ""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index mailboxes via cPanel UAPI and write export.pass.config.json",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="cPanel URL, e.g. https://panel.example.com:2083")
    parser.add_argument("--username", required=True, help="cPanel account username")
    parser.add_argument("--password", required=False, help="cPanel password; insecure because process args can expose it")
    parser.add_argument("--password-file", required=False, help="Path to a file containing the cPanel password")
    parser.add_argument("--password-env", required=False, help="Environment variable containing the cPanel password")
    parser.add_argument("--token", required=False, help="cPanel API token; insecure because process args can expose it")
    parser.add_argument("--token-file", required=False, help="Path to a file containing the cPanel API token")
    parser.add_argument("--token-env", required=False, help="Environment variable containing the cPanel API token")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--imap-host", required=True, help="IMAP server hostname to place into generated config")
    parser.add_argument("--imap-port", type=int, default=993, help="IMAP server port")
    parser.add_argument("--imap-ssl", action="store_true", default=True, help="Use SSL for IMAP connection")
    parser.add_argument("--no-imap-ssl", dest="imap_ssl", action="store_false", help="Disable SSL for IMAP connection")
    parser.add_argument("--imap-starttls", action="store_true", default=False, help="Use STARTTLS when SSL is disabled")
    parser.add_argument("--default-password", default="", help="Password value to put for each account; insecure because process args can expose it")
    parser.add_argument("--default-password-file", required=False, help="Path to a file containing the default mailbox password")
    parser.add_argument("--default-password-env", required=False, help="Environment variable containing the default mailbox password")
    parser.add_argument("--out", default="export.pass.config.json", help="Output JSON path")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite output file if it exists")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        password, token = resolve_cpanel_auth(args)
        default_password = resolve_default_password(args)
        client = CPanelClient(
            base_url=args.url,
            username=args.username,
            password=password,
            token=token,
            verify_ssl=not bool(args.no_verify_ssl),
        )
        all_emails = client.list_all_email_accounts()
    except Exception as exc:
        print(f"Failed to query cPanel UAPI: {exc}", file=sys.stderr)
        return 2

    domains = sorted({email.split("@", 1)[1].lower() for email in all_emails if "@" in email})
    if not domains:
        print("No email accounts found for this cPanel account.")
        return 0
    selected_idx = prompt_select_from_list(domains, title="Available Email Domains")
    if not selected_idx:
        print("No valid domain selection provided.", file=sys.stderr)
        return 2
    selected_domains = {domains[i] for i in selected_idx}
    selected_emails = sorted(email for email in all_emails if email.split("@", 1)[1].lower() in selected_domains)

    server = ServerSettings(
        host=args.imap_host,
        port=int(args.imap_port),
        ssl=bool(args.imap_ssl) and not bool(args.imap_starttls),
        starttls=bool(args.imap_starttls),
    )
    payload: Dict[str, Any] = build_config(server, selected_emails, default_password=default_password)
    try:
        write_json(payload, args.out, overwrite=bool(args.overwrite))
    except Exception as exc:
        print(f"Failed to write {args.out}: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {args.out} with {len(payload.get('accounts', []))} accounts across {len(selected_domains)} domain(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
