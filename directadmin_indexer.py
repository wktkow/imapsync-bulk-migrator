#!/usr/bin/env python3
"""
directadmin_indexer

Interactive domain and mailbox indexer for DirectAdmin-compatible API.

This utility connects to a control panel API (DirectAdmin-compatible), lists
domains for the authenticated user, lets you interactively select the domains
to include, then enumerates all POP/IMAP mailboxes for those domains and
generates a JSON config file compatible with imapsync-bulk-migrator
(`export.pass.config.json` format).

No changes are made on the server. Read-only, safe by default.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

import urllib.parse

try:
    import requests
except Exception:  # pragma: no cover
    print("This script requires the 'requests' package. Install via: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)


@dataclass
class ServerSettings:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


class DirectAdminClient:
    """
    Minimal client for DirectAdmin-compatible API.

    Authentication: basic auth with username/password (or login key as password).
    """

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, timeout_sec: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.timeout_sec = timeout_sec

    def _endpoint(self, path: str) -> str:
        if path.startswith("/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path}"

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Tuple[Optional[dict], Optional[Dict[str, List[str]]]]:
        """
        Returns (json_obj, kv_pairs) where exactly one is non-None depending on server response.
        """
        params = dict(params or {})
        # Ask for JSON when supported by the server
        params.setdefault("json", "yes")
        url = self._endpoint(path)
        resp = self.session.get(url, params=params, timeout=self.timeout_sec)
        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "").lower()

        # Try JSON first
        if "json" in ctype:
            try:
                return resp.json(), None
            except Exception:
                pass

        # Some DA installs return urlencoded bodies
        text = resp.text.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return resp.json(), None
            except Exception:
                pass
        # Fallback: parse as querystring (key=value&list[]=a&list[]=b)
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True, strict_parsing=False)
        return None, parsed

    def list_domains(self) -> List[str]:
        # User-level domains
        json_obj, kv = self._get("CMD_API_SHOW_DOMAINS")
        if json_obj is not None:
            # Newer DA returns {"list": ["example.com", ...]}
            if isinstance(json_obj, dict):
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(d) for d in json_obj["list"]]
                # Some variants nest under "domains"
                if "domains" in json_obj and isinstance(json_obj["domains"], list):
                    return [str(d) for d in json_obj["domains"]]
        if kv is not None:
            # Expect keys like list[]=domain
            items = kv.get("list[]") or kv.get("list") or []
            return [str(d) for d in items]
        raise RuntimeError("Unable to parse domains response from API")

    def list_pop_accounts(self, domain: str) -> List[str]:
        # POP/IMAP accounts per domain
        # Prefer explicit action=list for compatibility
        json_obj, kv = self._get("CMD_API_POP", params={"domain": domain, "action": "list"})
        if json_obj is not None:
            # Common shapes:
            # {"list": ["user1", "user2"]}
            # {"users": ["user1", ...]}
            if isinstance(json_obj, dict):
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(u) for u in json_obj["list"]]
                if "users" in json_obj and isinstance(json_obj["users"], list):
                    return [str(u) for u in json_obj["users"]]
        if kv is not None:
            items = kv.get("list[]") or kv.get("list") or kv.get("users[]") or kv.get("users") or []
            return [str(u) for u in items]
        # Some installs place names under index keys like list0=user
        if json_obj and isinstance(json_obj, dict):
            dynamic = [v for k, v in json_obj.items() if k.startswith("list")]
            if dynamic:
                return [str(u) for u in dynamic]
        return []


def prompt_select_from_list(options: List[str], title: str) -> List[int]:
    """
    Simple interactive selector without external dependencies.

    Shows a numbered list and prompts the user to enter comma-separated indices
    and/or ranges (e.g., "1,3-5"). Empty input selects all.
    Returns the list of selected indices.
    """
    print()
    print(title)
    print("=" * max(8, len(title)))
    for idx, opt in enumerate(options, start=1):
        print(f" {idx:2d}) {opt}")
    print()
    raw = input("Select indices (e.g., 1,3-5) or press Enter for ALL: ").strip()
    if not raw:
        return list(range(len(options)))

    selected: List[int] = []
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    for tok in tokens:
        if "-" in tok:
            try:
                start_s, end_s = tok.split("-", 1)
                start = int(start_s)
                end = int(end_s)
                if start <= 0 or end <= 0:
                    raise ValueError
                for i in range(start, end + 1):
                    if 1 <= i <= len(options):
                        selected.append(i - 1)
            except Exception:
                print(f"Ignoring invalid range: {tok}")
        else:
            try:
                i = int(tok)
                if 1 <= i <= len(options):
                    selected.append(i - 1)
                else:
                    print(f"Index out of range: {i}")
            except Exception:
                print(f"Ignoring invalid token: {tok}")

    # Deduplicate preserving order
    seen = set()
    deduped: List[int] = []
    for i in selected:
        if i not in seen:
            seen.add(i)
            deduped.append(i)
    if not deduped:
        return list(range(len(options)))
    return deduped


def build_config(server: ServerSettings, emails: List[str], default_password: str) -> Dict[str, object]:
    return {
        "server": {
            "host": server.host,
            "port": server.port,
            "ssl": server.ssl,
            "starttls": server.starttls,
        },
        "accounts": [
            {"email": e, "password": default_password} for e in sorted(emails)
        ],
    }


def write_json(payload: Dict[str, object], out_path: str, overwrite: bool) -> None:
    path_exists = os.path.exists(out_path)
    if path_exists and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {out_path} (use --overwrite)")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Index domains and mailboxes via DirectAdmin-compatible API and write export.pass.config.json",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--url", required=True, help="Base URL to the control panel API, e.g. https://panel.example.com:2222")
    p.add_argument("--username", required=True, help="API username (user-level is sufficient)")
    p.add_argument("--password", required=True, help="API password or login key")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")

    p.add_argument("--imap-host", required=True, help="IMAP server hostname to place into generated config")
    p.add_argument("--imap-port", type=int, default=993, help="IMAP server port")
    p.add_argument("--imap-ssl", action="store_true", default=True, help="Use SSL for IMAP connection (default on)")
    p.add_argument("--no-imap-ssl", dest="imap_ssl", action="store_false", help="Disable SSL for IMAP connection")
    p.add_argument("--imap-starttls", action="store_true", default=False, help="Use STARTTLS when SSL is disabled")

    p.add_argument("--default-password", default="", help="Password value to put for each account (leave empty to fill later)")
    p.add_argument("--out", default="export.pass.config.json", help="Output JSON path")
    p.add_argument("--overwrite", action="store_true", help="Overwrite output file if it exists")

    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        client = DirectAdminClient(
            base_url=args.url,
            username=args.username,
            password=args.password,
            verify_ssl=not args.no_verify_ssl,
        )
        domains = client.list_domains()
    except Exception as exc:
        print(f"Failed to query API: {exc}", file=sys.stderr)
        return 2

    if not domains:
        print("No domains found for this account.")
        return 0

    selected_idx = prompt_select_from_list(domains, title="Available Domains")
    selected_domains = [domains[i] for i in selected_idx]

    all_emails: List[str] = []
    for domain in selected_domains:
        try:
            users = client.list_pop_accounts(domain)
        except Exception as exc:
            print(f"Warning: failed to list accounts for {domain}: {exc}")
            users = []
        emails = [f"{u}@{domain}" for u in users]
        print(f"{domain}: {len(emails)} accounts")
        all_emails.extend(emails)

    # Build config
    server = ServerSettings(
        host=args.imap_host,
        port=int(args.imap_port),
        ssl=bool(args.imap_ssl),
        starttls=bool(args.imap_starttls),
    )
    payload = build_config(server, all_emails, default_password=args.default_password)

    # Default output: export.pass.config.json (same shape used by migrator)
    # If output exists and no --overwrite, refuse to clobber
    try:
        write_json(payload, args.out, overwrite=bool(args.overwrite))
    except Exception as exc:
        print(f"Failed to write {args.out}: {exc}", file=sys.stderr)
        return 2

    print(f"Wrote {args.out} with {len(payload.get('accounts', []))} accounts across {len(selected_domains)} domain(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())


