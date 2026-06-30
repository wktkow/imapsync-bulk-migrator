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
import contextlib
import errno
import json
import os
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import urllib.parse

from components.secret_files import read_secret_file_no_links

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


@dataclass
class ServerSettings:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_HAS_DESCRIPTOR_RELATIVE_OUTPUT = all(
    fn in os.supports_dir_fd
    for fn in (os.link, os.mkdir, os.open, os.rename, os.unlink)
)


class DirectAdminClient:
    """
    Minimal client for DirectAdmin-compatible API.

    Authentication: basic auth with username/password (or login key as password).
    """

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, timeout_sec: int = 20) -> None:
        if requests is None:  # type: ignore
            raise RuntimeError("DirectAdmin indexer requires the 'requests' package. Install via: pip install -r requirements.txt")
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()  # type: ignore[union-attr]
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
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if json_obj is not None:
            # Newer DA returns {"list": ["example.com", ...]}
            if isinstance(json_obj, dict):
                has_error = "error" in json_obj
                err = str(json_obj.get("error", "0"))
                if err not in {"0", "false", "False"}:
                    msg = str(json_obj.get("text") or json_obj.get("message") or "DirectAdmin returned error")
                    raise RuntimeError(msg)
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(d) for d in json_obj["list"]]
                # Some variants nest under "domains"
                if "domains" in json_obj and isinstance(json_obj["domains"], list):
                    return [str(d) for d in json_obj["domains"]]
                if has_error:
                    return []
                raise RuntimeError("Unable to parse domains response from API")
            elif isinstance(json_obj, list):
                return [str(d) for d in json_obj]
        if kv is not None:
            has_error = "error" in kv
            err = _kv_get_one(kv, "error") or "0"
            if err not in {"0", "false", "False"}:
                msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or "DirectAdmin returned error"
                raise RuntimeError(msg)
            # Expect keys like list[]=domain
            items = kv.get("list[]") or kv.get("list")
            if items is None:
                if has_error or not kv:
                    return []
                raise RuntimeError("Unable to parse domains response from API")
            return [str(d) for d in items]
        raise RuntimeError("Unable to parse domains response from API")

    def list_pop_accounts(self, domain: str) -> List[str]:
        # POP/IMAP accounts per domain
        # Prefer explicit action=list for compatibility
        json_obj, kv = self._get("CMD_API_POP", params={"domain": domain, "action": "list"})
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if json_obj is not None:
            # Common shapes:
            # {"list": ["user1", "user2"]}
            # {"users": ["user1", ...]}
            if isinstance(json_obj, dict):
                has_error = "error" in json_obj
                err = str(json_obj.get("error", "0"))
                if err not in {"0", "false", "False"}:
                    msg = str(json_obj.get("text") or json_obj.get("message") or "DirectAdmin returned error")
                    raise RuntimeError(msg)
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(u) for u in json_obj["list"]]
                if "users" in json_obj and isinstance(json_obj["users"], list):
                    return [str(u) for u in json_obj["users"]]
                dynamic_values = []
                for k, v in json_obj.items():
                    if isinstance(k, str) and k.startswith("list"):
                        if isinstance(v, list):
                            dynamic_values.extend(v)
                        else:
                            dynamic_values.append(v)
                if dynamic_values:
                    return [str(u) for u in dynamic_values]
                if has_error:
                    return []
                raise RuntimeError(f"Unable to parse POP account list response for {domain}")
            elif isinstance(json_obj, list):
                return [str(u) for u in json_obj]
        if kv is not None:
            has_error = "error" in kv
            err = _kv_get_one(kv, "error") or "0"
            if err not in {"0", "false", "False"}:
                msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or "DirectAdmin returned error"
                raise RuntimeError(msg)
            items = kv.get("list[]") or kv.get("list") or kv.get("users[]") or kv.get("users")
            if items is None:
                if has_error:
                    return []
                raise RuntimeError(f"Unable to parse POP account list response for {domain}")
            return [str(u) for u in items]
        # Some installs place names under index keys like list0=user
        if json_obj and isinstance(json_obj, dict):
            dynamic = [v for k, v in json_obj.items() if k.startswith("list")]
            if dynamic:
                return [str(u) for u in dynamic]
        raise RuntimeError(f"Unable to parse POP account list response for {domain}")


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
        return []
    return deduped


def build_config(server: ServerSettings, emails: List[str], default_password: str) -> Dict[str, Any]:
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


def _indexer_normalized_absolute_path(path: Path) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    parts: List[str] = []
    for part in absolute.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return Path(absolute.anchor).joinpath(*parts)


def _indexer_parent_matches_fd(parent_path: Path, parent_fd: int) -> bool:
    try:
        current = os.stat(parent_path, follow_symlinks=False)
    except OSError:
        return False
    pinned = os.fstat(parent_fd)
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == pinned.st_dev
        and current.st_ino == pinned.st_ino
    )


def _raise_if_indexer_parent_replaced(parent_path: Path, parent_fd: int, label: str) -> None:
    if not _indexer_parent_matches_fd(parent_path, parent_fd):
        raise RuntimeError(f"refusing to use replaced indexer {label} directory: {parent_path}")


def _fsync_indexer_directory_fd(dir_fd: int, path: Path, label: str) -> None:
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise RuntimeError(f"unable to fsync indexer {label} directory for durability: {path}") from exc


def _indexer_dir_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_or_create_indexer_parent_dir(path: Path, label: str) -> Tuple[int, str, Path]:
    if not _HAS_DESCRIPTOR_RELATIVE_OUTPUT:
        raise RuntimeError("platform does not support descriptor-relative indexer output access")
    absolute = _indexer_normalized_absolute_path(path)
    name = absolute.name
    if not name or name in {".", ".."}:
        raise RuntimeError(f"refusing to use invalid indexer {label} path: {path}")
    parent_path = absolute.parent
    flags = _indexer_dir_open_flags()
    fd = os.open(absolute.anchor, flags)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:-1]:
            created = False
            try:
                os.mkdir(part, PRIVATE_DIR_MODE, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked indexer {label} directory: {path}") from exc
                if exc.errno != errno.EEXIST:
                    raise
            if created:
                _fsync_indexer_directory_fd(fd, current, label)
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise RuntimeError(f"refusing to use symlinked indexer {label} directory: {path}") from exc
                if exc.errno == errno.ENOTDIR:
                    with contextlib.suppress(OSError):
                        component_stat = os.stat(part, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISLNK(component_stat.st_mode):
                            raise RuntimeError(f"refusing to use symlinked indexer {label} directory: {path}") from exc
                    raise RuntimeError(f"indexer {label} path component is not a directory: {current / part}") from exc
                raise
            try:
                stat_result = os.fstat(next_fd)
                if not stat.S_ISDIR(stat_result.st_mode):
                    raise RuntimeError(f"indexer {label} path component is not a directory: {current / part}")
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            current = current / part
        _raise_if_indexer_parent_replaced(parent_path, fd, label)
        return fd, name, parent_path
    except Exception:
        os.close(fd)
        raise


def write_json(payload: Dict[str, Any], out_path: str, overwrite: bool) -> None:
    out = Path(out_path)
    parent_fd, name, parent_path = _open_or_create_indexer_parent_dir(out, "output")
    tmp_name = f".{name}.{os.getpid()}.{time.time_ns()}.tmp"
    created_tmp = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(tmp_name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise RuntimeError(f"refusing to use unsafe indexer temporary file: {out.with_name(tmp_name)}") from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(f"refusing to use symlinked indexer temporary file: {out.with_name(tmp_name)}") from exc
            raise
        created_tmp = True
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                os.fchmod(f.fileno(), PRIVATE_FILE_MODE)
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            if overwrite:
                os.rename(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                tmp_name = ""
                try:
                    _raise_if_indexer_parent_replaced(parent_path, parent_fd, "output")
                except Exception:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=parent_fd)
                    raise
                _fsync_indexer_directory_fd(parent_fd, parent_path, "output")
                _raise_if_indexer_parent_replaced(parent_path, parent_fd, "output")
            else:
                try:
                    os.link(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                except FileExistsError as exc:
                    raise FileExistsError(f"Refusing to overwrite existing file: {out_path} (use --overwrite)") from exc
                try:
                    _raise_if_indexer_parent_replaced(parent_path, parent_fd, "output")
                except Exception:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=parent_fd)
                    raise
                os.unlink(tmp_name, dir_fd=parent_fd)
                tmp_name = ""
                _fsync_indexer_directory_fd(parent_fd, parent_path, "output")
                _raise_if_indexer_parent_replaced(parent_path, parent_fd, "output")
        except Exception:
            if tmp_name and created_tmp:
                removed_tmp = False
                try:
                    os.unlink(tmp_name, dir_fd=parent_fd)
                    removed_tmp = True
                except FileNotFoundError:
                    pass
                if removed_tmp:
                    _fsync_indexer_directory_fd(parent_fd, parent_path, "output")
            raise
    finally:
        os.close(parent_fd)


def read_secret_file(path: str, *, label: str) -> str:
    value = read_secret_file_no_links(path, label=label)
    if not value:
        raise ValueError(f"{label} is empty: {path}")
    return value


def resolve_password(args: argparse.Namespace) -> str:
    sources = [
        name
        for name, value in (
            ("--password", getattr(args, "password", None)),
            ("--password-file", getattr(args, "password_file", None)),
            ("--password-env", getattr(args, "password_env", None)),
        )
        if value
    ]
    if not sources:
        raise ValueError("DirectAdmin password requires one of: --password-file, --password-env, --password")
    if len(sources) > 1:
        raise ValueError("DirectAdmin password must be provided by only one source")
    if getattr(args, "password_file", None):
        return read_secret_file(str(args.password_file), label="DirectAdmin password file")
    if getattr(args, "password_env", None):
        env_name = str(args.password_env)
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ValueError(f"DirectAdmin password environment variable is unset or empty: {env_name}")
        return value
    print("Warning: --password can expose the secret via shell history/process arguments; prefer --password-file or --password-env", file=sys.stderr)
    return str(args.password)


def resolve_default_password(args: argparse.Namespace) -> str:
    sources = [
        name
        for name, value in (
            ("--default-password", getattr(args, "default_password", None)),
            ("--default-password-file", getattr(args, "default_password_file", None)),
            ("--default-password-env", getattr(args, "default_password_env", None)),
        )
        if value
    ]
    if len(sources) > 1:
        raise ValueError("Default mailbox password must be provided by only one source")
    if getattr(args, "default_password_file", None):
        return read_secret_file(str(args.default_password_file), label="Default mailbox password file")
    if getattr(args, "default_password_env", None):
        env_name = str(args.default_password_env)
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ValueError(f"Default mailbox password environment variable is unset or empty: {env_name}")
        return value
    if getattr(args, "default_password", None):
        print("Warning: --default-password can expose mailbox passwords via shell history/process arguments; prefer --default-password-file or --default-password-env", file=sys.stderr)
        return str(args.default_password)
    return ""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Index domains and mailboxes via DirectAdmin-compatible API and write export.pass.config.json",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--url", required=True, help="Base URL to the control panel API, e.g. https://panel.example.com:2222")
    p.add_argument("--username", required=True, help="API username (user-level is sufficient)")
    p.add_argument("--password", required=False, help="API password or login key; insecure because process args can expose it")
    p.add_argument("--password-file", required=False, help="Path to a file containing the API password or login key")
    p.add_argument("--password-env", required=False, help="Environment variable containing the API password or login key")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")

    p.add_argument("--imap-host", required=True, help="IMAP server hostname to place into generated config")
    p.add_argument("--imap-port", type=int, default=993, help="IMAP server port")
    p.add_argument("--imap-ssl", action="store_true", default=True, help="Use SSL for IMAP connection (default on)")
    p.add_argument("--no-imap-ssl", dest="imap_ssl", action="store_false", help="Disable SSL for IMAP connection")
    p.add_argument("--imap-starttls", action="store_true", default=False, help="Use STARTTLS when SSL is disabled")

    p.add_argument("--default-password", default="", help="Password value to put for each account (leave empty to fill later); insecure because process args can expose it")
    p.add_argument("--default-password-file", required=False, help="Path to a file containing the default mailbox password")
    p.add_argument("--default-password-env", required=False, help="Environment variable containing the default mailbox password")
    p.add_argument("--out", default="export.pass.config.json", help="Output JSON path")
    p.add_argument("--overwrite", action="store_true", help="Overwrite output file if it exists")

    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        password = resolve_password(args)
        default_password = resolve_default_password(args)
        client = DirectAdminClient(
            base_url=args.url,
            username=args.username,
            password=password,
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
    if not selected_idx:
        print("No valid domain selection provided.", file=sys.stderr)
        return 2
    selected_domains = [domains[i] for i in selected_idx]

    all_emails: List[str] = []
    for domain in selected_domains:
        try:
            users = client.list_pop_accounts(domain)
        except Exception as exc:
            print(f"Failed to list accounts for {domain}: {exc}", file=sys.stderr)
            return 2
        emails = [f"{u}@{domain}" for u in users]
        print(f"{domain}: {len(emails)} accounts")
        all_emails.extend(emails)
    if not all_emails:
        print("No email accounts found for the selected domain(s).")
        return 0

    # Build config
    server = ServerSettings(
        host=args.imap_host,
        port=int(args.imap_port),
        ssl=bool(args.imap_ssl) and not bool(args.imap_starttls),
        starttls=bool(args.imap_starttls),
    )
    payload = build_config(server, all_emails, default_password=default_password)

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
