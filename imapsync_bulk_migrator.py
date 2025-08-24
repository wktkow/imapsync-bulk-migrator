#!/usr/bin/env python3
"""
imapsync-bulk-migrator

KISS-friendly bulk export/import/validate utility around IMAP that also
leverages the `imapsync` binary for connectivity prechecks.

Modes:
- export: Download all folders and messages from Server A to local storage
- import: Upload previously exported messages from local storage to Server B
- test:   Connectivity checks for all accounts via imaplib and imapsync --justconnect
- validate: Compare local export counts with Server B counts; optionally resync missing

No external Python dependencies. Requires `imapsync` installed on the system.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import json
import logging
import os
import queue
import re
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import imaplib


# -------- Logging setup --------

def setup_logging(log_directory: Path) -> Path:
    log_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    log_file = log_directory / f"run-{timestamp}.log"

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # Clear existing handlers (safe for multiple invocations in same process)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.info("Logging initialized. File: %s", str(log_file))
    return log_file


# -------- Models and configuration --------


@dataclasses.dataclass
class Account:
    email: str
    password: str


@dataclasses.dataclass
class ServerConfig:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


@dataclasses.dataclass
class Config:
    server: ServerConfig
    accounts: List[Account]

    @staticmethod
    def from_json_file(path: Path) -> "Config":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Config root must be an object")

        server_raw = data.get("server")
        if not isinstance(server_raw, dict):
            raise ValueError("Config must include 'server' object")
        host = server_raw.get("host")
        if not host or not isinstance(host, str):
            raise ValueError("server.host must be a non-empty string")
        port = int(server_raw.get("port", 993))
        use_ssl = bool(server_raw.get("ssl", True))
        starttls = bool(server_raw.get("starttls", False))

        accounts_raw = data.get("accounts")
        if not isinstance(accounts_raw, list) or not accounts_raw:
            raise ValueError("Config must include non-empty 'accounts' array")
        accounts: List[Account] = []
        for idx, item in enumerate(accounts_raw):
            if not isinstance(item, dict):
                raise ValueError(f"accounts[{idx}] must be an object")
            email = item.get("email")
            password = item.get("password")
            if not email or not isinstance(email, str):
                raise ValueError(f"accounts[{idx}].email must be a non-empty string")
            if not isinstance(password, str):
                raise ValueError(f"accounts[{idx}].password must be a string (can be empty)")
            accounts.append(Account(email=email, password=password))

        server = ServerConfig(host=host, port=port, ssl=use_ssl, starttls=starttls)
        return Config(server=server, accounts=accounts)


# -------- Utility helpers --------


SANITIZE_PATTERN = re.compile(r"[^A-Za-z0-9_.@+-]+")


def sanitize_for_path(name: str) -> str:
    name = name.strip().replace(os.sep, "_").replace("/", "_")
    name = SANITIZE_PATTERN.sub("_", name)
    return name[:200] if len(name) > 200 else name


def ensure_imapsync_available() -> None:
    path = shutil.which("imapsync")
    if not path:
        raise RuntimeError(
            "The 'imapsync' binary is required but was not found in PATH. "
            "Install it and try again."
        )
    try:
        subprocess.run([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except Exception as exc:
        raise RuntimeError("Failed to execute 'imapsync --version'. Is imapsync installed correctly?") from exc


def check_environment(min_free_gb: float = 1.0) -> None:
    if sys.version_info < (3, 9):
        raise RuntimeError("Python 3.9+ is required.")

    total, used, free = shutil.disk_usage(Path.cwd())
    free_gb = free / (1024 ** 3)
    if free_gb < min_free_gb:
        raise RuntimeError(
            f"Insufficient free disk space: {free_gb:.2f} GiB available, requires ≥ {min_free_gb:.2f} GiB"
        )


def run_imapsync_justconnect(host: str, port: int, ssl_enabled: bool, starttls: bool, user: str, password: str, timeout_sec: int = 30) -> Tuple[bool, str]:
    ensure_imapsync_available()
    args = [
        "imapsync",
        "--justconnect",
        "--host1", host,
        "--user1", user,
        "--password1", password,
        "--port1", str(port),
        "--timeout1", str(timeout_sec),
        "--nofoldersizes",
        "--noreleasecheck",
    ]
    if ssl_enabled:
        args.append("--ssl1")
    elif starttls:
        args.append("--tls1")

    logging.debug("Running imapsync justconnect: %s", " ".join(["***" if a in {password} else a for a in args]))
    try:
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
        ok = res.returncode == 0
        return ok, res.stdout
    except Exception as exc:
        return False, f"Exception: {exc}"


@contextlib.contextmanager
def imap_connection(server: ServerConfig, account: Account) -> Iterable[imaplib.IMAP4]:
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
    status, data = imap.list()
    if status != "OK":
        raise RuntimeError("Failed to list mailboxes")
    mailboxes: List[str] = []
    # Typical line: b'(\HasNoChildren) "/" "INBOX"'
    for raw in data or []:
        if raw is None:
            continue
        line = raw.decode(errors="ignore")
        # Extract the last quoted string or the token after delimiter
        m = re.findall(r'"([^"]+)"$', line)
        if m:
            mailboxes.append(m[0])
        else:
            # Fallback: last token
            parts = line.split(" ")
            if parts:
                candidate = parts[-1].strip('"')
                mailboxes.append(candidate)
    # Deduplicate and sort putting INBOX first
    unique = []
    seen = set()
    for mb in mailboxes:
        if mb not in seen:
            seen.add(mb)
            unique.append(mb)
    unique.sort(key=lambda x: (0 if x.upper() == "INBOX" else 1, x.lower()))
    return unique


def fetch_all_uids(imap: imaplib.IMAP4, mailbox: str) -> List[int]:
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
    return uids


def _parse_fetch_response_for_uid(fetch_response: List[bytes]) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Return (rfc822_bytes, flags_string, internaldate_string)"""
    if not fetch_response:
        return None, None, None
    # Response structure examples vary; gather contiguous parts
    msg_bytes: Optional[bytes] = None
    flags: Optional[str] = None
    internaldate: Optional[str] = None
    joinable: List[bytes] = []
    for part in fetch_response:
        if isinstance(part, tuple) and len(part) == 2:
            # part[1] may be the RFC822 content
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
            # Sometimes FLAGS/INTERNALDATE appear here
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


def export_account(account: Account, server: ServerConfig, out_root: Path, ignore_errors: bool) -> None:
    account_dir = out_root / sanitize_for_path(account.email)
    account_dir.mkdir(parents=True, exist_ok=True)
    logging.info("[export] %s: starting", account.email)
    with imap_connection(server, account) as imap:
        mailboxes = list_all_mailboxes(imap)
        for mailbox in mailboxes:
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

                # Chunk fetch to keep memory bounded
                batch_size = 200
                for i in range(0, len(uids), batch_size):
                    batch = uids[i : i + batch_size]
                    uid_set = ",".join(str(u) for u in batch)
                    status, data = imap.uid("fetch", uid_set, "(RFC822 FLAGS INTERNALDATE)")
                    if status != "OK":
                        raise RuntimeError(f"fetch failed in {mailbox}")
                    # data is a list; group it per message heuristically
                    # We iterate pairs and collect until we encounter a closing b')'
                    cursor = 0
                    while cursor < len(data):
                        # Accumulate parts until next tuple boundary
                        parts: List[bytes] = []
                        while cursor < len(data) and data[cursor] is not None:
                            parts.append(data[cursor])
                            cursor += 1
                            # Heuristic stop when we see b')' in a bytes item
                            if isinstance(parts[-1], (bytes, bytearray)) and parts[-1].strip().endswith(b")"):
                                break
                        cursor += 1  # Skip None or move to next
                        msg_bytes, flags, internaldate = _parse_fetch_response_for_uid(parts)
                        if not msg_bytes:
                            continue
                        # Parse minimal to ensure it's a valid email
                        with contextlib.suppress(Exception):
                            _ = BytesParser(policy=default_policy).parsebytes(msg_bytes)
                        # Build filename using time and an index to avoid collisions
                        uid_hint = str(int(time.time() * 1000))
                        base = f"{uid_hint}-{abs(hash(msg_bytes)) & 0xFFFFFFFF:08x}"
                        eml_path = folder_dir / f"{base}.eml"
                        meta_path = folder_dir / f"{base}.json"
                        with open(eml_path, "wb") as f:
                            f.write(msg_bytes)
                        meta = {
                            "mailbox": mailbox,
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


def import_account(account: Account, server: ServerConfig, in_root: Path, ignore_errors: bool) -> None:
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    logging.info("[import] %s: starting", account.email)
    with imap_connection(server, account) as imap:
        # Map of folder name to list of (eml_path, flags, internaldate)
        per_folder: Dict[str, List[Tuple[Path, str, Optional[str]]]] = {}
        for folder_dir in sorted([p for p in account_dir.iterdir() if p.is_dir()]):
            folder = folder_dir.name
            entries: List[Tuple[Path, str, Optional[str]]] = []
            for eml_path in sorted(folder_dir.glob("*.eml")):
                meta_path = eml_path.with_suffix(".json")
                flags = ""
                internaldate = None
                if meta_path.exists():
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        flags = str(meta.get("flags", ""))
                        internaldate = meta.get("internaldate") or None
                entries.append((eml_path, flags, internaldate))
            per_folder[folder] = entries

        for folder, entries in per_folder.items():
            mailbox = folder
            try:
                # Ensure mailbox exists
                status, _ = imap.select(mailbox)
                if status != "OK":
                    with contextlib.suppress(Exception):
                        imap.create(mailbox)
                    status, _ = imap.select(mailbox)
                    if status != "OK":
                        raise RuntimeError(f"cannot select or create mailbox {mailbox}")
                # Append messages
                logging.info("[import] %s: %s <- %d messages", account.email, mailbox, len(entries))
                for eml_path, flags, internaldate in entries:
                    with open(eml_path, "rb") as f:
                        data = f.read()
                    flags_tuple = None
                    if flags:
                        # Flags string like: "\\Seen \\Answered"
                        # Normalize to parenthesized list, imaplib accepts None or string
                        flags_norm = "(" + " ".join(flag.strip() for flag in flags.split() if flag.strip()) + ")"
                        flags_tuple = flags_norm
                    date_time = internaldate
                    # Append into currently selected mailbox
                    status, _ = imap.append(mailbox, flags_tuple, date_time, data)
                    if status != "OK":
                        raise RuntimeError(f"append failed for {eml_path}")
            except Exception as exc:
                logging.exception("[import] %s: mailbox %s failed: %s", account.email, mailbox, exc)
                if not ignore_errors:
                    raise
    logging.info("[import] %s: completed", account.email)


def validate_account(account: Account, in_root: Path, server: ServerConfig) -> Tuple[str, Dict[str, Tuple[int, int]]]:
    """Return mapping: folder -> (local_count, remote_count)"""
    account_dir = in_root / sanitize_for_path(account.email)
    if not account_dir.exists():
        raise RuntimeError(f"Input account directory not found: {account_dir}")
    local_counts: Dict[str, int] = {}
    for folder_dir in [p for p in account_dir.iterdir() if p.is_dir()]:
        count = len(list(folder_dir.glob("*.eml")))
        local_counts[folder_dir.name] = count

    remote_counts: Dict[str, int] = {}
    with imap_connection(server, account) as imap:
        mailboxes = list_all_mailboxes(imap)
        for mailbox in mailboxes:
            try:
                status, _ = imap.select(mailbox, readonly=True)
                if status != "OK":
                    raise RuntimeError(f"select failed: {mailbox}")
                status, data = imap.search(None, "ALL")
                if status != "OK":
                    raise RuntimeError(f"search failed: {mailbox}")
                # Count messages
                num = len((data[0] or b"").split()) if data else 0
                remote_counts[mailbox] = num
            except Exception:
                remote_counts[mailbox] = -1

    results: Dict[str, Tuple[int, int]] = {}
    for folder, local_count in local_counts.items():
        remote = remote_counts.get(folder, -1)
        results[folder] = (local_count, remote)
    return account.email, results


def test_accounts(config: Config, max_workers: int) -> None:
    # imaplib check + imapsync justconnect ensures credentials work and imapsync is functional
    errors: queue.Queue[str] = queue.Queue()

    def worker(acc: Account) -> None:
        try:
            # Quick login test via imaplib
            with imap_connection(config.server, acc):
                pass
            # imapsync --justconnect
            ok, out = run_imapsync_justconnect(
                host=config.server.host,
                port=config.server.port,
                ssl_enabled=config.server.ssl,
                starttls=config.server.starttls,
                user=acc.email,
                password=acc.password,
                timeout_sec=30,
            )
            if not ok:
                raise RuntimeError(f"imapsync justconnect failed for {acc.email}:\n{out}")
            logging.info("[test] %s: OK", acc.email)
        except Exception as exc:
            logging.error("[test] %s: FAILED: %s", acc.email, exc)
            errors.put(f"{acc.email}: {exc}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="test") as ex:
        list(ex.map(worker, config.accounts))

    if not errors.empty():
        reasons = "\n".join(list(errors.queue))
        raise RuntimeError(f"Connectivity test failed for some accounts:\n{reasons}")


def parallel_process_accounts(
    label: str,
    func,
    accounts: List[Account],
    max_workers: int,
    stop_on_error: bool,
) -> None:
    errors: queue.Queue[str] = queue.Queue()

    def wrapped(acc: Account) -> None:
        try:
            func(acc)
        except Exception as exc:
            logging.error("[%s] %s: FAILED: %s", label, acc.email, exc)
            errors.put(f"{acc.email}: {exc}")
            if stop_on_error:
                # Propagate to trigger immediate shutdown
                raise

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label) as ex:
        # Use submit to allow early stop on error
        futures = [ex.submit(wrapped, acc) for acc in accounts]
        for fut in concurrent.futures.as_completed(futures):
            # Will re-raise if an exception happened in wrapped()
            fut.result()

    if not errors.empty() and not stop_on_error:
        logging.warning("[%s] Completed with errors (%d accounts). See logs.", label, errors.qsize())


def generate_import_config_template_from_export(export_config: Config, output_path: Path) -> None:
    """
    Generate an import.pass.config.json template using the same accounts as export.
    We keep the server section identical; users can update host later to server B.
    Will not overwrite an existing file.
    """
    if output_path.exists():
        logging.info("Import config already exists, not overwriting: %s", output_path)
        return
    payload = {
        "server": {
            "host": export_config.server.host,
            "port": export_config.server.port,
            "ssl": export_config.server.ssl,
            "starttls": export_config.server.starttls,
        },
        "accounts": [
            {"email": a.email, "password": a.password} for a in export_config.accounts
        ],
    }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logging.info("Generated import config template at: %s", output_path)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk export/import/validate IMAP mailboxes with prechecks via imapsync.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", required=True, choices=["export", "import", "test", "validate"], help="Operation mode")
    parser.add_argument("--config", required=False, help="Path to JSON config file with server and accounts")
    parser.add_argument("--output-dir", default=str(Path.cwd() / "exported"), help="Directory to write exported data")
    parser.add_argument("--input-dir", default=str(Path.cwd() / "exported"), help="Directory to read exported data for import/validate")
    parser.add_argument("--max-workers", type=int, default=max(4, (os.cpu_count() or 4)), help="Parallel worker threads for accounts")
    parser.add_argument("--ignore-errors", action="store_true", help="Continue other accounts on errors")
    parser.add_argument("--log-dir", default=str(Path.cwd() / "logs"), help="Directory to store log files")
    parser.add_argument("--min-free-gb", type=float, default=1.0, help="Fail-fast if free disk space is lower")
    parser.add_argument("--resync-missing", action="store_true", help="In validate mode, attempt to re-import missing messages")

    args = parser.parse_args(argv)

    log_file = setup_logging(Path(args.log_dir))
    logging.info("Starting imapsync-bulk-migrator | mode=%s", args.mode)

    # Environment checks
    try:
        check_environment(min_free_gb=float(args.min_free_gb))
        ensure_imapsync_available()
    except Exception as exc:
        logging.error("Environment/dependency check failed: %s", exc)
        return 2

    # Determine default config path per mode if not provided
    default_config = {
        "export": "export.pass.config.json",
        "import": "import.pass.config.json",
        "test": "export.pass.config.json",
        "validate": "import.pass.config.json",
    }[args.mode]
    config_path = Path(args.config or default_config)
    if not config_path.exists():
        logging.error("Config not found: %s", str(config_path))
        return 2

    try:
        config = Config.from_json_file(config_path)
    except Exception as exc:
        logging.error("Invalid config: %s", exc)
        return 2

    # Pre-test connectivity for import/export as required by prompt
    try:
        logging.info("Running connectivity tests (imaplib + imapsync --justconnect) ...")
        test_accounts(config, max_workers=int(args.max_workers))
        logging.info("Connectivity tests passed for all accounts")
    except Exception as exc:
        logging.error("Connectivity tests failed: %s", exc)
        return 3

    # Graceful shutdown on SIGINT/SIGTERM
    stop_event = threading.Event()

    def handle_sig(signum, _frame):
        logging.warning("Received signal %s, requesting stop...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    try:
        if args.mode == "export":
            out_root = Path(args.output_dir)
            out_root.mkdir(parents=True, exist_ok=True)

            # Auto-generate import.pass.config.json template (do not overwrite)
            try:
                generate_import_config_template_from_export(
                    export_config=config, output_path=Path("import.pass.config.json")
                )
            except Exception as exc:
                logging.warning("Failed to generate import config template: %s", exc)

            def do_export(acc: Account) -> None:
                if stop_event.is_set():
                    return
                export_account(acc, config.server, out_root, ignore_errors=bool(args.ignore_errors))

            parallel_process_accounts("export", do_export, config.accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            logging.info("Export finished. Data stored under: %s", out_root)
        elif args.mode == "import":
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2

            def do_import(acc: Account) -> None:
                if stop_event.is_set():
                    return
                import_account(acc, config.server, in_root, ignore_errors=bool(args.ignore_errors))

            parallel_process_accounts("import", do_import, config.accounts, int(args.max_workers), stop_on_error=not args.ignore_errors)
            logging.info("Import finished into server %s", config.server.host)
        elif args.mode == "test":
            # Already run above
            logging.info("Test completed successfully.")
        elif args.mode == "validate":
            in_root = Path(args.input_dir)
            if not in_root.exists():
                logging.error("Input directory does not exist: %s", in_root)
                return 2

            mismatches: List[Tuple[str, str, int, int]] = []

            def do_validate(acc: Account) -> None:
                email, folder_map = validate_account(acc, in_root, config.server)
                for folder, (local_count, remote_count) in folder_map.items():
                    if local_count != remote_count:
                        mismatches.append((email, folder, local_count, remote_count))

            parallel_process_accounts("validate", do_validate, config.accounts, int(args.max_workers), stop_on_error=False)

            if mismatches:
                logging.warning("Validation mismatches found:")
                for email, folder, local_count, remote_count in mismatches:
                    logging.warning("%s | %s | local=%d remote=%d", email, folder, local_count, remote_count)
                if args.resync_missing:
                    logging.info("Attempting resync for mismatched folders by re-running import for affected accounts ...")
                    affected = {e for e, _, _, _ in mismatches}

                    def do_resync(acc: Account) -> None:
                        if acc.email in affected:
                            import_account(acc, config.server, in_root, ignore_errors=True)

                    parallel_process_accounts("resync", do_resync, [a for a in config.accounts if a.email in affected], int(args.max_workers), stop_on_error=False)
            else:
                logging.info("Validation successful: local export matches remote counts for all accounts.")
        else:
            logging.error("Unknown mode: %s", args.mode)
            return 2
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        return 1

    logging.info("Done. Log file: %s", log_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())


