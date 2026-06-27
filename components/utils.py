import base64
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SANITIZE_PATTERN = re.compile(r"[^A-Za-z0-9_.@+-]+")


def sanitize_for_path(name: str) -> str:
    name = name.strip().replace(os.sep, "_").replace("/", "_")
    name = SANITIZE_PATTERN.sub("_", name)
    name = name[:200] if len(name) > 200 else name
    if name in {"", ".", ".."}:
        return "_"
    return name


_IMAP_ATOM_SPECIALS = set('(){ %*"\\]')


def quote_imap_search_value(value: str) -> str:
    """Return an IMAP search string safe for imaplib's raw argument joining."""
    if value and not any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _IMAP_ATOM_SPECIALS for ch in value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', r"\"")
    return f'"{escaped}"'


def encode_imap_utf7(value: str) -> str:
    """Encode a mailbox name using IMAP modified UTF-7."""
    result: list[str] = []
    pending: list[str] = []

    def flush_pending() -> None:
        if not pending:
            return
        raw = "".join(pending).encode("utf-16-be")
        encoded = base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",")
        result.append(f"&{encoded}-")
        pending.clear()

    for char in value:
        codepoint = ord(char)
        if 0x20 <= codepoint <= 0x7E and char != "&":
            flush_pending()
            result.append(char)
        elif char == "&":
            flush_pending()
            result.append("&-")
        else:
            pending.append(char)
    flush_pending()
    return "".join(result)


def decode_imap_utf7(value: str) -> str:
    """Decode a mailbox name encoded with IMAP modified UTF-7."""
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "&":
            result.append(char)
            index += 1
            continue
        end = value.find("-", index + 1)
        if end < 0:
            result.append("&")
            index += 1
            continue
        token = value[index + 1 : end]
        if token == "":
            result.append("&")
        else:
            padded = token.replace(",", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            try:
                result.append(base64.b64decode(padded).decode("utf-16-be"))
            except Exception:
                result.append(f"&{token}-")
        index = end + 1
    return "".join(result)


def ensure_imapsync_available() -> None:
    path = shutil.which("imapsync")
    if not path:
        raise RuntimeError(
            "The 'imapsync' binary is required but was not found in PATH. Install it and try again."
        )
    subprocess.run([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)


def check_environment(min_free_gb: float = 1.0) -> None:
    if sys.version_info < (3, 9):
        raise RuntimeError("Python 3.9+ is required.")
    _ = min_free_gb


def check_free_space_for_path(target_path: Path, min_free_gb: float) -> None:
    """Check free space on the filesystem backing `target_path`.

    Uses the path if it exists, otherwise its parent directory.
    """
    probe = target_path
    # Climb to an existing ancestor (fallback to CWD as a last resort).
    while not probe.exists():
        parent = probe.parent
        if parent == probe:
            probe = Path.cwd()
            break
        probe = parent
    _, _, free = shutil.disk_usage(probe)
    free_gb = free / (1024 ** 3)
    if free_gb < min_free_gb:
        raise RuntimeError(
            f"Insufficient free disk space at {probe}: {free_gb:.2f} GiB available, requires ≥ {min_free_gb:.2f} GiB"
        )
