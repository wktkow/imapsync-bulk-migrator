from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional


MAX_SECRET_FILE_BYTES = 1024 * 1024
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _open_directory_no_links(name: str, *, dir_fd: Optional[int] = None) -> int:
    flags = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
    if dir_fd is None:
        return os.open(name, flags)
    return os.open(name, flags, dir_fd=dir_fd)


def _secret_absolute_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return Path.cwd() / candidate


def _open_secret_parent(path: Path, *, label: str) -> tuple[int, str]:
    parts = path.parts
    if len(parts) < 2 or parts[-1] in {"", ".", ".."}:
        raise RuntimeError(f"invalid {label} path: {path}")
    try:
        fd = _open_directory_no_links(parts[0])
    except OSError as exc:
        raise RuntimeError(f"failed to open {label}: {path}") from exc
    try:
        for part in parts[1:-1]:
            try:
                next_fd = _open_directory_no_links(part, dir_fd=fd)
            except OSError as exc:
                raise RuntimeError(f"failed to open {label}: {path}") from exc
            os.close(fd)
            fd = next_fd
    except Exception:
        os.close(fd)
        raise
    return fd, parts[-1]


def read_secret_file_no_links(
    path: str | Path,
    *,
    label: str,
    max_bytes: int = MAX_SECRET_FILE_BYTES,
) -> str:
    """Read a small regular secret file without following symlinks or blocking on FIFOs."""
    secret_path = _secret_absolute_path(path)
    parent_fd, name = _open_secret_parent(secret_path, label=label)
    file_fd: Optional[int] = None
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK, dir_fd=parent_fd)
        except OSError as exc:
            raise RuntimeError(f"failed to open {label}: {path}") from exc
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"refusing to read non-regular {label}: {path}")
        if st.st_nlink != 1:
            raise RuntimeError(f"refusing to read hard-linked {label}: {path}")
        if st.st_size > max_bytes:
            raise RuntimeError(f"{label} is too large: {path}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise RuntimeError(f"{label} is too large: {path}")
        return data.decode("utf-8").rstrip("\r\n")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)
