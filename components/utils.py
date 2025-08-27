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
    return name[:200] if len(name) > 200 else name


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

    total, used, free = shutil.disk_usage(Path.cwd())
    free_gb = free / (1024 ** 3)
    if free_gb < min_free_gb:
        raise RuntimeError(
            f"Insufficient free disk space: {free_gb:.2f} GiB available, requires ≥ {min_free_gb:.2f} GiB"
        )


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


