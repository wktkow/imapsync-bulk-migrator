import logging
import subprocess
from typing import Tuple

from .utils import ensure_imapsync_available


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
    res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
    ok = res.returncode == 0
    return ok, res.stdout


