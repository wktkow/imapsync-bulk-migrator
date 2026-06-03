import logging
import os
import subprocess
import tempfile
from typing import Tuple

from .utils import ensure_imapsync_available


def run_imapsync_justconnect(host: str, port: int, ssl_enabled: bool, starttls: bool, user: str, password: str, timeout_sec: int = 30) -> Tuple[bool, str]:
    """Run `imapsync --justconnect` as a connection probe.

    Legacy `test_accounts` performs credential validation with imaplib before
    invoking this connection-only imapsync check.
    """
    ensure_imapsync_available()
    passfile_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="imapsync-pass-", delete=False) as passfile:
            passfile.write(password)
            passfile.write("\n")
            passfile_path = passfile.name
        os.chmod(passfile_path, 0o600)
        args = [
            "imapsync",
            "--justconnect",
            "--host1", host,
            "--user1", user,
            "--passfile1", passfile_path,
            "--port1", str(port),
            "--timeout1", str(timeout_sec),
            "--nofoldersizes",
            "--noreleasecheck",
        ]
        if ssl_enabled:
            args.append("--ssl1")
        elif starttls:
            args.append("--tls1")

        logging.debug("Running imapsync justconnect: %s", " ".join(args))
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True, timeout=timeout_sec + 10)
        ok = res.returncode == 0
        return ok, res.stdout
    except subprocess.TimeoutExpired:
        return False, "timeout"
    finally:
        if passfile_path:
            try:
                os.unlink(passfile_path)
            except FileNotFoundError:
                pass
