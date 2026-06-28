import logging
import os
import subprocess
import tempfile
import time
from typing import Optional, Tuple

from .utils import ensure_imapsync_available


def run_imapsync_justconnect(
    host: str,
    port: int,
    ssl_enabled: bool,
    starttls: bool,
    user: str,
    password: str,
    timeout_sec: int = 30,
    *,
    stop_event: Optional[object] = None,
) -> Tuple[bool, str]:
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
        else:
            args.extend(["--nossl1", "--notls1"])

        logging.debug("Running imapsync justconnect: %s", " ".join(args))
        if stop_event is None:
            res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True, timeout=timeout_sec + 10)
            ok = res.returncode == 0
            return ok, res.stdout

        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + timeout_sec + 10
        while True:
            try:
                out, _stderr = proc.communicate(timeout=0.2)
                return proc.returncode == 0, out
            except subprocess.TimeoutExpired:
                if getattr(stop_event, "is_set", lambda: False)():
                    proc.terminate()
                    try:
                        out, _stderr = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        out, _stderr = proc.communicate()
                    return False, "stop requested\n" + (out or "")
                if time.monotonic() >= deadline:
                    proc.kill()
                    out, _stderr = proc.communicate()
                    return False, "timeout\n" + (out or "")
    except subprocess.TimeoutExpired:
        return False, "timeout"
    finally:
        if passfile_path:
            try:
                os.unlink(passfile_path)
            except FileNotFoundError:
                pass
