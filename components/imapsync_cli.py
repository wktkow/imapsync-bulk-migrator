import logging
import os
import subprocess
import tempfile
import time
from typing import Optional, Tuple

from .utils import ensure_imapsync_available


def _fd_passfile_path(fd: int) -> str:
    for template in ("/proc/self/fd/{fd}", "/dev/fd/{fd}"):
        candidate = template.format(fd=fd)
        if os.path.exists(candidate):
            return candidate
    raise RuntimeError("platform does not expose inherited file descriptors as passfile paths")


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
    resolved_imapsync = ensure_imapsync_available()
    imapsync_bin = resolved_imapsync if isinstance(resolved_imapsync, str) and resolved_imapsync else "imapsync"
    with tempfile.TemporaryFile("w+", encoding="utf-8") as passfile:
        passfile.write(password)
        passfile.write("\n")
        passfile.flush()
        passfile.seek(0)
        passfile_fd = passfile.fileno()
        passfile_path = _fd_passfile_path(passfile_fd)
        args = [
            imapsync_bin,
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
        try:
            if stop_event is None:
                res = subprocess.run(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                    text=True,
                    timeout=timeout_sec + 10,
                    pass_fds=(passfile_fd,),
                )
                ok = res.returncode == 0
                return ok, res.stdout

            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                pass_fds=(passfile_fd,),
            )
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
