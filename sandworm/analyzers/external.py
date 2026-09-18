"""Resource-bounded invocation of trusted parser tools (never sample commands)."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path


def run_parser(command: list[str], log: Path, *, timeout: int = 300, max_bytes: int = 32 * 1024**2) -> None:
    with log.open("wb") as output:
        # A queued attempt already has a dedicated group. Keep parser tools and
        # their descendants in it so cancellation cannot leave them behind.
        in_attempt = hasattr(os, "getpgrp") and os.environ.get("SANDWORM_ATTEMPT_PROCESS_GROUP") == str(os.getpgrp())
        proc = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=not in_attempt)
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline or log.stat().st_size > max_bytes:
                    raise RuntimeError("parser exceeded time/output budget")
                time.sleep(0.1)
            if proc.returncode:
                raise RuntimeError(f"parser exited with status {proc.returncode}; see {log.name}")
        finally:
            if proc.poll() is None:
                if hasattr(os, "killpg"):
                    # Exceeding a parser budget inside a worker ends the whole
                    # attempt, including descendants; CLI runs have their own
                    # parser group and leave the caller alive.
                    os.killpg(os.getpgrp() if in_attempt else proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait()
        if log.stat().st_size > max_bytes:
            raise RuntimeError("parser output exceeds limit")
