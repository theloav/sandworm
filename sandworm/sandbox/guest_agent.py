"""Installed ONLY inside the disposable Linux guest; never run on the controller.

The payload is on a read-only ISO labelled SANDWORM. Sample output is separated
from the root-only serial evidence channel. No host mounts or network devices.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import signal
import subprocess
import time
from pathlib import Path


def main() -> None:
    if not Path("/etc/sandworm-disposable-guest").is_file():
        raise RuntimeError("guest agent must only run in a provisioned disposable VM")
    payload = Path("/mnt/sandworm")
    payload.mkdir(exist_ok=True)
    for _ in range(60):
        if Path("/dev/disk/by-label/SANDWORM").exists():
            break
        time.sleep(1)
    else:
        return
    subprocess.run(["mount", "-o", "ro,nosuid,nodev,noexec", "/dev/disk/by-label/SANDWORM", str(payload)], check=True)
    request = json.loads((payload / "request.json").read_text())
    sample = (payload / "sample.bin").read_bytes()
    if hashlib.sha256(sample).hexdigest() != request["sha256"]:
        raise RuntimeError("payload identity mismatch")
    work = Path("/tmp/sandworm-analysis")
    work.mkdir(mode=0o755)
    path = work / "sample.bin"
    path.write_bytes(sample)
    path.chmod(0o555)
    trace = Path("/tmp/sandworm-trace")
    runners = {"elf": [str(path)], "shell": ["/bin/sh", str(path)],
               "php": ["/usr/bin/php", str(path)], "python": ["/usr/bin/python3", str(path)],
               "javascript": ["/usr/bin/node", str(path)]}
    command = runners[request["engine"]]
    user = pwd.getpwnam("sandworm")
    home = Path(user.pw_dir)
    canaries = request.get("canaries", [])
    for canary in canaries:
        placement = home / Path(canary["placement"]).name
        placement.write_text(canary["token"])
        os.chown(placement, user.pw_uid, user.pw_gid)
    with open("/tmp/sandworm-stdout", "wb") as out:
        proc = subprocess.Popen(["strace", "-f", "-qq", "-s", "256", "-u", "sandworm", "-o", str(trace), *command],
                                stdout=out, stderr=out, start_new_session=True,
                                cwd=home, env={"PATH": "/usr/bin:/bin", "HOME": str(home)})
        try:
            proc.wait(timeout=min(request.get("timeout", 30), 300))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    with trace.open("rb") as fh:
        text = fh.read(4 * 1024 * 1024).decode("utf-8", "replace")
    result = {"target_sha256": request["sha256"], "schema_version": 1,
              "traces": [{"kind": "linux", "text": text}],
              "canaries": canaries, "exit_code": proc.returncode}
    data = base64.b64encode(json.dumps(result).encode()).decode()
    with open("/dev/ttyS0", "w") as serial:
        serial.write("\nSANDWORM_RESULT:" + data + "\nSANDWORM_DONE\n")
        serial.flush()
    # Keep memory available for QMP capture until the controller tears down VM.
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
