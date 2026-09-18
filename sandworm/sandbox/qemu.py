"""Disposable, networkless QEMU system-VM backend with serial artifact capture."""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from ..core.sample import Sample
from .base import (
    AnalysisPolicy,
    Artifact,
    ArtifactBundle,
    BackendError,
    JobHandle,
    JobState,
    JobStatus,
)


def tool(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise BackendError(f"{name} is required; see docs/sandbox-deployment.md")
    return value


def firmware_args() -> list[str]:
    """Support unprivileged QEMU installations with relocated firmware data."""
    directory = os.environ.get("SANDWORM_QEMU_DATA")
    args = ["-vga", "none"]
    if directory:
        root = Path(directory).resolve()
        args += ["-L", str(root)]
        bios = root.parent / "seabios" / "bios-256k.bin"
        if bios.is_file():
            args += ["-bios", str(bios)]
    return args


def qmp(socket_path: Path, command: str, arguments: dict | None = None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(120)
        sock.connect(str(socket_path))
        stream = sock.makefile("rwb")
        stream.readline()
        for name, args in (("qmp_capabilities", {}), (command, arguments or {})):
            stream.write((json.dumps({"execute": name, "arguments": args}) + "\n").encode())
            stream.flush()
            while True:
                line = stream.readline(1024 * 1024)
                if not line:
                    raise BackendError("QMP connection closed")
                response = json.loads(line)
                if "error" in response:
                    raise BackendError(str(response["error"]))
                if "return" in response:
                    break
        return response["return"]


class QemuBackend:
    name = "qemu"

    def __init__(self, *, image: Path, image_sha256: str, artifact_dir: Path):
        self.image, self.image_sha256 = image.resolve(), image_sha256.lower()
        self.artifact_dir = artifact_dir
        self.jobs: dict[str, dict] = {}

    def submit(self, sample: Sample, policy: AnalysisPolicy) -> JobHandle:
        if policy.network != "disabled":
            raise BackendError("QEMU backend only permits disabled networking")
        qemu, iso = tool("qemu-system-x86_64"), tool("genisoimage")
        actual = Artifact.from_path("other", self.image)
        if actual.sha256 != self.image_sha256:
            raise BackendError("guest image does not match the pinned SHA-256")
        from ..core.triage import identify
        fmt = identify(sample.data, sample.name).fmt
        engine = policy.options.get("engine")
        if engine is None:
            engine = "php" if fmt == "php" else "elf" if fmt == "elf" else "javascript" if sample.name.endswith(".js") else "python" if sample.name.endswith(".py") else "shell" if sample.name.endswith(".sh") else ""
        if engine not in {"php", "elf", "javascript", "python", "shell"}:
            raise BackendError("QEMU profile requires a supported Linux executable or script")
        handle = JobHandle(uuid.uuid4().hex, self.name, sample.sha256)
        self.artifact_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = self.artifact_dir.resolve() / handle.id
        directory.mkdir(mode=0o700)
        # Socket lives in a short path to fit the AF_UNIX limit.
        temporary = tempfile.TemporaryDirectory(prefix="sw-vm-")
        qmp_path = Path(temporary.name) / "qmp.sock"
        staging = directory / "payload"
        staging.mkdir(mode=0o700)
        canaries = []
        if policy.options.get("canaries", "false").lower() == "true":
            from dataclasses import asdict

            from ..enrich.canary import plant
            canary_set = plant(staging / "canaries")
            canaries = [asdict(c) | {"placement": Path(c.placement).name} for c in canary_set.canaries]
        (staging / "sample.bin").write_bytes(sample.data)
        (staging / "request.json").write_text(json.dumps({"sha256": sample.sha256, "engine": engine,
                                                          "timeout": policy.timeout_seconds, "canaries": canaries}))
        payload_iso = directory / "payload.iso"
        try:
            subprocess.run([iso, "-quiet", "-o", str(payload_iso), "-V", "SANDWORM", "-J", "-r", str(staging)],
                           check=True, capture_output=True, timeout=30)
            args = [qemu, *firmware_args(), "-m", "1024", "-smp", "2", "-accel", "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg",
                    "-snapshot", "-blockdev", json.dumps({"driver": "qcow2", "node-name": "base", "file": {"driver": "file", "filename": str(self.image)}}),
                    "-device", "virtio-blk-pci,drive=base", "-cdrom", str(payload_iso), "-nic", "none", "-display", "none",
                    "-monitor", "none", "-serial", "file:" + str(directory / "serial.log"), "-no-reboot",
                    "-qmp", f"unix:{qmp_path},server=on,wait=off", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
            # Explicit ephemeral overlay is required with -blockdev; -snapshot
            # alone does not turn arbitrary blockdev nodes into snapshots.
            overlay = directory / "overlay.qcow2"
            subprocess.run([tool("qemu-img"), "create", "-f", "qcow2", "-F", "qcow2", "-b", str(self.image), str(overlay)],
                           check=True, capture_output=True, timeout=30)
            block = args.index("-blockdev") + 1
            args[block] = json.dumps({"driver": "qcow2", "node-name": "base", "file": {"driver": "file", "filename": str(overlay)}})
            with (directory / "qemu.log").open("wb") as log:
                proc = subprocess.Popen(args, stdout=log, stderr=log)
        except Exception:
            temporary.cleanup()
            for name in ("payload.iso", "overlay.qcow2"):
                (directory / name).unlink(missing_ok=True)
            raise
        finally:
            # Plaintext transport is needed only for the VM lifetime; staging
            # files can go immediately after creating its read-only ISO.
            shutil.rmtree(staging)
        self.jobs[handle.id] = {"proc": proc, "directory": directory, "policy": policy,
                                "socket": qmp_path, "temporary": temporary, "started": time.monotonic()}
        return handle

    def status(self, job: JobHandle) -> JobStatus:
        row = self.jobs.get(job.id)
        if row is None:
            return JobStatus(JobState.DESTROYED)
        return JobStatus(JobState.RUNNING if row["proc"].poll() is None else JobState.FAILED)

    def collect(self, job: JobHandle) -> ArtifactBundle:
        row = self.jobs[job.id]
        directory, policy = row["directory"], row["policy"]
        serial = directory / "serial.log"
        deadline = row["started"] + policy.timeout_seconds + 240
        report = None
        while time.monotonic() < deadline:
            if serial.exists():
                if serial.stat().st_size > 16 * 1024**2:
                    raise BackendError("guest serial output exceeded limit")
                for line in serial.read_bytes().splitlines():
                    if line.startswith(b"SANDWORM_RESULT:"):
                        report = json.loads(base64.b64decode(line.partition(b":")[2], validate=True))
                        break
            if report is not None:
                break
            if row["proc"].poll() is not None:
                raise BackendError("guest exited before returning evidence; inspect qemu.log")
            time.sleep(1)
        if report is None or report.get("target_sha256") != job.sample_sha256:
            raise BackendError("guest returned no valid sample-bound report before deadline")
        path = directory / "runtime.json"
        path.write_text(json.dumps(report))
        artifacts = [Artifact.from_path("trace", path, media_type="application/json")]
        if policy.capture_memory:
            dump = directory / "memory.elf"
            qmp(row["socket"], "stop")
            qmp(row["socket"], "dump-guest-memory", {"paging": False, "protocol": "file:" + str(dump)})
            artifacts.append(Artifact.from_path("memory_dump", dump))
        return ArtifactBundle(job=job, target_sha256=job.sample_sha256, backend_version="1",
                              execution_mode="sandbox", artifacts=tuple(artifacts), policy=policy,
                              image_id=self.image_sha256, isolation_verified=True)

    def destroy(self, job: JobHandle) -> None:
        row = self.jobs.pop(job.id, None)
        if row is None:
            return
        proc = row["proc"]
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        row["temporary"].cleanup()
        for name in ("payload.iso", "overlay.qcow2"):
            (row["directory"] / name).unlink(missing_ok=True)
