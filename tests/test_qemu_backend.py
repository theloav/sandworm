"""VM boundary regression tests without requiring a hypervisor in CI."""
import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from sandworm.core.sample import Sample
from sandworm.sandbox.base import AnalysisPolicy, BackendError, JobState
from sandworm.sandbox.qemu import QemuBackend


@pytest.fixture
def backend(tmp_path, monkeypatch):
    image = tmp_path / "base.qcow2"
    image.write_bytes(b"fixture guest image")
    monkeypatch.setattr("sandworm.sandbox.qemu.tool", lambda name: name)
    return QemuBackend(image=image, image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(), artifact_dir=tmp_path / "artifacts")


def test_qemu_rejects_network_and_changed_image(backend):
    sample = Sample.from_bytes("demo.sh", b"echo benign")
    with pytest.raises(BackendError, match="disabled networking"):
        backend.submit(sample, AnalysisPolicy(network="simulated"))
    backend.image.write_bytes(b"changed")
    with pytest.raises(BackendError, match="pinned SHA-256"):
        backend.submit(sample, AnalysisPolicy())


def test_qemu_failed_launch_cleans_plaintext_and_overlay(backend, monkeypatch):
    def run(args, **kwargs):
        output = Path(args[args.index("-o") + 1]) if args[0] == "genisoimage" else Path(args[-1])
        output.write_bytes(b"temporary transport")

    def fail(*args, **kwargs):
        raise OSError("fixture launch failure")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", fail)
    with pytest.raises(OSError, match="launch failure"):
        backend.submit(Sample.from_bytes("demo.sh", b"echo benign"), AnalysisPolicy())
    assert not list(backend.artifact_dir.rglob("payload.iso"))
    assert not list(backend.artifact_dir.rglob("sample.bin"))
    assert not list(backend.artifact_dir.rglob("overlay.qcow2"))
    assert backend.jobs == {}


def test_qemu_launch_boundary_identity_and_teardown(backend, monkeypatch):
    commands = []

    def run(args, **kwargs):
        commands.append(args)

    class Process:
        stopped = False

        def __init__(self, args, **kwargs):
            commands.append(args)

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def wait(self, *args):
            return 0

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", Process)
    sample = Sample.from_bytes("demo.sh", b"echo benign")
    job = backend.submit(sample, AnalysisPolicy(capture_memory=False))
    args = commands[-1]
    assert args[args.index("-nic") + 1] == "none"
    assert "-virtfs" not in args and "-netdev" not in args
    block = json.loads(args[args.index("-blockdev") + 1])
    assert block["file"]["filename"].endswith("overlay.qcow2")
    row = backend.jobs[job.id]
    assert not (row["directory"] / "payload").exists()
    serial = row["directory"] / "serial.log"

    def report(digest):
        serial.write_bytes(b"SANDWORM_RESULT:" + base64.b64encode(json.dumps({"target_sha256": digest, "traces": []}).encode()) + b"\n")

    report("f" * 64)
    with pytest.raises(BackendError, match="sample-bound"):
        backend.collect(job)
    report(sample.sha256)
    bundle = backend.collect(job)
    assert bundle.isolation_verified and bundle.target_sha256 == sample.sha256
    backend.destroy(job)
    assert row["proc"].stopped
    assert backend.status(job).state == JobState.DESTROYED
