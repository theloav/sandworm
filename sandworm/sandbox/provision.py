"""Build an analysis guest from a hash-pinned Ubuntu cloud image.

Provisioning has network access to install guest packages and contains no sample.
The resulting image is booted without any network device for every analysis.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import uuid
from importlib.resources import files
from pathlib import Path

from .base import Artifact, BackendError
from .qemu import firmware_args, tool


def cloud_config() -> str:
    agent = files("sandworm.sandbox").joinpath("guest_agent.py").read_bytes()
    unit = """[Unit]
Description=Sandworm disposable guest agent
After=local-fs.target
ConditionPathExists=/etc/sandworm-disposable-guest
[Service]
Type=simple
ExecStartPre=/bin/chmod 0600 /dev/ttyS0
ExecStart=/usr/bin/python3 /usr/local/lib/sandworm-agent.py
Restart=no
[Install]
WantedBy=multi-user.target
"""
    # JSON is valid YAML, so values cannot break cloud-config quoting.
    return "#cloud-config\n" + json.dumps({
        "users": [{"name": "sandworm", "lock_passwd": True, "shell": "/bin/bash"}],
        "ssh_pwauth": False,
        "package_update": True,
        "packages": ["strace", "python3", "php-cli", "nodejs"],
        "write_files": [
            {"path": "/etc/sandworm-disposable-guest", "content": "provisioned\n", "permissions": "0400"},
            {"path": "/usr/local/lib/sandworm-agent.py", "encoding": "b64", "content": base64.b64encode(agent).decode(), "permissions": "0500"},
            {"path": "/etc/systemd/system/sandworm-agent.service", "content": unit, "permissions": "0644"},
        ],
        "runcmd": [
            ["systemctl", "disable", "ssh.service"],
            ["systemctl", "mask", "serial-getty@ttyS0.service"],
            ["chmod", "0600", "/dev/ttyS0"],
            ["systemctl", "enable", "sandworm-agent.service"],
            ["sh", "-c", "command -v strace && command -v php && command -v node && echo SANDWORM_IMAGE_READY >/dev/ttyS0"],
        ],
        "power_state": {"mode": "poweroff", "timeout": 30, "condition": True},
    })


def build_guest(source: Path, expected_sha256: str, output: Path) -> dict:
    qemu, img, iso = tool("qemu-system-x86_64"), tool("qemu-img"), tool("genisoimage")
    if Artifact.from_path("other", source).sha256 != expected_sha256.lower():
        raise BackendError("cloud image SHA-256 mismatch")
    output = output.resolve()
    if output.exists():
        raise ValueError("output directory already exists; choose a new build directory")
    output.mkdir(parents=True, mode=0o700)
    source = source.resolve()
    disk = output / "provisioning.qcow2"
    subprocess.run([img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(source), str(disk), "12G"], check=True)
    seed = output / "seed"
    seed.mkdir()
    (seed / "user-data").write_text(cloud_config())
    (seed / "meta-data").write_text(json.dumps({"instance-id": "sandworm-" + uuid.uuid4().hex, "local-hostname": "sandworm-guest"}))
    seed_iso = output / "seed.iso"
    subprocess.run([iso, "-quiet", "-o", str(seed_iso), "-V", "CIDATA", "-J", "-r", str(seed)], check=True)
    serial = output / "provisioning.log"
    args = [qemu, *firmware_args(), "-m", "2048", "-smp", "2", "-accel", "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg",
            "-blockdev", json.dumps({"driver": "qcow2", "node-name": "os", "file": {"driver": "file", "filename": str(disk)}}),
            "-device", "virtio-blk-pci,drive=os", "-cdrom", str(seed_iso),
            "-netdev", "user,id=provision", "-device", "virtio-net-pci,netdev=provision,romfile=", "-display", "none", "-monitor", "none", "-no-reboot",
            "-serial", "file:" + str(serial)]
    try:
        subprocess.run(args, check=True, timeout=2400)
    except subprocess.TimeoutExpired as exc:
        raise BackendError("guest provisioning timed out; inspect provisioning.log") from exc
    if "SANDWORM_IMAGE_READY" not in [line.strip() for line in serial.read_text(errors="replace").splitlines()]:
        raise BackendError("guest packages/service did not finish provisioning; inspect provisioning.log")
    image = output / "sandworm-linux.qcow2"
    subprocess.run([img, "convert", "-O", "qcow2", str(disk), str(image)], check=True, timeout=600)
    digest = Artifact.from_path("other", image).sha256
    manifest = {"linux": {"backend": "qemu", "image": str(image), "sha256": digest,
                          "timeout": 60, "network": "disabled", "options": {"canaries": "true"}}}
    (output / "profiles.json").write_text(json.dumps(manifest, indent=2))
    (output / "build.json").write_text(json.dumps({"source_sha256": expected_sha256, "image_sha256": digest,
                                                   "guest_agent_sha256": Artifact.from_path("other", Path(__file__).with_name("guest_agent.py")).sha256}, indent=2))
    return manifest
