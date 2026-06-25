"""Linux ELF detonation in a locked-down container with syscall tracing.

Runs the ELF under ``strace`` (or seccomp-notify in the real container image)
inside an isolated, ephemeral container with the simulated network. Normalizes
the syscall trace into EvidenceItems (file/network/process). Gated on isolation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

_SYSCALL_MAP = {
    "open": ("file", "read"),
    "openat": ("file", "read"),
    "unlink": ("file", "write"),
    "connect": ("network", "connect"),
    "socket": ("network", "connect"),
    "execve": ("process", "spawn"),
    "clone": ("process", "spawn"),
    "fork": ("process", "spawn"),
    "ptrace": ("process", "inject"),
}


class LinuxSandboxAnalyzer(BaseAnalyzer):
    name = "dynamic.linux"
    handles = {"elf"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        strace = shutil.which("strace")
        if not strace:  # pragma: no cover
            return [
                ctx.ev(
                    source="dynamic.linux",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "strace not present; use the container image's seccomp tracer"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]

        items: list[EvidenceItem] = []
        with tempfile.TemporaryDirectory() as td:  # pragma: no cover - requires isolation
            tdir = Path(td)
            target = tdir / "sample.bin"
            target.write_bytes(sample.data)
            target.chmod(0o700)
            trace = tdir / "trace.txt"
            try:
                subprocess.run(
                    [strace, "-f", "-o", str(trace), str(target)],
                    capture_output=True,
                    timeout=15,
                    cwd=td,
                    check=False,
                )
            except Exception as exc:
                return [
                    ctx.ev(
                        source="dynamic.linux",
                        artifact="process",
                        operation="exec",
                        subject={"analyzer": self.name},
                        object={"status": "error"},
                        details={"error": repr(exc)},
                        confidence=0.2,
                        evidence_refs=[ref],
                    )
                ]
            if trace.exists():
                for line in trace.read_text(errors="replace").splitlines():
                    m = re.match(r"(?:\[pid\s+\d+\]\s+)?(\w+)\((.*)", line)
                    if not m:
                        continue
                    sc = m.group(1)
                    if sc in _SYSCALL_MAP:
                        art, op = _SYSCALL_MAP[sc]
                        items.append(
                            ctx.ev(
                                source="dynamic.linux",
                                artifact=art,
                                operation=op,
                                subject={"analyzer": self.name, "pid": "elf"},
                                object={"syscall": sc, "args": m.group(2)[:160]},
                                details={"observed": "strace"},
                                confidence=0.8,
                                evidence_refs=[ref],
                            )
                        )
        return items


def register(registry) -> None:
    registry.register(LinuxSandboxAnalyzer())
