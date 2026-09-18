"""Normalize Linux syscall traces returned by a sandbox backend.

This module intentionally contains no process-launching code. A disposable
worker captures the trace; the controller only parses the returned text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

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
        # Kept as a compatibility adapter for external plugins. Built-ins no
        # longer register execution analyzers; use normalize_strace on a trace
        # returned in an ArtifactBundle.
        return []


def normalize_strace(trace: str, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Convert an inert ``strace -f`` text artifact into evidence."""
    for line in trace.splitlines():
        match = re.match(r"(?:(?:\[pid\s+)?(\d+)\]?\s+)?(\w+)\((.*)", line)
        if not match:
            continue
        pid, syscall, args = match.groups()
        if syscall not in _SYSCALL_MAP:
            continue
        artifact, operation = _SYSCALL_MAP[syscall]
        yield ctx.ev(
            source="dynamic.linux",
            artifact=artifact,
            operation=operation,
            subject={"analyzer": "dynamic.linux", "pid": pid or "unknown"},
            object={"syscall": syscall, "args": args[:160]},
            details={"observed": "sandbox strace artifact"},
            confidence=0.8,
            evidence_refs=[ref],
        )


def register(registry) -> None:
    registry.register(LinuxSandboxAnalyzer())
