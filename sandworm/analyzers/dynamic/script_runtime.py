"""Normalize instrumented script traces returned by sandbox backends."""

from __future__ import annotations

from collections.abc import Iterator

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context


class ScriptRuntimeAnalyzer(BaseAnalyzer):
    name = "dynamic.script"
    handles = {"script", "shell", "powershell", "javascript"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        return []


def normalize_shell_trace(trace: str, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Convert an inert ``set -x`` trace artifact into process evidence."""
    for line in trace.splitlines():
        if not line.startswith("+"):
            continue
        command = line.lstrip("+ ").strip()
        if not command:
            continue
        yield ctx.ev(
            source="dynamic.script",
            artifact="process",
            operation="spawn",
            subject={"analyzer": "dynamic.script", "pid": "shell"},
            object={"command": command},
            details={"observed": "sandbox shell trace artifact"},
            confidence=0.85,
            evidence_refs=[ref],
        )


def register(registry) -> None:
    registry.register(ScriptRuntimeAnalyzer())
