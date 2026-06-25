"""Adapter to an existing Windows sandbox backend (CAPE / DRAKVUF).

SANDWORM does NOT build hypervisor instrumentation. This adapter submits the PE to
a CAPE/DRAKVUF instance (or ingests a pre-produced report) and normalizes its
process/file/registry/network/api output into EvidenceItems. Gated: detonation
only via the isolation-verified backend.

For offline/CI use, pass a path to an existing CAPE JSON report via
``ctx.extra['cape_report']`` and this adapter will normalize it without touching
any sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context


class WindowsCapeAnalyzer(BaseAnalyzer):
    name = "dynamic.windows.cape"
    handles = {"pe"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        report_path = ctx.extra.get("cape_report")
        if not report_path or not Path(report_path).exists():
            return [
                ctx.ev(
                    source="dynamic.windows.cape",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "no CAPE/DRAKVUF backend report available; submit job or pass cape_report"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]
        report = json.loads(Path(report_path).read_text())
        return list(self._normalize(report, ctx, ref))

    def _normalize(self, report: dict, ctx: Context, ref: str):
        behavior = report.get("behavior", {})
        # Process tree
        for proc in behavior.get("processes", []):
            yield ctx.ev(
                source="dynamic.windows.cape",
                artifact="process",
                operation="spawn",
                subject={"pid": proc.get("ppid"), "name": proc.get("parent_name")},
                object={"pid": proc.get("pid"), "name": proc.get("process_name")},
                details={"command_line": proc.get("command_line")},
                confidence=0.9,
                evidence_refs=[ref],
            )
        # API calls of interest (injection etc.)
        for call in behavior.get("apistats_flat", []):
            yield ctx.ev(
                source="dynamic.windows.cape",
                artifact="api_call",
                operation="exec",
                subject={"analyzer": self.name},
                object={"api": call},
                details={},
                confidence=0.7,
                evidence_refs=[ref],
            )
        # Network
        for host in report.get("network", {}).get("hosts", []):
            yield ctx.ev(
                source="dynamic.windows.cape",
                artifact="network",
                operation="connect",
                subject={"analyzer": self.name},
                object={"host": host},
                details={"note": "egress observed (routed to simulated network)"},
                confidence=0.8,
                evidence_refs=[ref],
            )
        # Dropped files
        for f in report.get("dropped", []):
            yield ctx.ev(
                source="dynamic.windows.cape",
                artifact="file",
                operation="create",
                subject={"analyzer": self.name},
                object={"path": f.get("name"), "sha256": f.get("sha256")},
                details={},
                confidence=0.8,
                evidence_refs=[ref],
            )
        # Registry
        for key in behavior.get("regkey_written", []):
            yield ctx.ev(
                source="dynamic.windows.cape",
                artifact="registry",
                operation="write",
                subject={"analyzer": self.name},
                object={"key": key},
                details={},
                confidence=0.75,
                evidence_refs=[ref],
            )


def register(registry) -> None:
    registry.register(WindowsCapeAnalyzer())
