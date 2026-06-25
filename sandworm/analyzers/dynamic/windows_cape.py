"""Adapter to an existing Windows sandbox backend (CAPE / DRAKVUF).

SANDWORM does NOT build hypervisor instrumentation. This adapter submits the PE to
a CAPE/DRAKVUF instance (or ingests a pre-produced report) and normalizes its
process/file/registry/network/api output into EvidenceItems.

Two distinct modes, with very different safety properties:

* **Live detonation** (submitting the sample to a sandbox) requires the verified
  isolation gate — this analyzer is ``requires_isolation = True`` so the registry
  only dispatches it inside a network-isolated detonation environment.
* **Replay** of a *recorded* CAPE report (``normalize_cape_report``) is NOT
  detonation: it ingests evidence produced by a prior, properly-isolated run. It
  executes nothing, so it is as safe as static analysis and may run offline. The
  pipeline calls the module-level normalizer directly for this — it does not pass
  through the detonation gate.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

SOURCE = "dynamic.windows.cape"


def normalize_cape_report(report: dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Normalize a CAPE/DRAKVUF JSON report into EvidenceItems.

    This is pure data transformation over an already-produced report — it never
    executes the sample, so it is safe to call without the isolation gate.
    """
    behavior = report.get("behavior", {})
    # Process tree (parent → child), the substrate for the runtime process graph.
    for proc in behavior.get("processes", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="process",
            operation="spawn",
            subject={"pid": proc.get("ppid"), "name": proc.get("parent_name")},
            object={"pid": proc.get("pid"), "name": proc.get("process_name")},
            details={"command_line": proc.get("command_line")},
            confidence=0.9,
            evidence_refs=[ref],
        )
    # API calls of interest (injection etc.). Mapped to ATT&CK via has_sink.
    for call in behavior.get("apistats_flat", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="api_call",
            operation="exec",
            subject={"analyzer": SOURCE},
            object={"api": call},
            details={},
            confidence=0.7,
            evidence_refs=[ref],
        )
    # Network egress, routed to the simulated responder during detonation.
    for host in report.get("network", {}).get("hosts", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="network",
            operation="connect",
            subject={"analyzer": SOURCE},
            object={"kind": "ipv4" if _looks_ipv4(str(host)) else "domain", "value": host, "host": host},
            details={"ioc": True, "false_positive_risk": "low", "note": "egress observed (routed to simulated network)"},
            confidence=0.85,
            evidence_refs=[ref],
        )
    # Dropped files.
    for f in report.get("dropped", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="file",
            operation="create",
            subject={"analyzer": SOURCE},
            object={"path": f.get("name"), "sha256": f.get("sha256")},
            details={},
            confidence=0.8,
            evidence_refs=[ref],
        )
    # Registry persistence writes.
    for key in behavior.get("regkey_written", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="registry",
            operation="write",
            subject={"analyzer": SOURCE},
            object={"key": key},
            details={},
            confidence=0.75,
            evidence_refs=[ref],
        )


def _looks_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


class WindowsCapeAnalyzer(BaseAnalyzer):
    name = SOURCE
    handles = {"pe"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        report_path = ctx.extra.get("cape_report")
        if not report_path or not Path(report_path).exists():
            return [
                ctx.ev(
                    source=SOURCE,
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
        return list(normalize_cape_report(report, ctx, ref))


def register(registry) -> None:
    registry.register(WindowsCapeAnalyzer())
