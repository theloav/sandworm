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
    start = report.get("start_time")  # ISO; lets the timeline show absolute times too

    def _t(details: dict, t: object) -> dict:
        # A relative offset (seconds from process start) recorded by the sandbox
        # drives the temporal timeline. Stored in details so the causal timeline
        # (which sorts on EvidenceItem.ts) is unaffected.
        if isinstance(t, (int, float)):
            details = {**details, "t_offset": float(t), "t_label": f"T+{float(t):.3f}s"}
            if start:
                details["t_start"] = start
        return details

    # Process tree (parent → child), the substrate for the runtime process graph.
    for proc in behavior.get("processes", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="process",
            operation="spawn",
            subject={"pid": proc.get("ppid"), "name": proc.get("parent_name")},
            object={"pid": proc.get("pid"), "name": proc.get("process_name")},
            details=_t({"command_line": proc.get("command_line")}, proc.get("t")),
            confidence=0.9,
            evidence_refs=[ref],
        )
    # API calls of interest (injection etc.). Mapped to ATT&CK via has_sink. A
    # structured ``api_calls: [{api, t}]`` carries per-call timing; ``apistats_flat``
    # (a bare list) stays supported for reports without timestamps.
    api_events = behavior.get("api_calls") or [{"api": a} for a in behavior.get("apistats_flat", [])]
    for call in api_events:
        api = call.get("api") if isinstance(call, dict) else call
        yield ctx.ev(
            source=SOURCE,
            artifact="api_call",
            operation="exec",
            subject={"analyzer": SOURCE},
            object={"api": api},
            details=_t({}, call.get("t") if isinstance(call, dict) else None),
            confidence=0.7,
            evidence_refs=[ref],
        )
    # Network egress, routed to the simulated responder during detonation. Hosts
    # may be a bare string or ``{host, t}``.
    for host in report.get("network", {}).get("hosts", []):
        hv = host.get("host") if isinstance(host, dict) else host
        yield ctx.ev(
            source=SOURCE,
            artifact="network",
            operation="connect",
            subject={"analyzer": SOURCE},
            object={"kind": "ipv4" if _looks_ipv4(str(hv)) else "domain", "value": hv, "host": hv},
            details=_t({"ioc": True, "false_positive_risk": "low", "note": "egress observed (routed to simulated network)"},
                       host.get("t") if isinstance(host, dict) else None),
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
            details=_t({}, f.get("t")),
            confidence=0.8,
            evidence_refs=[ref],
        )
    # Registry persistence writes. Entries may be a bare string or ``{key, t}``.
    for key in behavior.get("regkey_written", []):
        kv = key.get("key") if isinstance(key, dict) else key
        yield ctx.ev(
            source=SOURCE,
            artifact="registry",
            operation="write",
            subject={"analyzer": SOURCE},
            object={"key": kv},
            details=_t({}, key.get("t") if isinstance(key, dict) else None),
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
