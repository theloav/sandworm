"""Bounded normalization of sample-bound Linux/script/CPU trace artifacts."""

from __future__ import annotations

from ..analyzers.base import Context
from ..core.evidence import EvidenceItem, EvidenceLocation


def normalize_runtime(report: dict, ctx: Context) -> list[EvidenceItem]:
    from ..analyzers.dynamic.linux_sandbox import normalize_strace
    from ..analyzers.dynamic.php_runtime import normalize_php_trace
    from ..analyzers.dynamic.script_runtime import normalize_shell_trace
    from ..analyzers.memory.diffsnap import diff_processes
    from ..core.evidence import EvidenceStore
    from ..enrich.canary import Canary, CanarySet, detect

    normalizers = {"linux": normalize_strace, "php": normalize_php_trace, "shell": normalize_shell_trace}
    ref = "sample:" + report["target_sha256"]
    items: list[EvidenceItem] = []
    for trace in report.get("traces", [])[:16]:
        kind = trace.get("kind")
        if kind not in normalizers:
            raise ValueError(f"unsupported trace kind: {kind}")
        text = trace.get("text", "")
        if not isinstance(text, str) or len(text) > 8 * 1024**2:
            raise ValueError("trace exceeds the supported size")
        items.extend(normalizers[kind](text, ctx, ref))
        if len(items) > 50000:
            raise ValueError("too many runtime events")
    for row in report.get("cpu_trace", [])[:50000]:
        # Input is decoded branch data (e.g. perf/libipt or DRAKVUF output), not
        # raw Intel PT bytes. Do not claim to decode hardware packet streams.
        items.append(ctx.ev(source="dynamic.cpu_trace", artifact="instruction", operation="branch",
                            subject={"pid": row.get("pid")}, object={"target": row.get("target")},
                            locations=[EvidenceLocation.model_validate(row["location"])],
                            details={"capture": report.get("capture", "imported decoded trace")},
                            confidence=0.8, evidence_refs=[ref]))
    before, after = report.get("baseline_processes"), report.get("post_processes")
    if isinstance(before, list) and isinstance(after, list):
        for process in diff_processes(before, after):
            items.append(ctx.ev(source="memory.diffsnap", artifact="process", operation="spawn",
                                object=process, confidence=0.7, evidence_refs=[ref]))
    canaries = report.get("canaries", [])
    if canaries:
        observed = EvidenceStore()
        observed.extend(items)
        tokens = CanarySet([Canary(**c) for c in canaries[:32]])
        items.extend(detect(observed, tokens, ctx.run_id))
    return items
