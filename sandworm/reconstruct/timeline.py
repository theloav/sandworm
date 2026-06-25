"""Causal timeline from evidence.

Orders EvidenceItems into a readable sequence. Where timestamps exist (dynamic
lane) they drive ordering; otherwise insertion order is used as a monotonic
proxy. Each entry is a compact, human-readable line plus its backing evidence id.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.evidence import EvidenceStore


@dataclass
class TimelineEntry:
    seq: int
    ts: str
    source: str
    text: str
    confidence: float
    evidence_id: str


def _describe(it) -> str:
    obj = it.object
    target = (
        obj.get("sink")
        or obj.get("path")
        or obj.get("host")
        or obj.get("value")
        or obj.get("key")
        or obj.get("function")
        or obj.get("verdict")
        or obj.get("command")
        or obj.get("layer")
        or it.artifact
    )
    verb = {
        "decode": "decoded layer",
        "exec": "executed/flagged sink",
        "connect": "network egress to",
        "write": "wrote",
        "read": "read",
        "spawn": "spawned",
        "inject": "injected into",
        "create": "created",
        "resolve": "resolved/imported",
    }.get(it.operation, it.operation)
    return f"[{it.source}] {verb} {target}"


def build_timeline(store: EvidenceStore) -> list[TimelineEntry]:
    items = list(store)
    # Sort by ts when comparable; fall back to original order.
    indexed = list(enumerate(items))
    try:
        indexed.sort(key=lambda p: (p[1].ts, p[0]))
    except Exception:
        pass
    out: list[TimelineEntry] = []
    for seq, (_orig, it) in enumerate(indexed):
        out.append(
            TimelineEntry(
                seq=seq,
                ts=it.ts,
                source=it.source,
                text=_describe(it),
                confidence=it.confidence,
                evidence_id=it.id,
            )
        )
    return out
