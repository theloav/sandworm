"""Causal timeline from evidence.

Orders EvidenceItems into a readable sequence. Where timestamps exist (dynamic
lane) they drive ordering; otherwise insertion order is used as a monotonic
proxy. Each entry is a compact, human-readable line plus its backing evidence id.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.evidence import EvidenceStore
from ..core.provenance import OBSERVED, provenance_of


@dataclass
class TimelineEntry:
    seq: int
    ts: str
    source: str
    text: str
    confidence: float
    evidence_id: str
    status: str = "inferred"  # observed | inferred | speculative


def _describe(it, status: str) -> str:
    obj = it.object
    target = (
        obj.get("sink")
        or obj.get("path")
        or obj.get("host")
        or obj.get("value")
        or obj.get("key")
        or obj.get("function")
        or obj.get("verdict")
        or obj.get("capability")
        or obj.get("command")
        or obj.get("layer")
        or it.artifact
    )
    if status == OBSERVED:
        # Runtime/memory: these are real events.
        verb = {
            "exec": "executed",
            "connect": "connected to",
            "write": "wrote",
            "read": "read",
            "spawn": "spawned",
            "inject": "injected into",
            "create": "created",
            "decode": "decoded",
            "resolve": "resolved",
        }.get(it.operation, it.operation)
    else:
        # Static: these are findings/capabilities, NOT observed events. Phrase
        # them as such so the timeline never implies the sample ran.
        verb = {
            "decode": "static: de-obfuscated layer",
            "exec": "static indicator: execution-capable sink",
            "connect": "static indicator: network capability",
            "write": "static indicator: file-write/encryption capability",
            "read": "static indicator",
            "resolve": "static indicator",
            "create": "static indicator",
            "inject": "static indicator: injection-capable API",
        }.get(it.operation, f"static: {it.operation}")
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
        status = provenance_of(it.source, it.confidence)
        out.append(
            TimelineEntry(
                seq=seq,
                ts=it.ts,
                source=it.source,
                text=_describe(it, status),
                confidence=it.confidence,
                evidence_id=it.id,
                status=status,
            )
        )
    return out
