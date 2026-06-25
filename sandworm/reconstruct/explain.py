"""Make confidence explainable: where did a technique's score come from, and how
would it evolve as static -> dynamic -> memory evidence accumulates.

This turns ``confidence = 0.68`` from a magic number into an auditable breakdown
(which analyzer lanes contributed, and by how much) plus a forward-looking
"confidence timeline" that shows the static value now and what is still *pending*
from the dynamic and memory lanes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore
from .attack_map import AttackMapping

_LANES = ("static", "dynamic", "memory")


def _lane_of(source: str) -> str:
    if source.startswith("dynamic."):
        return "dynamic"
    if source.startswith("memory."):
        return "memory"
    return "static"  # static.* / plugin.* / enrich.*


def _method_of(it) -> str:
    """The detection *method* behind a finding (what kind of analysis produced
    it), so confidence can be explained as 'execution sink 40% / signature 30%'
    rather than just naming the analyzer."""
    obj = it.object
    if obj.get("yara_rule"):
        return "signature match"
    if it.operation == "decode":
        return "deobfuscation"
    if obj.get("sink"):
        return "execution sink"
    if obj.get("import") or obj.get("symbol") or obj.get("api"):
        return "import/API analysis"
    if obj.get("capability"):
        return "capability heuristic"
    if obj.get("verdict"):
        return "heuristic verdict"
    if obj.get("value") or obj.get("kind") in {"url", "domain", "ipv4"}:
        return "string/IOC"
    if it.source.startswith(("dynamic.", "memory.")):
        return "runtime observation"
    return "static heuristic"


@dataclass
class ConfidenceBreakdown:
    technique_id: str
    final_confidence: float
    by_source: dict[str, int]                 # source -> % contribution
    by_method: dict[str, int]                 # detection method -> % contribution
    lane_confidence: dict[str, float | None]  # static/dynamic/memory -> best conf or None (pending)
    contributions: list[tuple[str, float]] = field(default_factory=list)

    def lane_timeline(self) -> list[tuple[str, str]]:
        """(lane, "0.68" | "pending") in static->dynamic->memory order."""
        out = []
        for lane in _LANES:
            v = self.lane_confidence.get(lane)
            out.append((lane, f"{v:.2f}" if v is not None else "pending"))
        return out


def confidence_breakdown(store: EvidenceStore, mapping: AttackMapping) -> ConfidenceBreakdown:
    fetched = [store.get(eid) for eid in mapping.evidence_ids]
    items = [it for it in fetched if it is not None]

    by_source_raw: dict[str, float] = {}
    by_method_raw: dict[str, float] = {}
    lane_best: dict[str, float | None] = {ln: None for ln in _LANES}
    contributions: list[tuple[str, float]] = []
    for it in items:
        by_source_raw[it.source] = max(by_source_raw.get(it.source, 0.0), it.confidence)
        method = _method_of(it)
        by_method_raw[method] = by_method_raw.get(method, 0.0) + it.confidence
        lane = _lane_of(it.source)
        cur = lane_best[lane]
        lane_best[lane] = it.confidence if cur is None else max(cur, it.confidence)
        contributions.append((it.source, it.confidence))

    total = sum(by_source_raw.values()) or 1.0
    by_source = {s: round(100 * v / total) for s, v in sorted(by_source_raw.items(), key=lambda kv: -kv[1])}
    mtotal = sum(by_method_raw.values()) or 1.0
    by_method = {m: round(100 * v / mtotal) for m, v in sorted(by_method_raw.items(), key=lambda kv: -kv[1])}

    return ConfidenceBreakdown(
        technique_id=mapping.technique_id,
        final_confidence=mapping.confidence,
        by_source=by_source,
        by_method=by_method,
        lane_confidence=lane_best,
        contributions=contributions,
    )
