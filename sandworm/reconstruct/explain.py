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
    signals: list[str] = field(default_factory=list)   # the concrete atoms that fired
    contributions: list[tuple[str, float]] = field(default_factory=list)
    prior: float = 0.0                        # Bayesian base rate the posterior updated from
    lane_posterior: dict[str, float] = field(default_factory=dict)  # per-lane fused posteriors

    def bayes_chain(self) -> list[tuple[str, str]]:
        """(label, value) steps of the Bayesian update, for display:
        prior → each lane's fused posterior → aggregate."""
        out: list[tuple[str, str]] = [("prior", f"{self.prior:.2f}")] if self.prior else []
        for lane in _LANES:
            if lane in self.lane_posterior:
                out.append((lane, f"{self.lane_posterior[lane]:.2f}"))
        out.append(("aggregate", f"{self.final_confidence:.2f}"))
        return out

    def lane_timeline(self) -> list[tuple[str, str]]:
        """(lane, "0.68" | "pending") in static->dynamic->memory order."""
        out = []
        for lane in _LANES:
            v = self.lane_confidence.get(lane)
            out.append((lane, f"{v:.2f}" if v is not None else "pending"))
        return out


def _signal_of(it) -> str:
    """A short, human label for the concrete atom that fired (for the
    '+exec(), +proc_open(), +outbound URL' style explanation)."""
    obj = it.object
    if obj.get("sink"):
        return str(obj["sink"]) + "()"
    if obj.get("import") or obj.get("symbol") or obj.get("api"):
        return str(obj.get("import") or obj.get("symbol") or obj.get("api"))
    if obj.get("kind") in {"url", "domain", "ipv4"}:
        return f"{obj.get('kind')}:{obj.get('value')}"
    if obj.get("capability"):
        return str(obj["capability"]) + " indicators"
    if obj.get("verdict"):
        return str(obj["verdict"])
    if obj.get("yara_rule"):
        return "YARA:" + str(obj["yara_rule"])
    if it.operation == "decode":
        return "deobfuscated layer"
    return ""


def confidence_breakdown(store: EvidenceStore, mapping: AttackMapping) -> ConfidenceBreakdown:
    fetched = [store.get(eid) for eid in mapping.evidence_ids]
    items = [it for it in fetched if it is not None]

    by_source_raw: dict[str, float] = {}
    by_method_raw: dict[str, float] = {}
    lane_best: dict[str, float | None] = {ln: None for ln in _LANES}
    contributions: list[tuple[str, float]] = []
    signals: list[str] = []
    for it in items:
        by_source_raw[it.source] = max(by_source_raw.get(it.source, 0.0), it.confidence)
        method = _method_of(it)
        by_method_raw[method] = by_method_raw.get(method, 0.0) + it.confidence
        lane = _lane_of(it.source)
        cur = lane_best[lane]
        lane_best[lane] = it.confidence if cur is None else max(cur, it.confidence)
        contributions.append((it.source, it.confidence))
        atom = _signal_of(it)
        if atom and atom not in signals:
            signals.append(atom)

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
        signals=signals[:8],
        contributions=contributions,
        prior=mapping.prior,
        lane_posterior=mapping.lane_posterior,
    )
