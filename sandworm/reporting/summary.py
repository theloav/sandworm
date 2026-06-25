"""Executive summary + (conservative) family hint.

The one-page-at-the-top view analysts and managers read first. Every line is
phrased to respect epistemic standing: it states the analysis mode and whether
runtime was observed, so "Primary capability: ransomware (inferred)" is never
mistaken for a confirmed detonation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore
from ..reconstruct.attack_map import AttackMapping
from ..reconstruct.narrative import (
    Phase,
    highest_inferred_phase,
    highest_observed_phase,
    runtime_observed,
)

# Conservative family fingerprints: (family, [required distinctive markers]).
# A hint is only emitted when a HIGH-signal marker is present — we would rather
# say "unknown" than misattribute.
_FAMILY_FINGERPRINTS = [
    ("WannaCry", ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea"]),
    ("WannaCry", [".wnry"]),
    ("WannaCry", ["wanadecryptor"]),
    ("Petya/NotPetya", ["wmic shadow", "wevtutil cl"]),
]

# Tactics that represent a primary "what does it do" capability, most-severe first.
_PRIMARY_TACTIC_ORDER = [
    ("impact", "destructive / ransomware impact"),
    ("credential-access", "credential theft"),
    ("collection", "data collection"),
    ("exfiltration", "data exfiltration"),
    ("persistence", "persistence"),
    ("command-and-control", "command-and-control"),
    ("execution", "code execution"),
]


@dataclass
class ExecutiveSummary:
    analysis_mode: str            # "static only" | "static + dynamic"
    runtime_observed: bool
    highest_observed_phase: str
    highest_inferred_phase: str
    family_hint: str              # "unknown" if not confidently fingerprinted
    family_confidence: float
    primary_capability: str
    technique_count: int
    network_indicator_count: int
    top_techniques: list[str] = field(default_factory=list)


def _family_hint(store: EvidenceStore) -> tuple[str, float]:
    # Scan IOC values + capability indicators for distinctive markers.
    hay_parts: list[str] = []
    for it in store:
        for k in ("value", "indicators", "yara_rule", "capability"):
            v = it.object.get(k)
            if v:
                hay_parts.append(str(v))
    hay = " ".join(hay_parts).lower()
    for family, markers in _FAMILY_FINGERPRINTS:
        if all(m.lower() in hay for m in markers):
            return family, 0.95
    return "unknown", 0.0


def _primary_capability(mappings: list[AttackMapping]) -> str:
    tactics = {m.tactic for m in mappings}
    for tactic, label in _PRIMARY_TACTIC_ORDER:
        if tactic in tactics:
            # qualify with epistemic standing of that tactic's strongest mapping
            best = max((m for m in mappings if m.tactic == tactic), key=lambda m: m.confidence)
            return f"{label} ({best.status})"
    return "no clear malicious capability"


def build_summary(
    store: EvidenceStore,
    mappings: list[AttackMapping],
    phases: list[Phase],
    *,
    isolated: bool,
) -> ExecutiveSummary:
    family, fam_conf = _family_hint(store)
    net = len([it for it in store if it.details.get("ioc") and it.object.get("kind") in {"url", "domain", "ipv4"}])
    top = [f"{m.technique_id} {m.technique_name}" for m in sorted(mappings, key=lambda m: -m.confidence)[:5]]
    return ExecutiveSummary(
        analysis_mode="static + dynamic" if isolated else "static only",
        runtime_observed=runtime_observed(phases),
        highest_observed_phase=highest_observed_phase(phases),
        highest_inferred_phase=highest_inferred_phase(phases),
        family_hint=family,
        family_confidence=fam_conf,
        primary_capability=_primary_capability(mappings),
        technique_count=len(mappings),
        network_indicator_count=net,
        top_techniques=top,
    )
