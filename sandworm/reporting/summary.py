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
    execution_confirmed: bool
    highest_observed_phase: str
    highest_inferred_phase: str
    family_hint: str              # "unknown" if not confidently fingerprinted
    family_confidence: float
    family_markers: list[str]     # what matched (explainable attribution)
    primary_capability: str
    risk: str                     # Critical | High | Medium | Low
    likelihood: str               # High | Medium | Low
    risk_reasons: list[str]
    technique_count: int
    network_indicator_count: int
    top_techniques: list[str] = field(default_factory=list)


def _family_hint(store: EvidenceStore) -> tuple[str, float, list[str]]:
    """Return (family, similarity, matched_markers). Explainable: we surface the
    exact markers that fired rather than a bare score."""
    hay_parts: list[str] = []
    for it in store:
        for k in ("value", "indicators", "yara_rule", "capability"):
            v = it.object.get(k)
            if v:
                hay_parts.append(str(v))
    hay = " ".join(hay_parts).lower()
    for family, markers in _FAMILY_FINGERPRINTS:
        if all(m.lower() in hay for m in markers):
            return family, 0.95, list(markers)
    return "unknown", 0.0, []


def _has_verdict(store: EvidenceStore, verdict: str) -> bool:
    return any(it.object.get("verdict") == verdict for it in store)


def _has_capability(store: EvidenceStore, capability: str) -> bool:
    return any(it.object.get("capability") == capability for it in store)


def _primary_capability(store: EvidenceStore, mappings: list[AttackMapping]) -> str:
    if _has_verdict(store, "php_webshell"):
        best = max((m for m in mappings if m.technique_id == "T1505.003"), key=lambda m: m.confidence, default=None)
        return f"interactive web shell — remote command execution ({best.status if best else 'inferred'})"
    tactics = {m.tactic for m in mappings}
    for tactic, label in _PRIMARY_TACTIC_ORDER:
        if tactic in tactics:
            best = max((m for m in mappings if m.tactic == tactic), key=lambda m: m.confidence)
            return f"{label} ({best.status})"
    return "no clear malicious capability"


def _exec_sink_count(store: EvidenceStore) -> int:
    sinks = {it.object.get("sink") for it in store if it.artifact == "api_call" and it.operation == "exec" and it.object.get("sink")}
    return len(sinks)


def _risk(store: EvidenceStore, mappings: list[AttackMapping], summary_net: int, family: str) -> tuple[str, str, list[str]]:
    tactics = {m.tactic for m in mappings}
    tids = {m.technique_id for m in mappings}
    reasons: list[str] = []

    n_sinks = _exec_sink_count(store)
    if n_sinks >= 2:
        reasons.append(f"Multiple independent execution sinks ({n_sinks})")
    if _has_verdict(store, "php_webshell"):
        reasons.append("Web-shell heuristic matched (obfuscation/sink + attacker input)")
    if summary_net:
        reasons.append(f"Embedded network infrastructure ({summary_net} indicator(s))")
    if any(it.object.get("sink") in {"move_uploaded_file", "file_put_contents", "fwrite"} for it in store):
        reasons.append("Interactive file upload / write capability")
    if _has_capability(store, "inhibit_recovery"):
        reasons.append("Shadow-copy / backup deletion (anti-recovery)")
    if _has_capability(store, "ransomware"):
        reasons.append("Ransomware encryption indicators")
    if "T1055" in tids:
        reasons.append("Process-injection primitives present")
    if family != "unknown":
        reasons.append(f"Static fingerprint match: {family}")

    # Risk: severity of the worst capability.
    if "impact" in tactics:
        risk = "Critical"
    elif _has_verdict(store, "php_webshell") or "credential-access" in tactics or "T1055" in tids or (
        "execution" in tactics and {"persistence", "command-and-control"} & tactics
    ):
        risk = "High"
    elif tactics & {"execution", "command-and-control", "discovery"}:
        risk = "Medium"
    else:
        risk = "Low"

    # Likelihood that this is genuinely malicious and would execute.
    if family != "unknown" or _has_verdict(store, "php_webshell") or n_sinks >= 3 or _has_capability(store, "ransomware"):
        likelihood = "High"
    elif mappings:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    if not reasons:
        reasons.append("No strong malicious indicators identified")
    return risk, likelihood, reasons


def build_summary(
    store: EvidenceStore,
    mappings: list[AttackMapping],
    phases: list[Phase],
    *,
    isolated: bool,
) -> ExecutiveSummary:
    family, fam_conf, markers = _family_hint(store)
    net = len([it for it in store if it.details.get("ioc") and it.object.get("kind") in {"url", "domain", "ipv4"}])
    top = [f"{m.technique_id} {m.technique_name}" for m in sorted(mappings, key=lambda m: -m.confidence)[:5]]
    risk, likelihood, reasons = _risk(store, mappings, net, family)
    return ExecutiveSummary(
        analysis_mode="static + dynamic" if isolated else "static only",
        runtime_observed=runtime_observed(phases),
        execution_confirmed=runtime_observed(phases),
        highest_observed_phase=highest_observed_phase(phases),
        highest_inferred_phase=highest_inferred_phase(phases),
        family_hint=family,
        family_confidence=fam_conf,
        family_markers=markers,
        primary_capability=_primary_capability(store, mappings),
        risk=risk,
        likelihood=likelihood,
        risk_reasons=reasons,
        technique_count=len(mappings),
        network_indicator_count=net,
        top_techniques=top,
    )
