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
    family_confidence_label: str  # qualitative standing of the attribution (e.g. "Medium")
    family_basis: str             # what the similarity is computed from
    family_markers: list[str]     # what matched (explainable attribution)
    family_components: list[tuple[str, str]]  # per-dimension attribution breakdown
    primary_capability: str
    risk: str                     # Critical | High | Medium | Low
    likelihood: str               # High | Medium | Low
    risk_reasons: list[str]
    maliciousness_score: int                      # 0-100, explainable
    score_factors: list[tuple[str, int]]          # (reason, +/- points)
    evidence_maturity: list[tuple[str, str]]      # (lane, "complete"|"pending")
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
    tids = {m.technique_id for m in mappings}
    tactics = {m.tactic for m in mappings}

    def _status(*technique_ids: str) -> str:
        cand = [m for m in mappings if m.technique_id in technique_ids]
        return max(cand, key=lambda m: m.confidence).status if cand else "inferred"

    # Specific, recognisable capability verdicts first (most informative).
    if _has_verdict(store, "php_webshell"):
        return f"interactive web shell — remote command execution ({_status('T1505.003')})"
    if _has_capability(store, "ransomware") or "T1486" in tids:
        return f"ransomware — data encryption for impact ({_status('T1486')})"
    if "T1055" in tids:
        # injection without its own exec evidence reads as a loader/injector
        return f"process injection / loader ({_status('T1055')})"
    if "T1486" in tids or "impact" in tactics:
        return f"destructive impact ({_status('T1486')})"

    for tactic, label in _PRIMARY_TACTIC_ORDER:
        if tactic in tactics:
            best = max((m for m in mappings if m.tactic == tactic), key=lambda m: m.confidence)
            return f"{label} ({best.status})"
    # We still mapped techniques even if none is a 'primary' tactic — don't claim
    # "no clear capability" when ATT&CK techniques exist.
    if mappings:
        top = max(mappings, key=lambda m: m.confidence)
        return f"{top.technique_name} ({top.status})"
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


# Points each signal contributes to the 0-100 maliciousness score. Calibrated so
# that a single serious capability (injection / web shell / ransomware) lands a
# sample firmly in the High band, and ransomware reaches Critical.
_SCORE_WEIGHTS = {
    "malicious_technique": 12,  # base: at least one real ATT&CK technique mapped
    "ransomware": 45,
    "inhibit_recovery": 20,
    "webshell": 40,
    "injection": 35,
    "exec_sinks": 18,
    "family": 18,
    "c2": 15,                   # network egress / C2 capability
    "upload": 10,
}


def _maliciousness(store: EvidenceStore, mappings: list[AttackMapping], net: int, family: str) -> tuple[int, list[tuple[str, int]]]:
    factors: list[tuple[str, int]] = []
    tids = {m.technique_id for m in mappings}
    if mappings:
        factors.append(("Malicious ATT&CK technique(s) present", _SCORE_WEIGHTS["malicious_technique"]))
    if _has_capability(store, "ransomware"):
        factors.append(("Ransomware / encryption indicators", _SCORE_WEIGHTS["ransomware"]))
    if _has_capability(store, "inhibit_recovery"):
        factors.append(("Shadow-copy / backup deletion", _SCORE_WEIGHTS["inhibit_recovery"]))
    if _has_verdict(store, "php_webshell"):
        factors.append(("Web-shell heuristic matched", _SCORE_WEIGHTS["webshell"]))
    if "T1055" in tids:
        factors.append(("Process-injection primitives", _SCORE_WEIGHTS["injection"]))
    n_sinks = _exec_sink_count(store)
    if n_sinks >= 2:
        factors.append((f"Multiple execution sinks ({n_sinks})", _SCORE_WEIGHTS["exec_sinks"]))
    if family != "unknown":
        factors.append((f"Static fingerprint match ({family})", _SCORE_WEIGHTS["family"]))
    if net:
        factors.append((f"Network egress / C2 indicators ({net})", _SCORE_WEIGHTS["c2"]))
    if any(it.object.get("sink") in {"move_uploaded_file", "file_put_contents"} for it in store):
        factors.append(("File upload / write capability", _SCORE_WEIGHTS["upload"]))
    # Breadth of corroborating evidence (capped) — more independent signals raise
    # confidence in the verdict.
    breadth = min(8, len(store) // 4)
    if breadth:
        factors.append((f"Breadth of corroborating evidence ({len(store)} items)", breadth))

    raw = sum(p for _, p in factors)
    # Static analysis alone can never fully confirm malice -> cap below 100 and
    # show the caveat as an explicit negative factor.
    observed = any(provenance_observed(it) for it in store)
    score = min(100 if observed else 96, raw)
    if not observed and factors:
        factors.append(("No runtime confirmation (static only)", -4))
        score = max(0, min(96, raw - 4))
    return score, factors


def provenance_observed(it) -> bool:
    return it.source.startswith(("dynamic.", "memory."))


def _evidence_maturity(store: EvidenceStore) -> list[tuple[str, str]]:
    has_dynamic = any(it.source.startswith("dynamic.") for it in store)
    has_memory = any(it.source.startswith("memory.") for it in store)
    return [
        ("static", "complete"),
        ("dynamic", "complete" if has_dynamic else "pending"),
        ("memory", "complete" if has_memory else "pending"),
    ]


def build_summary(
    store: EvidenceStore,
    mappings: list[AttackMapping],
    phases: list[Phase],
    *,
    isolated: bool,
) -> ExecutiveSummary:
    family, fam_conf, markers = _family_hint(store)
    # The similarity number is a static string/resource match only. Until runtime
    # corroborates it, the *standing* of the attribution is Medium, not High — so
    # an analyst never reads "95%" as a confirmed behavioral match.
    family_runtime_confirmed = runtime_observed(phases) and family != "unknown"
    family_confidence_label = "High" if family_runtime_confirmed else "Medium" if family != "unknown" else "—"
    family_basis = "static string/resource markers" + ("" if not family_runtime_confirmed else " + runtime")
    if family != "unknown":
        # Honest, transparent attribution: say which dimensions actually
        # contributed and which are still pending (so 95% is never mistaken for a
        # multi-signal behavioral match).
        family_components = [
            ("static string markers", "matched: " + ", ".join(markers)),
            ("strings/resources", "matched"),
            ("imports", "not yet analysed"),
            ("behaviour", "pending — requires dynamic execution"),
        ]
    else:
        family_components = []
    net = len([it for it in store if it.details.get("ioc") and it.object.get("kind") in {"url", "domain", "ipv4"}])
    top = [f"{m.technique_id} {m.technique_name}" for m in sorted(mappings, key=lambda m: -m.confidence)[:5]]
    risk, likelihood, reasons = _risk(store, mappings, net, family)
    score, factors = _maliciousness(store, mappings, net, family)
    maturity = _evidence_maturity(store)
    return ExecutiveSummary(
        analysis_mode="static + dynamic" if isolated else "static only",
        runtime_observed=runtime_observed(phases),
        execution_confirmed=runtime_observed(phases),
        highest_observed_phase=highest_observed_phase(phases),
        highest_inferred_phase=highest_inferred_phase(phases),
        family_hint=family,
        family_confidence=fam_conf,
        family_confidence_label=family_confidence_label,
        family_basis=family_basis,
        family_markers=markers,
        family_components=family_components,
        primary_capability=_primary_capability(store, mappings),
        risk=risk,
        likelihood=likelihood,
        risk_reasons=reasons,
        maliciousness_score=score,
        score_factors=factors,
        evidence_maturity=maturity,
        technique_count=len(mappings),
        network_indicator_count=net,
        top_techniques=top,
    )
