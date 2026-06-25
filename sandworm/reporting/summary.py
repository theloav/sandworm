"""Executive summary + (conservative) family hint.

The one-page-at-the-top view analysts and managers read first. Every line is
phrased to respect epistemic standing: it states the analysis mode and whether
runtime was observed, so "Primary capability: ransomware (inferred)" is never
mistaken for a confirmed detonation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore
from ..core.provenance import OBSERVED
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

    # Risk must rest on the STRENGTH of evidence, not merely the presence of a
    # tactic — otherwise legitimate software trips it (a benign app importing
    # CreateProcess + RegSetValueEx + a networking call nominally "has" execution,
    # persistence and C2). High/Critical therefore require a concrete capability
    # or corroboration; a bag of weak, dual-use single-import inferences does not.
    credible = sum(1 for m in mappings if m.status == OBSERVED or m.confidence >= 0.6)
    observed_malicious = any(m.status == OBSERVED for m in mappings)
    strong_capability = (
        _has_capability(store, "ransomware")
        or _has_capability(store, "inhibit_recovery")
        or _has_verdict(store, "php_webshell")
        or "T1055" in tids
        or n_sinks >= 2
        or family != "unknown"
        or observed_malicious
    )

    if "impact" in tactics:                                   # only fires from a real impact capability
        risk = "Critical"
    elif strong_capability or "credential-access" in tactics or (credible >= 2 and summary_net >= 1):
        risk = "High"
    elif credible >= 1 or summary_net >= 2 or n_sinks == 1:
        risk = "Medium"
    else:                                                     # only weak, dual-use single-import signals
        risk = "Low"

    # Likelihood that this is genuinely malicious (vs. benign software whose
    # imports merely *resemble* malicious capability).
    if strong_capability or n_sinks >= 3:
        likelihood = "High"
    elif credible >= 1 or summary_net >= 2:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    if not reasons:
        reasons.append("No strong malicious indicators identified")
    return risk, likelihood, reasons


# Maliciousness is a confidence-weighted sum over *capability axes*, not a flat
# bag of fixed points. Each axis contributes its severity weight scaled by the
# STANDING of the evidence behind it — so runtime-observed behaviour counts for
# more than a static inference, and a weak speculative signal counts for less.
# This ties the score directly to the observed/inferred/speculative taxonomy and
# credits whole behaviour dimensions (persistence, discovery, anti-analysis,
# packing, collection) the old fixed model ignored. Raw evidence COUNT no longer
# moves the score — capability does.
_STANDING_FACTOR = {"observed": 1.15, "inferred": 1.0, "speculative": 0.6}

# axis severity weights (inferred baseline; observed gets +15%, speculative −40%).
_AXIS_WEIGHTS = {
    "technique": 10,        # flat: at least one real ATT&CK technique mapped
    "ransomware": 40,
    "inhibit_recovery": 16,
    "webshell": 40,
    "injection": 40,
    "credential_access": 24,
    "persistence": 16,
    "c2": 14,
    "exec_sinks": 14,
    "discovery": 9,
    "evasion": 9,           # anti-analysis: sandbox/debugger evasion
    "obfuscation": 11,      # packing / obfuscation / runtime unpacking
    "collection": 11,
    "family": 16,
}


def _axis_standing(mappings: list[AttackMapping], tids: tuple[str, ...] = (), tactics: tuple[str, ...] = ()) -> str | None:
    """Best epistemic standing among the mappings anchoring an axis (so the axis
    is weighted by how well-supported it is)."""
    order = {"observed": 3, "inferred": 2, "speculative": 1}
    cand = [m for m in mappings if m.technique_id in tids or m.tactic in tactics]
    if not cand:
        return None
    return max(cand, key=lambda m: order.get(m.status, 0)).status


def _maliciousness(store: EvidenceStore, mappings: list[AttackMapping], net: int, family: str) -> tuple[int, list[tuple[str, int]]]:
    factors: list[tuple[str, int]] = []
    tids = {m.technique_id for m in mappings}
    tactics = {m.tactic for m in mappings}
    n_sinks = _exec_sink_count(store)

    def axis(present: bool, key: str, label: str, *, tids_: tuple[str, ...] = (),
             tactics_: tuple[str, ...] = (), standing: str | None = None, scale: bool = True) -> None:
        if not present:
            return
        st = standing or _axis_standing(mappings, tids_, tactics_) or "speculative"
        base = _AXIS_WEIGHTS[key]
        pts = round(base * _STANDING_FACTOR[st]) if scale else base
        if pts:
            factors.append((f"{label} ({st})" if scale else label, pts))

    axis(bool(mappings), "technique", "Malicious ATT&CK technique mapped", tids_=tuple(tids), scale=False)
    axis(_has_capability(store, "ransomware"), "ransomware", "Ransomware / encryption for impact", tids_=("T1486",))
    axis(_has_capability(store, "inhibit_recovery"), "inhibit_recovery", "Inhibit system recovery", tids_=("T1490",))
    axis(_has_verdict(store, "php_webshell"), "webshell", "Interactive web shell", tids_=("T1505.003",))
    axis("T1055" in tids, "injection", "Process injection / loader", tids_=("T1055",))
    axis("credential-access" in tactics, "credential_access", "Credential access", tactics_=("credential-access",))
    axis("persistence" in tactics, "persistence", "Persistence mechanism", tactics_=("persistence",))
    axis(bool(net) or "command-and-control" in tactics, "c2", "Network / C2 capability", tactics_=("command-and-control",))
    axis(n_sinks >= 2, "exec_sinks", f"Multiple execution sinks ({n_sinks})", tids_=("T1059",))
    axis("discovery" in tactics, "discovery", "Host / network discovery", tactics_=("discovery",))
    axis(bool({"T1497", "T1622"} & tids), "evasion", "Anti-analysis / evasion", tids_=("T1497", "T1622"))
    axis(bool({"T1027", "T1140"} & tids) or any(it.operation == "decode" for it in store),
         "obfuscation", "Obfuscation / packing", tids_=("T1027", "T1140"))
    axis("collection" in tactics, "collection", "Collection / capture", tactics_=("collection",))
    axis(family != "unknown", "family", f"Family fingerprint ({family})", standing="inferred")

    raw = sum(p for _, p in factors)
    # Diminishing returns: once a sample stacks several strong capabilities the
    # extra points are real but redundant. A flat additive sum blows past 100 and
    # everything pins to the ceiling, losing all differentiation in the high band.
    # So we leave low/mid scores untouched and asymptotically compress only the
    # top, surfaced as an explicit (negative) factor so the table still sums.
    if raw > _DR_KNEE:
        compressed = round(_DR_KNEE + (100 - _DR_KNEE) * (1 - math.exp(-(raw - _DR_KNEE) / _DR_SCALE)))
        factors.append(("Diminishing returns (overlapping capabilities)", compressed - raw))
    else:
        compressed = raw
    # Static analysis alone can never fully confirm malice -> cap below 100 and
    # show the caveat as an explicit negative factor.
    observed = any(provenance_observed(it) for it in store)
    if not observed and factors:
        factors.append(("No runtime confirmation (static only)", -4))
        score = max(0, min(96, compressed - 4))
    else:
        score = min(100, compressed)
    return score, factors


# Maliciousness diminishing-returns curve: scores at/below the knee are additive
# and untouched; above it, extra capability is compressed and approaches 100.
_DR_KNEE = 80
_DR_SCALE = 40


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
