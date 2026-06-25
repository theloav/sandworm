"""Ordered lifecycle phases -> attack narrative.

Buckets the ATT&CK mappings into malware lifecycle phases and reports how far
execution reached. The narrative is the human-facing "what happened, in order"
story; it is built entirely from mapped evidence so every sentence is grounded.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.provenance import OBSERVED, SPECULATIVE, strongest
from .attack_map import AttackMapping

# Lifecycle phases in canonical order.
LIFECYCLE_ORDER = [
    "execution", "unpack/deobfuscate", "injection", "discovery",
    "credential-access", "persistence", "command-and-control",
    "collection", "exfiltration", "impact",
]

# Default phase for each ATT&CK tactic.
_PHASE_BY_TACTIC = {
    "execution": "execution",
    "defense-evasion": "unpack/deobfuscate",
    "privilege-escalation": "injection",
    "discovery": "discovery",
    "reconnaissance": "discovery",
    "credential-access": "credential-access",
    "persistence": "persistence",
    "command-and-control": "command-and-control",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
}

# Per-technique overrides: a technique whose tactic's default phase would be
# misleading. e.g. Process Injection is tagged "defense-evasion" in ATT&CK, but
# in the *lifecycle* it belongs to injection — NOT to unpack/deobfuscate (where
# T1027 Obfuscated Files correctly lives). This is what stops T1027 and T1055
# from both appearing under "injection".
_PHASE_OVERRIDE = {
    "T1055": "injection",
    "T1055.001": "injection",
    "T1055.002": "injection",
    "T1055.003": "injection",
    "T1055.004": "injection",
    "T1055.012": "injection",
    "T1620": "injection",
}


def _phase_of(m: AttackMapping) -> str:
    return _PHASE_OVERRIDE.get(m.technique_id) or _PHASE_BY_TACTIC.get(m.tactic, "execution")


@dataclass
class Phase:
    name: str
    reached: bool
    techniques: list[AttackMapping]
    summary: str
    status: str = "speculative"  # observed | inferred | speculative (best in phase)


def build_narrative(mappings: list[AttackMapping]) -> list[Phase]:
    # Assign each technique to exactly ONE lifecycle phase so a technique never
    # appears under two phases (e.g. T1027 under both unpack and injection).
    by_phase: dict[str, list[AttackMapping]] = {name: [] for name in LIFECYCLE_ORDER}
    placed: set[str] = set()
    for m in mappings:
        if m.technique_id in placed:
            continue
        placed.add(m.technique_id)
        by_phase[_phase_of(m)].append(m)

    phases: list[Phase] = []
    for name in LIFECYCLE_ORDER:
        uniq = by_phase[name]
        reached = bool(uniq)
        status = strongest([m.status for m in uniq]) if uniq else SPECULATIVE
        if reached:
            names = ", ".join(f"{m.technique_id} ({m.technique_name})" for m in uniq)
            verb = "reached" if status == OBSERVED else "indicated (static inference)"
            summary = f"{name.capitalize()} {verb}: {names}."
        else:
            summary = f"No evidence that {name} was reached."
        phases.append(Phase(name=name, reached=reached, techniques=uniq, summary=summary, status=status))
    return phases


def _furthest(phases: list[Phase], predicate) -> str:
    hits = [p.name for p in phases if p.reached and predicate(p)]
    return hits[-1] if hits else "none"


def highest_observed_phase(phases: list[Phase]) -> str:
    """The furthest phase confirmed by runtime/memory evidence."""
    return _furthest(phases, lambda p: p.status == OBSERVED)


def highest_inferred_phase(phases: list[Phase]) -> str:
    """The furthest phase supported by any (incl. static) evidence."""
    return _furthest(phases, lambda p: True)


def furthest_phase(phases: list[Phase]) -> str:
    # Backwards-compatible: prefer observed, fall back to inferred.
    obs = highest_observed_phase(phases)
    return obs if obs != "none" else highest_inferred_phase(phases)


def runtime_observed(phases: list[Phase]) -> bool:
    return any(p.reached and p.status == OBSERVED for p in phases)


def narrative_text(phases: list[Phase]) -> str:
    lines = ["# Attack narrative", ""]
    for p in phases:
        marker = "✔" if p.reached else "·"
        lines.append(f"{marker} {p.summary}")
    lines.append("")
    lines.append(f"Highest observed phase: **{highest_observed_phase(phases)}**.")
    lines.append(f"Highest inferred phase: **{highest_inferred_phase(phases)}** (static inference).")
    return "\n".join(lines)
