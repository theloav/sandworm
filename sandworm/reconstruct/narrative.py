"""Ordered lifecycle phases -> attack narrative.

Buckets the ATT&CK mappings into malware lifecycle phases and reports how far
execution reached. The narrative is the human-facing "what happened, in order"
story; it is built entirely from mapped evidence so every sentence is grounded.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.provenance import OBSERVED, SPECULATIVE, strongest
from .attack_map import AttackMapping

# Lifecycle phases in canonical order, each backed by ATT&CK tactics.
LIFECYCLE = [
    ("execution", ["execution"]),
    ("unpack/deobfuscate", ["defense-evasion"]),
    ("injection", ["privilege-escalation", "defense-evasion"]),
    ("discovery", ["discovery", "reconnaissance"]),
    ("credential-access", ["credential-access"]),
    ("persistence", ["persistence"]),
    ("command-and-control", ["command-and-control"]),
    ("collection", ["collection"]),
    ("exfiltration", ["exfiltration"]),
    ("impact", ["impact"]),
]


@dataclass
class Phase:
    name: str
    reached: bool
    techniques: list[AttackMapping]
    summary: str
    status: str = "speculative"  # observed | inferred | speculative (best in phase)


def build_narrative(mappings: list[AttackMapping]) -> list[Phase]:
    by_tactic: dict[str, list[AttackMapping]] = {}
    for m in mappings:
        by_tactic.setdefault(m.tactic, []).append(m)

    phases: list[Phase] = []
    for name, tactics in LIFECYCLE:
        techs: list[AttackMapping] = []
        for t in tactics:
            techs.extend(by_tactic.get(t, []))
        # de-dupe by technique id
        seen = set()
        uniq = []
        for m in techs:
            if m.technique_id not in seen:
                seen.add(m.technique_id)
                uniq.append(m)
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
