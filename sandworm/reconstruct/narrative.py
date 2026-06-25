"""Ordered lifecycle phases -> attack narrative.

Buckets the ATT&CK mappings into malware lifecycle phases and reports how far
execution reached. The narrative is the human-facing "what happened, in order"
story; it is built entirely from mapped evidence so every sentence is grounded.
"""

from __future__ import annotations

from dataclasses import dataclass

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
        if reached:
            names = ", ".join(f"{m.technique_id} ({m.technique_name})" for m in uniq)
            summary = f"Reached {name}: {names}."
        else:
            summary = f"No evidence that {name} was reached."
        phases.append(Phase(name=name, reached=reached, techniques=uniq, summary=summary))
    return phases


def furthest_phase(phases: list[Phase]) -> str:
    reached = [p.name for p in phases if p.reached]
    return reached[-1] if reached else "no observable malicious phase"


def narrative_text(phases: list[Phase]) -> str:
    lines = ["# Attack narrative", ""]
    for p in phases:
        marker = "✔" if p.reached else "·"
        lines.append(f"{marker} {p.summary}")
    lines.append("")
    lines.append(f"Execution reached: **{furthest_phase(phases)}**.")
    return "\n".join(lines)
