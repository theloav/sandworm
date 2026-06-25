"""Differential analysis: run under N conditions, diff the evidence.

Surfaces environment checks and dormant payloads by comparing evidence produced
under different conditions (e.g. network on/off, Office present/absent). For v1 we
keep it to 2–3 conditions. The caller supplies a callable that runs the pipeline
under a given condition and returns an EvidenceStore.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..core.evidence import EvidenceItem, EvidenceStore

# v1 conditions kept deliberately small.
DEFAULT_CONDITIONS = ["network_on", "network_off"]


@dataclass
class DiffResult:
    condition_a: str
    condition_b: str
    only_in_a: list[str]
    only_in_b: list[str]
    note: str


def _ids(store: EvidenceStore) -> set[str]:
    return {it.id for it in store}


def diff_runs(runs: dict[str, EvidenceStore]) -> list[DiffResult]:
    """Pairwise-diff a dict of condition -> store. Returns one DiffResult per
    adjacent pair of conditions."""
    conditions = list(runs.keys())
    out: list[DiffResult] = []
    for a, b in zip(conditions, conditions[1:], strict=False):
        ia, ib = _ids(runs[a]), _ids(runs[b])
        only_a = sorted(ia - ib)
        only_b = sorted(ib - ia)
        note = ""
        if only_a and not only_b:
            note = f"behavior present under '{a}' but dormant under '{b}' — likely an environment check"
        elif only_b and not only_a:
            note = f"behavior triggered only under '{b}' — possible conditional/dormant payload"
        elif only_a or only_b:
            note = "divergent behavior across conditions — environment-sensitive sample"
        else:
            note = "identical behavior across conditions"
        out.append(DiffResult(a, b, only_a, only_b, note))
    return out


def run_differential(
    conditions: list[str],
    runner: Callable[[str], EvidenceStore],
    run_id: str,
) -> tuple[list[DiffResult], list[EvidenceItem]]:
    """Execute ``runner`` under each condition and diff. Emits a summary
    EvidenceItem per divergence so it lands in the graph/report."""
    runs = {c: runner(c) for c in conditions}
    diffs = diff_runs(runs)
    findings: list[EvidenceItem] = []
    for d in diffs:
        if d.only_in_a or d.only_in_b:
            findings.append(
                EvidenceItem(
                    run_id=run_id,
                    source="enrich.differential",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": "enrich.differential"},
                    object={"conditions": [d.condition_a, d.condition_b]},
                    details={"note": d.note, "only_in_a": d.only_in_a[:10], "only_in_b": d.only_in_b[:10]},
                    confidence=0.6,
                    evidence_refs=[],
                )
            )
    return diffs, findings
