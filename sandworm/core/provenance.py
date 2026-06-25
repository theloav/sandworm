"""Epistemic status of a finding — the load-bearing honesty primitive.

SANDWORM must never overstate what it knows. Every finding is one of:

* ``observed``    — confirmed by runtime or memory evidence (the sample actually
                    did this inside the detonation env / it is present in a memory
                    image). Only the dynamic.* and memory.* lanes can assert this.
* ``inferred``    — supported by static evidence or capability analysis (the
                    binary *contains* the code/import/string for this), but the
                    behavior was not observed executing.
* ``speculative`` — a low-confidence hypothesis that needs more evidence.

Reports, narratives, and ATT&CK mappings carry this so an analyst can tell
"the sample encrypted files" (observed) from "the sample is capable of
encrypting files" (inferred) at a glance.
"""

from __future__ import annotations

OBSERVED = "observed"
INFERRED = "inferred"
SPECULATIVE = "speculative"

# Only these source prefixes may assert observed behavior.
_OBSERVED_PREFIXES = ("dynamic.", "memory.")

# Rank for "best available" aggregation (higher = stronger epistemic standing).
RANK = {SPECULATIVE: 0, INFERRED: 1, OBSERVED: 2}
_BY_RANK = {v: k for k, v in RANK.items()}


def provenance_of(source: str, confidence: float) -> str:
    """Classify a single finding from its source lane and confidence."""
    if source.startswith(_OBSERVED_PREFIXES):
        return OBSERVED
    if confidence < 0.5:
        return SPECULATIVE
    return INFERRED


def strongest(provenances: list[str]) -> str:
    """The best epistemic standing across several contributing findings."""
    if not provenances:
        return SPECULATIVE
    return _BY_RANK[max(RANK[p] for p in provenances)]
