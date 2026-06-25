"""Epistemic honesty: a static-only run must never claim 'observed', and dynamic/
memory evidence must upgrade a technique to 'observed'."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.provenance import provenance_of, strongest
from sandworm.reconstruct.attack_map import map_evidence
from sandworm.reconstruct.narrative import (
    build_narrative,
    highest_observed_phase,
    runtime_observed,
)


def _ev(source, conf, **obj):
    return EvidenceItem(
        run_id="r", source=source, artifact="api_call", operation="exec",
        subject={"a": "x"}, object=obj, confidence=conf,
    )


def test_provenance_classification():
    assert provenance_of("static.pe", 0.9) == "inferred"
    assert provenance_of("static.common", 0.45) == "speculative"
    assert provenance_of("dynamic.windows.cape", 0.7) == "observed"
    assert provenance_of("memory.vol3", 0.6) == "observed"
    assert strongest(["speculative", "inferred", "observed"]) == "observed"
    assert strongest(["speculative", "inferred"]) == "inferred"


def test_static_only_never_observed():
    store = EvidenceStore()
    store.append(_ev("static.php", 0.9, sink="system"))
    store.append(_ev("static.common", 0.9, capability="ransomware", indicators=[".wnry", "bitcoin"]))
    mappings = map_evidence(store)
    assert mappings
    assert all(m.status in {"inferred", "speculative"} for m in mappings)
    assert all(m.status != "observed" for m in mappings)

    phases = build_narrative(mappings)
    assert runtime_observed(phases) is False
    assert highest_observed_phase(phases) == "none"


def test_dynamic_evidence_is_observed():
    store = EvidenceStore()
    # same technique (execution sink) but seen at runtime
    store.append(_ev("dynamic.php", 0.9, sink="system"))
    mappings = map_evidence(store)
    t1059 = [m for m in mappings if m.technique_id == "T1059"][0]
    assert t1059.status == "observed"

    phases = build_narrative(mappings)
    assert runtime_observed(phases) is True
    assert highest_observed_phase(phases) != "none"


def test_ransomware_why_lists_indicators():
    store = EvidenceStore()
    store.append(
        EvidenceItem(
            run_id="r", source="static.common", artifact="file", operation="write",
            subject={"a": "x"},
            object={"capability": "ransomware", "indicators": [".wnry", "bitcoin", "your files"]},
            confidence=0.8,
        )
    )
    m = [m for m in map_evidence(store) if m.technique_id == "T1486"][0]
    assert ".wnry" in m.why  # the "why" is transparent about what triggered it
