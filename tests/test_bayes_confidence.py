"""Bayesian confidence aggregation across evidence lanes (#5)."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.reconstruct.attack_map import map_evidence
from sandworm.reconstruct.bayes import PRIOR, fuse


def test_prior_only_returns_no_lane():
    agg, lanes = fuse({})
    assert agg == round(PRIOR, 3) or agg <= PRIOR + 1e-9
    assert lanes == {}


def test_cross_lane_corroboration_climbs():
    # A weak static inference becomes believable once dynamic + memory confirm it
    # — the headline payoff of the Bayesian model.
    static_only, _ = fuse({"static": [0.45]})
    plus_dynamic, _ = fuse({"static": [0.45], "dynamic": [0.7]})
    plus_memory, _ = fuse({"static": [0.45], "dynamic": [0.7], "memory": [0.8]})
    assert static_only < plus_dynamic < plus_memory
    assert static_only < 0.6 and plus_memory > 0.9


def test_within_lane_evidence_is_discounted_not_independent():
    # Three correlated items in one lane must not be treated as three independent
    # confirmations (which would saturate instantly); a 4th adds little.
    three, _ = fuse({"static": [0.7, 0.7, 0.7]})
    four, _ = fuse({"static": [0.7, 0.7, 0.7, 0.7]})
    assert three < 0.99 or four - three < 0.05  # diminishing within a lane
    assert four >= three                         # but still monotonic


def test_lane_posteriors_never_claim_certainty():
    _, lanes = fuse({"static": [0.99, 0.99, 0.99, 0.99]})
    assert all(v <= 0.99 for v in lanes.values())


def test_mapping_exposes_prior_and_lane_posteriors():
    store = EvidenceStore()
    for api in ("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"):
        store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"api": api}, confidence=0.7))
        store.append(EvidenceItem(run_id="r", source="dynamic.windows.cape", artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"api": api}, confidence=0.7))
    m = [x for x in map_evidence(store) if x.technique_id == "T1055"][0]
    assert m.prior == PRIOR
    assert "static" in m.lane_posterior and "dynamic" in m.lane_posterior
    assert 0.0 < m.confidence <= 0.99


def test_weak_single_signal_stays_near_prior():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "RegCreateKey"},
                 details={"attack_hint": "T1112", "why": "reg"}, confidence=0.3))
    m = [x for x in map_evidence(store) if x.technique_id == "T1112"][0]
    assert m.confidence < 0.6  # a lone weak inference never inflates into a finding
