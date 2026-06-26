"""Cross-sample behavioural diffing & lineage (#3)."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.reconstruct.lineage import (
    LineageIndex,
    Signature,
    diff,
    jaccard,
    signature_of,
)


def _ransomware_store(c2_tld: str = "com", inject: bool = False) -> EvidenceStore:
    s = EvidenceStore()
    s.append(EvidenceItem(run_id="r", source="static.common", artifact="file", operation="write",
             subject={"a": "x"}, object={"capability": "ransomware", "indicators": [".wnry"]}, confidence=0.8))
    s.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
             subject={"a": "x"}, object={"import": "CreateService"}, details={"attack_hint": "T1543.003", "why": "svc"}, confidence=0.55))
    s.append(EvidenceItem(run_id="r", source="static.common", artifact="network", operation="resolve",
             subject={"a": "x"}, object={"kind": "domain", "value": f"pay-now.{c2_tld}"}, details={"ioc": True}, confidence=0.6))
    if inject:
        for api in ("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"):
            s.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"api": api}, confidence=0.7))
    return s


def test_similar_samples_have_high_jaccard():
    a = signature_of("aaa", "variantA", _ransomware_store())
    b = signature_of("bbb", "variantB", _ransomware_store())          # identical behaviour
    c = signature_of("ccc", "unrelated", EvidenceStore())             # nothing
    assert jaccard(a.minhash, b.minhash) == 1.0
    assert jaccard(a.minhash, c.minhash) < 0.3


def test_diff_surfaces_added_technique_and_ioc_rotation():
    a = signature_of("aaa", "Sample A", _ransomware_store(c2_tld="com"))
    b = signature_of("bbb", "Sample B", _ransomware_store(c2_tld="top", inject=True))
    d = diff(a, b)
    assert "T1486" in d.shared                       # both are ransomware
    assert "T1055" in d.only_in_b                     # B added process injection
    assert "T1055" not in d.only_in_a
    note = d.evolution_note(a, b)
    assert "added" in note and "T1055" in note
    assert "rotated" in note                          # .com → .top infrastructure change


def test_index_roundtrip_and_neighbours(tmp_path):
    idx = LineageIndex(tmp_path / "lineage.json")
    idx.add(signature_of("aaa", "A", _ransomware_store()))
    idx.add(signature_of("bbb", "B", _ransomware_store(inject=True)))
    idx.add(signature_of("ccc", "novel", EvidenceStore()))
    idx.save()

    reloaded = LineageIndex(tmp_path / "lineage.json")
    assert set(reloaded.sigs) == {"aaa", "bbb", "ccc"}
    target = reloaded.sigs["aaa"]
    neigh = reloaded.neighbours(target, threshold=0.5)
    names = [n.signature.sha256 for n in neigh]
    assert "bbb" in names and "ccc" not in names      # B is a neighbour, novel is not
    assert all(n.similarity >= 0.5 for n in neigh)


def test_first_seen_attributes_an_indicator_to_earliest_sample():
    idx = LineageIndex.__new__(LineageIndex)
    idx.sigs = {
        "old": Signature("old", "first", frozenset({"cap:ransomware"}), (), techniques=["T1486"],
                         iocs=["pay-now.com"], created="2026-01-01T00:00:00"),
        "new": Signature("new", "later", frozenset({"cap:ransomware"}), (), techniques=["T1486"],
                         iocs=["pay-now.com"], created="2026-06-01T00:00:00"),
    }
    owner = idx.first_seen("pay-now.com")
    assert owner is not None and owner.sha256 == "old"   # earliest to carry the IOC
