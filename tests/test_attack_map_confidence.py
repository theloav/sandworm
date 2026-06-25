"""ATT&CK mapping must carry a confidence in (0,1], an explanation, and evidence
ids — never a bare technique id."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.reconstruct.attack_map import map_evidence


def _store(*items) -> EvidenceStore:
    s = EvidenceStore()
    for it in items:
        s.append(it)
    return s


def _ev(**over):
    base = dict(run_id="r", source="static.php", artifact="api_call", operation="exec",
                subject={"analyzer": "x"}, object={}, confidence=0.8)
    base.update(over)
    return EvidenceItem(**base)


def test_command_sink_maps_to_t1059_with_why():
    store = _store(_ev(object={"sink": "system"}))
    mappings = map_evidence(store)
    t1059 = [m for m in mappings if m.technique_id == "T1059"]
    assert t1059
    m = t1059[0]
    assert 0.0 < m.confidence <= 1.0
    assert m.why and "system" in m.why
    assert m.evidence_ids  # cites backing evidence
    assert m.technique_name and m.tactic


def test_injection_maps_to_t1055():
    store = _store(_ev(source="static.pe", object={"import": "WriteProcessMemory"}, details={"why": "x"}))
    mappings = map_evidence(store)
    assert any(m.technique_id == "T1055" for m in mappings)


def test_confidence_increases_with_corroboration():
    one = map_evidence(_store(_ev(object={"sink": "system"})))
    two = map_evidence(
        _store(
            _ev(object={"sink": "system"}),
            _ev(object={"sink": "exec"}, confidence=0.9),
            _ev(object={"sink": "shell_exec"}, confidence=0.9),
        )
    )
    c1 = next(m.confidence for m in one if m.technique_id == "T1059")
    c2 = next(m.confidence for m in two if m.technique_id == "T1059")
    assert c2 >= c1


def test_no_bare_techniques():
    store = _store(_ev(object={"sink": "system"}), _ev(operation="decode", artifact="string", object={"layer": 0}))
    for m in map_evidence(store):
        assert m.why.strip()
        assert m.evidence_ids
        assert m.confidence <= 0.99
