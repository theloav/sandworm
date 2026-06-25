"""The evidence spine: confidence is required & bounded; ids are stable; the
store queries correctly and round-trips through JSONL."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandworm.core.evidence import EvidenceItem, EvidenceStore


def _item(**over):
    base = dict(
        run_id="r1", source="static.php", artifact="string", operation="decode",
        subject={"analyzer": "x"}, object={"layer": 0}, confidence=0.5,
    )
    base.update(over)
    return EvidenceItem(**base)


def test_confidence_required():
    with pytest.raises(ValidationError):
        EvidenceItem(run_id="r", source="s", artifact="file", operation="read")


@pytest.mark.parametrize("bad", [-0.1, 1.1, float("nan"), float("inf")])
def test_confidence_bounds(bad):
    with pytest.raises(ValidationError):
        _item(confidence=bad)


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        _item(unexpected="nope")


def test_stable_id_dedupe():
    a = _item()
    b = _item()  # identical content
    assert a.id == b.id
    c = _item(object={"layer": 1})
    assert c.id != a.id

    store = EvidenceStore()
    store.append(a)
    store.append(b)  # dupe collapses
    store.append(c)
    assert len(store) == 2


def test_query_facets():
    store = EvidenceStore()
    store.append(_item(operation="decode"))
    store.append(_item(artifact="api_call", operation="exec", object={"sink": "system"}, confidence=0.9))
    assert len(store.query(operation="decode")) == 1
    assert len(store.query(artifact="api_call")) == 1
    assert len(store.query(min_confidence=0.8)) == 1
    assert store.query(subject_match={"analyzer": "x"})


def test_jsonl_roundtrip(tmp_path):
    store = EvidenceStore()
    store.append(_item())
    store.append(_item(object={"layer": 2}, confidence=0.8))
    path = tmp_path / "ev.jsonl"
    store.dump(str(path))
    loaded = EvidenceStore.load(str(path))
    assert len(loaded) == len(store)
    assert {i.id for i in loaded} == {i.id for i in store}
