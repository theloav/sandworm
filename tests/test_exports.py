"""Tests for the Navigator layer, STIX 2.1 bundle, and findings JSON exports."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.reconstruct.attack_map import AttackMapping
from sandworm.reporting.export import navigator_layer, sarif_log, stix_bundle


def _mapping(tid="T1059", name="Command and Scripting Interpreter", tactic="execution", conf=0.9):
    return AttackMapping(
        technique_id=tid, technique_name=name, tactic=tactic, confidence=conf,
        why="observed execution sink", evidence_ids=["ev_x"], status="observed",
    )


def _ioc_store():
    store = EvidenceStore()
    for kind, val in [("url", "http://evil.example.ru/x"), ("ipv4", "203.0.113.9"),
                      ("domain", "bad.example.top")]:
        store.append(EvidenceItem(
            run_id="r", source="static.common", artifact="network", operation="resolve",
            object={"kind": kind, "value": val}, details={"ioc": True}, confidence=0.7,
        ))
    return store


def test_navigator_layer_shape_and_scores():
    layer = navigator_layer([_mapping(conf=0.8), _mapping("T1055.012", "Process Hollowing", "defense-evasion", 0.6)],
                            name="x.exe", sha256="abc123")
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"]: t for t in layer["techniques"]}
    assert ids["T1059"]["score"] == 0.8
    # Sub-technique id preserved for Navigator.
    assert "T1055.012" in ids
    assert ids["T1055.012"]["showSubtechniques"] is True


def test_stix_bundle_has_expected_sdos():
    bundle = stix_bundle(_ioc_store(), [_mapping()], sha256="deadbeef", name="x.exe")
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert "malware" in types
    assert types.count("attack-pattern") == 1
    assert types.count("relationship") == 1
    assert types.count("indicator") == 3  # url, ipv4, domain


def test_stix_patterns_valid():
    bundle = stix_bundle(_ioc_store(), [], sha256="d", name="x")
    patterns = {o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert "[url:value = 'http://evil.example.ru/x']" in patterns
    assert "[ipv4-addr:value = '203.0.113.9']" in patterns
    assert "[domain-name:value = 'bad.example.top']" in patterns


def test_stix_ids_deterministic():
    a = stix_bundle(_ioc_store(), [_mapping()], sha256="d", name="x")
    b = stix_bundle(_ioc_store(), [_mapping()], sha256="d", name="x")
    # Same run ⇒ same SDO ids (dedupe-friendly for TIP ingestion).
    ids_a = {o["id"] for o in a["objects"] if o["type"] != "bundle"}
    ids_b = {o["id"] for o in b["objects"] if o["type"] != "bundle"}
    assert ids_a == ids_b


def test_confidence_carried_to_stix():
    bundle = stix_bundle(_ioc_store(), [_mapping(conf=0.85)], sha256="d", name="x")
    rel = next(o for o in bundle["objects"] if o["type"] == "relationship")
    assert rel["confidence"] == 85


class _FakeSummary:
    def __init__(self, risk):
        self.risk = risk
        self.maliciousness_score = 90
        self.family_hint = ""


class _FakeSample:
    name = "x.exe"
    sha256 = "abc"
    size = 10


class _FakeResult:
    def __init__(self, mappings):
        self.mappings = mappings
        self.sample = _FakeSample()


def test_sarif_log_shape_and_levels():
    entries = [
        (_FakeResult([_mapping("T1059"), _mapping("T1055", "Process Injection", "defense-evasion")]), _FakeSummary("High")),
        (_FakeResult([_mapping("T1059")]), _FakeSummary("Low")),
    ]
    log = sarif_log(entries)
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"T1059", "T1055"}  # deduped across samples
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels and "note" in levels  # High→error, Low→note
    # Each result records the sample it came from.
    assert all("locations" in r for r in run["results"])
