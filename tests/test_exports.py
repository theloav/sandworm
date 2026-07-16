"""Tests for the Navigator layer, STIX 2.1 bundle, and findings JSON exports."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.reconstruct.attack_map import AttackMapping
from sandworm.reporting.export import (
    ioc_csv,
    misp_event,
    navigator_layer,
    openioc_xml,
    sarif_log,
    stix_bundle,
)


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


# --- MISP / OpenIOC / CSV ---


def test_misp_event_attributes_and_tags():
    event = misp_event(_ioc_store(), [_mapping()], sha256="deadbeef", name="x.exe")["Event"]
    types = {a["type"] for a in event["Attribute"]}
    assert {"url", "ip-dst", "domain", "sha256"} <= types
    # ATT&CK technique surfaced as a MISP galaxy tag.
    assert any("mitre-attack" in t["name"] and "T1059" in t["name"] for t in event["Tag"])


def test_misp_to_ids_gated_by_confidence():
    store = EvidenceStore()
    store.append(EvidenceItem(
        run_id="r", source="static.common", artifact="network", operation="resolve",
        object={"kind": "url", "value": "http://weak.example.top/x"}, details={"ioc": True}, confidence=0.3,
    ))
    attrs = misp_event(store, [], sha256="d", name="x")["Event"]["Attribute"]
    url_attr = next(a for a in attrs if a["type"] == "url")
    assert url_attr["to_ids"] is False  # low-confidence IOC is not detection-eligible


def test_openioc_is_valid_xml_with_indicators(tmp_path):
    import xml.etree.ElementTree as ET

    xml = openioc_xml(_ioc_store(), sha256="deadbeef", name="x.exe")
    # Round-trip through a written UTF-8 file so an encoding-declaration mismatch
    # (e.g. the "·" in the description) is caught the way a consumer would hit it.
    p = tmp_path / "ioc.xml"
    p.write_text(xml)
    root = ET.parse(p).getroot()
    ns = "{http://schemas.mandiant.com/2010/ioc}"
    items = root.findall(f".//{ns}IndicatorItem")
    assert len(items) == 3
    contents = {i.find(f"{ns}Content").text for i in items}
    assert "http://evil.example.ru/x" in contents


def test_openioc_escapes_special_chars():
    import xml.etree.ElementTree as ET

    store = EvidenceStore()
    store.append(EvidenceItem(
        run_id="r", source="static.common", artifact="network", operation="resolve",
        object={"kind": "url", "value": "http://evil.example.ru/a?x=1&y=2"}, details={"ioc": True}, confidence=0.7,
    ))
    xml = openioc_xml(store, sha256="d", name="a&b<c>")
    ET.fromstring(xml)  # ampersand in value + name must not break XML


def test_ioc_csv_rows():
    csv_text = ioc_csv(_ioc_store(), sha256="deadbeef", name="x.exe")
    lines = csv_text.strip().splitlines()
    assert lines[0] == "kind,value,confidence,sample,sha256"
    assert len(lines) == 4  # header + 3 IOCs
    assert any("203.0.113.9" in ln for ln in lines)


def test_ioc_exporters_dedupe():
    # The same IOC seen by two different analyzers collapses to one row, keeping
    # the higher confidence (the store dedups identical items; _iter_iocs dedups
    # across distinct evidence items by (kind, value)).
    store = EvidenceStore()
    for source, conf in (("static.common", 0.4), ("static.decode", 0.9)):
        store.append(EvidenceItem(
            run_id="r", source=source, artifact="network", operation="resolve",
            object={"kind": "domain", "value": "dup.example.top"}, details={"ioc": True}, confidence=conf,
        ))
    rows = ioc_csv(store, sha256="d", name="x").strip().splitlines()
    assert len(rows) == 2  # header + one deduped IOC
    assert "0.900" in rows[1]


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
