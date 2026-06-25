"""Explainability + detection-quality features added after the WannaCry review:
confidence provenance/timeline, behavioral Sigma, split coverage, reasoning graph."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.detect.sigma_gen import generate_sigma
from sandworm.detect.yara_gen import YaraRule
from sandworm.reconstruct.attack_map import map_evidence
from sandworm.reconstruct.explain import confidence_breakdown
from sandworm.reconstruct.graph import add_detections_to_graph, build_graph
from sandworm.reporting.coverage import compute_coverage


def _ransomware_store():
    s = EvidenceStore()
    s.append(EvidenceItem(run_id="r", source="static.common", artifact="file", operation="write",
             subject={"a": "x"}, object={"capability": "ransomware", "indicators": [".wnry", "bitcoin"]}, confidence=0.8))
    s.append(EvidenceItem(run_id="r", source="static.common", artifact="process", operation="exec",
             subject={"a": "x"}, object={"capability": "inhibit_recovery", "indicators": ["vssadmin"]}, confidence=0.8))
    return s


def test_confidence_timeline_static_only():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "system"}, confidence=0.9))
    m = [m for m in map_evidence(store) if m.technique_id == "T1059"][0]
    bd = confidence_breakdown(store, m)
    lanes = dict(bd.lane_timeline())
    assert lanes["static"] not in (None, "pending")  # static has a value
    assert lanes["dynamic"] == "pending"
    assert lanes["memory"] == "pending"
    assert sum(bd.by_source.values()) in range(98, 103)  # ~100%


def test_confidence_timeline_upgrades_with_dynamic():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "system"}, confidence=0.6))
    store.append(EvidenceItem(run_id="r", source="dynamic.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "system"}, confidence=0.95))
    m = [m for m in map_evidence(store) if m.technique_id == "T1059"][0]
    bd = confidence_breakdown(store, m)
    lanes = dict(bd.lane_timeline())
    assert lanes["static"] != "pending" and lanes["dynamic"] != "pending"
    assert m.status == "observed"  # dynamic evidence upgrades standing


def test_behavioral_sigma_for_ransomware():
    store = _ransomware_store()
    mappings = map_evidence(store)
    rules = generate_sigma(store, mappings)
    kinds = {r.kind for r in rules}
    assert "behavioral" in kinds
    titles = " ".join(r.title for r in rules)
    assert "Shadow copy" in titles
    assert "file-encryption" in titles


def test_coverage_inventory_counts():
    store = _ransomware_store()
    mappings = map_evidence(store)
    sigma = generate_sigma(store, mappings)
    yara = [YaraRule(name="t", strings=[b"x"], condition_min=1)]
    cov = compute_coverage(mappings, sigma, yara)
    assert cov.inventory.behavioral_rules >= 2
    assert cov.inventory.yara_rules == 1
    assert cov.inventory.runtime_rules == 0
    # behavioral rules tagged T1486/T1490 now give impact coverage
    assert cov.overall > 0


def test_coverage_does_not_claim_observed_when_static():
    # static-only: nothing observed, so runtime coverage must be N/A, not 100%.
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "system"}, confidence=0.9))
    mappings = map_evidence(store)
    cov = compute_coverage(mappings, generate_sigma(store, mappings), [])
    assert cov.observed_techniques == 0
    assert cov.runtime_coverage is None  # N/A, not a misleading number
    assert cov.inferred_techniques >= 1


def test_webshell_risk_and_behavioral_rule():
    from sandworm.reconstruct.narrative import build_narrative
    from sandworm.reporting.summary import build_summary

    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.php", artifact="file", operation="exec",
                 subject={"a": "x"}, object={"verdict": "php_webshell"}, confidence=0.8))
    for sink in ("system", "proc_open", "popen"):
        store.append(EvidenceItem(run_id="r", source="static.php", artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"sink": sink}, confidence=0.9))
    store.append(EvidenceItem(run_id="r", source="static.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "move_uploaded_file"}, confidence=0.7))
    mappings = map_evidence(store)
    summary = build_summary(store, mappings, build_narrative(mappings), isolated=False)
    assert summary.risk in {"High", "Critical"}
    assert summary.likelihood == "High"
    assert any("execution sink" in r for r in summary.risk_reasons)
    assert any("Web-shell" in r for r in summary.risk_reasons)

    sigma = generate_sigma(store, mappings)
    assert any(r.kind == "behavioral" and "Web server" in r.title for r in sigma)


def test_sigma_hostnames_are_bare():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.common", artifact="network", operation="resolve",
                 subject={"a": "x"}, object={"kind": "url", "value": "https://crt.sh/?q=%25.evil"},
                 details={"ioc": True}, confidence=0.7))
    sigma = generate_sigma(store, map_evidence(store))
    c2 = [r for r in sigma if "C2" in r.title][0]
    hosts = c2.detection["selection"]["DestinationHostname|contains"]
    assert "crt.sh" in hosts
    assert all("https://" not in h and "?" not in h for h in hosts)


def test_reasoning_graph_has_typed_chain():
    store = _ransomware_store()
    mappings = map_evidence(store)
    graph = build_graph(store, mappings, sample_name="wc.bin")
    add_detections_to_graph(graph, mappings, sigma=generate_sigma(store, mappings))
    labels = {n.label for n in graph.nodes.values()}
    assert {"Sample", "Capability", "Technique", "Detection"} <= labels
    rels = {e.rel for e in graph.edges}
    assert {"CONTAINS", "INDICATES", "DETECTED_BY"} <= rels
