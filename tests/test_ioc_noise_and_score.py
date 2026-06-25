"""Regressions from the Go-backdoor report: filter library/runtime noise out of
network IOCs, and provide an explainable maliciousness score + evidence maturity."""

from __future__ import annotations

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.common import (
    CommonAnalyzer,
    classify_domain,
    extract_iocs,
    extract_iocs_classified,
)
from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.sample import Sample
from sandworm.reconstruct.attack_map import map_evidence
from sandworm.reconstruct.narrative import build_narrative
from sandworm.reporting.summary import build_summary


def test_go_runtime_symbols_not_iocs():
    noise = "runtime.name reflect.name pkix.Name big.Int idna.info unicode.Cc asn1.BitString.At go.itab.net"
    domains = {v for k, v, _c, _f in extract_iocs(noise) if k == "domain"}
    assert domains == set(), f"Go symbols leaked as domains: {domains}"


def test_oid_and_nonhash_not_iocs():
    text = "1.3.6.1 2.5.4.102 28421709430404007434844970703125 B10B11B12B13B14B15B16B17B18B19B2"
    found = {(k, v) for k, v, _c, _f in extract_iocs(text)}
    assert not any(k == "ipv4" for k, _ in found)   # OIDs are not IPs
    assert not any(k in {"md5", "sha256"} for k, _ in found)  # decimal/uppercase != hash


def test_toolchain_domains_classified_library_not_ioc():
    assert classify_domain("github.com") == "library"
    assert classify_domain("golang.org") == "library"
    assert classify_domain("realc2.evil-domain.ru") == "ioc"
    assert classify_domain("reflect.name") == "drop"

    text = "github.com golang.org c2.evil.ru"
    cats = {v: cat for k, v, _c, _f, cat in extract_iocs_classified(text)}
    assert cats["github.com"] == "library"
    assert cats["c2.evil.ru"] == "ioc"


def test_garbage_urls_rejected():
    iocs = {v for k, v, _c, _f in extract_iocs("https://L) https://H https://real.evil.com/x")}
    assert "https://real.evil.com/x" in iocs
    assert "https://L)" not in iocs and "https://L" not in iocs


def test_library_artifacts_excluded_from_network(temp_config):
    data = b"MZ" + b"\x00" * 64 + b"github.com\x00golang.org\x00http://c2.evil.ru/g\x00"
    sample = Sample.from_bytes("go.bin", data)
    sample.format_hint = "pe"
    items = CommonAnalyzer().analyze(sample, Context(run_id="t", config=temp_config))
    net = [i for i in items if i.artifact == "network" and i.details.get("ioc")]
    libs = [i for i in items if i.details.get("library_artifact")]
    assert any("c2.evil.ru" in str(i.object) for i in net)
    assert all("github.com" not in str(i.object) for i in net)  # not a network IOC
    assert libs  # but recorded as a library artifact


def test_maliciousness_score_is_explainable():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.common", artifact="file", operation="write",
                 subject={"a": "x"}, object={"capability": "ransomware", "indicators": [".wnry", "bitcoin"]}, confidence=0.8))
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "WriteProcessMemory"}, details={"why": "x"}, confidence=0.7))
    mappings = map_evidence(store)
    summary = build_summary(store, mappings, build_narrative(mappings), isolated=False)

    assert 0 <= summary.maliciousness_score <= 96  # static can't reach 100
    assert summary.score_factors
    labels = " ".join(label for label, _ in summary.score_factors)
    assert "Ransomware" in labels
    assert any(pts < 0 for _, pts in summary.score_factors)  # the "no runtime" caveat
    # evidence maturity: static complete, dynamic+memory pending
    maturity = dict(summary.evidence_maturity)
    assert maturity["static"] == "complete"
    assert maturity["dynamic"] == "pending" and maturity["memory"] == "pending"


def test_generic_decrypt_string_is_not_ransomware(temp_config):
    # A backdoor with `decrypt` + `.crypt` (both weak/generic) must NOT be called
    # ransomware — this was a dangerous false positive.
    data = b"MZ" + b"\x00" * 64 + b"decrypt\x00.crypt\x00http://c2.evil.ru/g\x00"
    sample = Sample.from_bytes("bd.bin", data)
    sample.format_hint = "pe"
    items = CommonAnalyzer().analyze(sample, Context(run_id="t", config=temp_config))
    assert not any(i.object.get("capability") == "ransomware" for i in items)
    tids = {m.technique_id for m in map_evidence(_store(items))}
    assert "T1486" not in tids


def test_strong_marker_is_ransomware(temp_config):
    data = b"MZ" + b"\x00" * 64 + b".wnry\x00@WanaDecryptor@\x00your files have been encrypted\x00"
    sample = Sample.from_bytes("wc.bin", data)
    sample.format_hint = "pe"
    items = CommonAnalyzer().analyze(sample, Context(run_id="t", config=temp_config))
    assert any(i.object.get("capability") == "ransomware" for i in items)
    assert "T1486" in {m.technique_id for m in map_evidence(_store(items))}


def test_injection_scores_high_band(temp_config):
    from sandworm.reconstruct.narrative import build_narrative
    from sandworm.reporting.summary import build_summary

    store = EvidenceStore()
    for imp in ("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"):
        store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                     subject={"a": "x"}, object={"import": imp}, details={"why": "x"}, confidence=0.7))
    mappings = map_evidence(store)
    summary = build_summary(store, mappings, build_narrative(mappings), isolated=False)
    assert summary.risk == "High"
    assert summary.maliciousness_score >= 40  # injection alone lands in the High band


def _store(items):
    s = EvidenceStore()
    s.extend(items)
    return s


def test_coverage_detectable_flag():
    from sandworm.detect.sigma_gen import generate_sigma
    from sandworm.detect.yara_gen import YaraRule
    from sandworm.reporting.coverage import compute_coverage

    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "WriteProcessMemory"}, details={"why": "x"}, confidence=0.7))
    mappings = map_evidence(store)
    cov = compute_coverage(mappings, generate_sigma(store, mappings), [YaraRule(name="t", strings=[b"x"], condition_min=1)])
    assert cov.detectable is True  # a YARA rule exists -> the sample IS detectable
    # even if technique-level behavioural coverage is 0%, detectable stays True


def test_dynamic_evidence_marks_maturity_complete():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="dynamic.php", artifact="api_call", operation="exec",
                 subject={"a": "x"}, object={"sink": "system"}, confidence=0.9))
    mappings = map_evidence(store)
    summary = build_summary(store, mappings, build_narrative(mappings), isolated=True)
    assert dict(summary.evidence_maturity)["dynamic"] == "complete"
