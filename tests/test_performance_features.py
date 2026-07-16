"""Tests for the performance work: static-evidence cache, sample size cap,
evidence-store facet index, and deterministic parallel dispatch."""

from __future__ import annotations

import pytest

from sandworm.core.config import Config, set_config
from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.pipeline import _cache_path, analyze_sample
from sandworm.core.sample import Sample, SampleTooLargeError

PHP = b"<?php system($_GET['c']); eval(base64_decode($_POST['x'])); ?>"


@pytest.fixture
def cfg(tmp_path):
    c = Config(work_dir=tmp_path / "wd")
    set_config(c)
    yield c
    set_config(Config())


# --- run cache ---


def test_cache_miss_then_hit(cfg):
    sample = Sample.from_bytes("shell.php", PHP)
    r1 = analyze_sample(sample, config=cfg, enable_dynamic=False)
    assert "<cache>" not in r1.analyzers_run
    assert _cache_path(cfg, sample).exists()

    r2 = analyze_sample(sample, config=cfg, enable_dynamic=False)
    assert r2.analyzers_run == ["<cache>"]
    # Same evidence and same ATT&CK mapping reconstructed from cache.
    assert len(r2.store) == len(r1.store)
    assert {m.technique_id for m in r2.mappings} == {m.technique_id for m in r1.mappings}


def test_no_cache_reruns(cfg):
    sample = Sample.from_bytes("shell.php", PHP)
    analyze_sample(sample, config=cfg, enable_dynamic=False)
    r = analyze_sample(sample, config=cfg, enable_dynamic=False, use_cache=False)
    assert "<cache>" not in r.analyzers_run


def test_cache_streams_to_subscriber(cfg):
    sample = Sample.from_bytes("shell.php", PHP)
    analyze_sample(sample, config=cfg, enable_dynamic=False)  # warm the cache
    seen: list = []
    analyze_sample(sample, config=cfg, enable_dynamic=False, on_evidence=seen.append)
    assert seen, "cache-hit run must still stream evidence to subscribers"


def test_recorded_report_run_bypasses_cache(cfg, tmp_path):
    # Recorded-report replay depends on external files, so it is never cacheable.
    sample = Sample.from_bytes("shell.php", PHP)
    analyze_sample(sample, config=cfg, enable_dynamic=False)  # warm static cache
    report = tmp_path / "cape.json"
    report.write_text('{"target_sha256": "deadbeef", "processes": []}')
    r = analyze_sample(sample, config=cfg, enable_dynamic=False, cape_report=str(report))
    assert "<cache>" not in r.analyzers_run


# --- sample size cap ---


def test_size_cap_rejects_large_file(cfg, tmp_path):
    cfg.max_sample_bytes = 1024
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * 4096)
    with pytest.raises(SampleTooLargeError):
        Sample.from_path(big, cfg)


def test_size_cap_zero_disables(cfg, tmp_path):
    cfg.max_sample_bytes = 0
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * 4096)
    assert Sample.from_path(big, cfg).size == 4096


# --- evidence store facet index ---


def _item(artifact, operation, val):
    return EvidenceItem(
        run_id="r", source="static.test", artifact=artifact, operation=operation,
        object={"value": val}, confidence=0.5,
    )


def test_facet_index_matches_scan():
    store = EvidenceStore()
    store.extend([
        _item("network", "connect", "a"),
        _item("network", "resolve", "b"),
        _item("network", "connect", "c"),
        _item("file", "write", "d"),
    ])
    indexed = store.by_facet("network", "connect")
    assert {i.object["value"] for i in indexed} == {"a", "c"}
    # query() with both facets pinned must agree with the index.
    assert store.query(artifact="network", operation="connect") == indexed


def test_facet_index_preserves_insertion_order():
    store = EvidenceStore()
    for v in "12345":
        store.append(_item("api_call", "exec", v))
    assert [i.object["value"] for i in store.by_facet("api_call", "exec")] == list("12345")
