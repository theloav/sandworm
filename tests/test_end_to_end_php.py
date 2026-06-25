"""Full pipeline: synthetic webshell -> evidence -> graph -> detections -> report."""

from __future__ import annotations

from sandworm.core.pipeline import (
    analyze_sample,
    build_report_inputs,
    persist_run,
)
from sandworm.core.sample import Sample
from sandworm.detect.yara_gen import passes_clean_corpus
from sandworm.reporting.report import render_html


def test_end_to_end_php(temp_config, samples_dir):
    sample = Sample.from_path(samples_dir / "benign_webshell.php")
    result = analyze_sample(sample, config=temp_config)

    # routed to PHP, static-only (no isolation in tests)
    assert result.triage.fmt == "php"
    assert result.isolated is False
    assert "static.php" in result.analyzers_run
    assert all("dynamic" not in n for n in result.analyzers_run)

    # evidence: deobfuscation layers + a sink
    decode_layers = result.store.query(source="static.php", operation="decode")
    assert len(decode_layers) >= 2
    assert result.store.query(artifact="api_call", operation="exec")

    # reconstruction: graph + ATT&CK with why + confidence
    assert result.graph.stats()["nodes"] > 0
    assert result.mappings
    for m in result.mappings:
        assert m.why and 0 < m.confidence <= 1
    tids = {m.technique_id for m in result.mappings}
    assert {"T1027", "T1059"} <= tids  # obfuscation + execution

    # narrative reached at least execution
    assert any(p.reached for p in result.phases)

    # detections: clean YARA + some Sigma + a coverage score
    assert result.yara
    assert passes_clean_corpus(result.yara)
    assert result.sigma
    assert 0.0 <= result.coverage.overall <= 1.0

    # report renders, self-contained, no external resources loaded at render time
    html = render_html(build_report_inputs(result))
    for needle in ("Executive summary", "Execution status", "Reasoning graph", "ATT&amp;CK", "Deobfuscation", "Detection coverage", "<svg"):
        assert needle in html
    # Epistemic honesty: a static-only run must not claim runtime was observed.
    assert "Runtime observed: <b>No</b>" in html
    # Self-contained: inline script/style are fine; nothing is fetched over the
    # network at render/view time.
    assert 'src="http' not in html and 'href="http' not in html

    # persisted run replays
    run_dir = persist_run(result, temp_config)
    assert (run_dir / "evidence.jsonl").exists()


def test_unknown_format_still_yields_evidence(temp_config):
    sample = Sample.from_bytes("blob.bin", b"\x01\x02 some random bytes http://evil.test/x \x03")
    result = analyze_sample(sample, config=temp_config)
    assert len(result.store) > 0  # common analyzer always runs
    assert "static.common" in result.analyzers_run
