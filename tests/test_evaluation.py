import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sandworm.cli import app
from sandworm.evaluation.benchmark import evaluate
from sandworm.evaluation.metrics import calibration, classification, reliability_svg, wilson


def test_known_metrics_and_empty_bins():
    result = calibration([(0.1, 0), (0.9, 1)])
    assert result["brier"] == pytest.approx(0.01)
    assert result["ece"] == pytest.approx(0.1)
    assert result["bins"][0]["accuracy"] is None
    assert sum(row["count"] for row in result["bins"]) == 2
    assert calibration([])["brier"] is None
    assert classification(2, 1, 2, 5)["precision"] == pytest.approx(2 / 3)
    assert classification(0, 0, 0, 4)["recall"] is None
    assert 0 < wilson(0, 100)[1] < 0.04
    assert "<svg" in reliability_svg(result)
    with pytest.raises(ValueError):
        calibration([(float("nan"), 1)])


def test_fixed_corpus_and_cli_regression_gate(tmp_path):
    manifest = Path(__file__).parents[1] / "benchmarks/manifest.json"
    report = evaluate(manifest)
    assert len(report["cases"]) == 8
    assert report["micro"]["tp"] + report["micro"]["fn"] == 10
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(report))
    result = CliRunner().invoke(app, ["benchmark", str(manifest), "--out", str(tmp_path / "results"), "--baseline", str(baseline)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "results/reliability.svg").is_file()
    report["per_technique"]["T1057"]["fn"] = -1  # impossible previous score must fail gate
    baseline.write_text(json.dumps(report))
    assert CliRunner().invoke(app, ["benchmark", str(manifest), "--out", str(tmp_path / "other"), "--baseline", str(baseline)]).exit_code == 1


def test_manifest_identity_and_path_rejection(tmp_path):
    source = tmp_path / "x.php"
    source.write_bytes(b"<?php echo 1;")
    case = {"id": "x", "path": "x.php", "sha256": "0" * 64, "positive": [], "negative": ["T1059"], "rationale": "literal output"}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "cases": [case]}))
    with pytest.raises(ValueError, match="identity"):
        evaluate(manifest)
    case["path"] = "../escape.php"
    manifest.write_text(json.dumps({"schema_version": 1, "cases": [case]}))
    with pytest.raises(ValueError, match="inside"):
        evaluate(manifest)


def test_yara_x_audit_counts_errors_not_as_clean(tmp_path):
    pytest.importorskip("yara_x")
    from sandworm.evaluation.goodware import audit, inventory
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "positive").write_bytes(b"anchor")
    (corpus / "negative").write_bytes(b"clean")
    (corpus / "duplicate").write_bytes(b"clean")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(inventory(corpus, provenance="test fixtures, not real goodware")))
    rules = tmp_path / "rules.yar"
    rules.write_text('rule test { strings: $a="anchor" condition: $a }')
    result = audit(rules, manifest, corpus)
    assert result["files_scanned"] == 2 and result["matching_files"] == 1
    assert result["observed_fp_rate"] == 0.5
    assert result["rules_sha256"] == hashlib.sha256(rules.read_bytes()).hexdigest()
    (corpus / "positive").write_bytes(b"changed")
    result = audit(rules, manifest, corpus)
    assert not result["complete"] and result["files_scanned"] == 1


def test_yara_serialization_uses_real_engine_with_safe_metadata():
    yara_x = pytest.importorskip("yara_x")
    from sandworm.detect.yara_gen import YaraRule
    rule = YaraRule("valid_rule", [b"anchor"], 1, {"description": 'quote"\ncondition: true //\\'})
    assert yara_x.compile(rule.to_yara()).scan(b"anchor").matching_rules
    assert not yara_x.compile(rule.to_yara()).scan(b"unrelated").matching_rules
    empty_metadata = YaraRule("no_metadata", [b"anchor"], 1)
    assert "meta:" not in empty_metadata.to_yara()
    assert empty_metadata.matches(b"anchor")
    with pytest.raises(ValueError, match="identifier"):
        YaraRule("bad } rule injected", [b"x"], 1).to_yara()
