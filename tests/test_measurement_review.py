import hashlib
import json
import re
from pathlib import Path

import pytest

from sandworm.evaluation.corpus_review import audit_corpus
from sandworm.evaluation.goodware import audit, inventory
from sandworm.evaluation.selection import ScriptedSelectionProbe, evaluate_selection

SELECTION = Path(__file__).parents[1] / "benchmarks/selection-manifest.json"


def test_frozen_rule_positive_controls_preserve_known_php_miss():
    yara_x = pytest.importorskip("yara_x")
    root = SELECTION.parent.parent
    rules = yara_x.compile((root / "benchmarks/audited-rules.yar").read_text())
    powershell = rules.scan((root / "benchmarks/fixtures/download.ps1").read_bytes())
    php = rules.scan((root / "samples/synthetic/benign_webshell.php").read_bytes())
    assert [rule.identifier for rule in powershell.matching_rules] == ["SANDWORM_77e23fc54a15"]
    # Frozen audit artifact has a known source-sample false negative. Do not
    # silently repair it while retaining the old audit's hashes and claims.
    assert list(php.matching_rules) == []


def test_selection_probe_exposes_residual_risk_without_live_asr_claim():
    result = evaluate_selection(SELECTION, ScriptedSelectionProbe(), repeats=2)
    assert result["pairs"] == result["conditional_failures"] == 10
    assert result["out_of_context_selections"] == 0
    assert all(row["attack_target_available"] for row in result["results"])
    assert result["manipulation_success_rate"] is None
    with pytest.raises(ValueError, match="live model"):
        evaluate_selection(SELECTION, ScriptedSelectionProbe(), live_model="fake")


def test_baseline_failures_are_not_counted_as_manipulation_successes():
    class Wrong:
        name = "always-wrong-test"

        def complete(self, system, prompt, *, max_tokens=1024):
            ids = [match.group(1) for line in prompt.splitlines() if "EXAMPLE_RECORD" in line
                   and (match := re.match(r"\[(ev_[a-f0-9]{16})\]", line))]
            return json.dumps({"evidence_ids": ids[:1]})

    result = evaluate_selection(SELECTION, Wrong())
    assert result["clean_correct_pairs"] == result["conditional_failures"] == 0
    assert result["scripted_conditional_failure_rate"] is None


def test_invalid_provider_responses_count_as_rejections():
    class Invalid:
        name = "invalid-output-test"

        def complete(self, system, prompt, *, max_tokens=1024):
            return '{"evidence_ids": ["ev_0000000000000000"]}'

    result = evaluate_selection(SELECTION, Invalid())
    assert result["rejections"] == 5
    assert not result["conditional_failures"]


def _reviewed_manifest(tmp_path):
    rows = []
    for index, split in enumerate(("train", "validation", "test")):
        content = f"fixture-{index}".encode()
        sample = tmp_path / f"{index}.txt"
        sample.write_bytes(content)
        rows.append({"id": str(index), "path": sample.name, "sha256": hashlib.sha256(content).hexdigest(),
                     "split": split, "family": f"project-{index}", "first_seen": f"202{index}-01-01",
                     "provenance": "test fixture", "rationale": "metadata-validator test only",
                     "positive": ["T1059"], "negative": ["T1486"],
                     "reviews": [{"annotator": reviewer, "positive": ["T1059"], "negative": ["T1486"]} for reviewer in ("alice", "bob")]})
    document = {"schema_version": 1, "label_policy": "static-behavior-capability-v1", "cases": rows}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document))
    return path, document


def test_review_checks_identity_disjoint_splits_and_reviewers(tmp_path):
    path, document = _reviewed_manifest(tmp_path)
    assert audit_corpus(path, min_test_cases=1)["ready_for_scoped_evaluation"]
    assert not audit_corpus(path)["ready_for_scoped_evaluation"]  # release-scale guard
    document["cases"][2]["family"] = "project-0"
    document["cases"][2]["first_seen"] = "2019-01-01"
    document["cases"][0]["reviews"][1]["positive"] = []
    path.write_text(json.dumps(document))
    issues = audit_corpus(path, min_test_cases=1)["issues"]
    assert any("family/project leakage" in issue for issue in issues)
    assert any("time leakage" in issue for issue in issues)
    assert any("adjudicator" in issue for issue in issues)
    (tmp_path / "0.txt").write_bytes(b"changed")
    assert any("sample unavailable" in issue for issue in audit_corpus(path)["issues"])


def test_population_selection_and_rule_specific_denominator(tmp_path):
    pytest.importorskip("yara_x")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.php").write_bytes(b"php anchor")
    (corpus / "b.ps1").write_bytes(b"powershell")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(inventory(corpus, provenance="test", extensions=(".php",))))
    rules = tmp_path / "rules.yar"
    rules.write_text('rule php { strings: $a="anchor" condition: $a } rule unrelated { condition: true }')
    result = audit(rules, manifest, corpus, rule_name="php")
    assert result["files_scanned"] == result["matching_files"] == 1
    assert result["selected_rules"] == ["php"]
    assert result["extensions"] == [".php"]
    with pytest.raises(ValueError, match="does not exist"):
        audit(rules, manifest, corpus, rule_name="missing")
