"""Generated YARA must NOT hit the bundled clean corpus."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.sample import Sample
from sandworm.detect.yara_gen import (
    CLEAN_CORPUS,
    YaraRule,
    generate_yara,
    passes_clean_corpus,
)


def _store_with_payload():
    s = EvidenceStore()
    s.append(
        EvidenceItem(
            run_id="r", source="static.php", artifact="string", operation="decode",
            subject={"a": "x"},
            object={"layer": 0, "function": "base64_decode"},
            details={"decoded_preview": "system($_REQUEST['cmd']); $sandworm_marker_Xy7Q = 'beacon_to_10_0_0_1';"},
            confidence=0.95,
        )
    )
    s.append(
        EvidenceItem(
            run_id="r", source="static.php", artifact="api_call", operation="exec",
            subject={"a": "x"}, object={"sink": "shell_exec"}, confidence=0.9,
        )
    )
    return s


def test_generated_rules_are_clean():
    sample = Sample.from_bytes("x.php", b"<?php /* unique_marker_Zq91 */ eval($x); ?>")
    rules = generate_yara(_store_with_payload(), sample)
    assert rules, "expected at least one clean rule"
    assert passes_clean_corpus(rules)
    for r in rules:
        for doc in CLEAN_CORPUS:
            assert not r.matches(doc)


def test_generic_strings_are_pruned():
    # A rule built only from generic tokens that appear in the clean corpus must
    # be dropped rather than shipped.
    s = EvidenceStore()
    s.append(
        EvidenceItem(
            run_id="r", source="static.php", artifact="string", operation="decode",
            subject={"a": "x"}, object={"layer": 0, "function": "x"},
            details={"decoded_preview": "function console phpinfo rsync backup"},
            confidence=0.9,
        )
    )
    sample = Sample.from_bytes("x.php", b"function console phpinfo rsync backup")
    rules = generate_yara(s, sample)
    assert passes_clean_corpus(rules)


def test_to_yara_serializes():
    rule = YaraRule(name="t", strings=[b"unique_marker_Zq91"], condition_min=1, meta={"a": "b"})
    text = rule.to_yara()
    assert "rule t" in text and "condition" in text
