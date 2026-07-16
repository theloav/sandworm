"""Tests for the goodware clean-corpus loader and its effect on YARA generation."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.sample import Sample
from sandworm.detect.yara_gen import generate_yara, load_clean_corpus


def test_load_corpus_missing_dir_is_empty(tmp_path):
    assert load_clean_corpus(tmp_path / "does-not-exist") == []


def test_load_corpus_reads_files_and_skips_readme(tmp_path):
    (tmp_path / "README.md").write_text("docs")
    (tmp_path / "good1.bin").write_bytes(b"benign one")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "good2.bin").write_bytes(b"benign two")
    corpus = load_clean_corpus(tmp_path)
    assert b"benign one" in corpus and b"benign two" in corpus
    assert b"docs" not in corpus  # README excluded


def test_load_corpus_caps_file_size(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"A" * (9 * 1024 * 1024))
    corpus = load_clean_corpus(tmp_path)
    assert len(corpus) == 1
    assert len(corpus[0]) <= 8 * 1024 * 1024


def _store_with_anchor(anchor: str) -> EvidenceStore:
    store = EvidenceStore()
    store.append(EvidenceItem(
        run_id="r", source="static.common", artifact="network", operation="resolve",
        object={"kind": "url", "value": anchor}, details={"ioc": True}, confidence=0.8,
    ))
    return store


def test_generated_rule_pruned_against_goodware():
    # A distinctive anchor that also appears in the goodware corpus must NOT
    # survive into a generated rule (it would false-positive).
    anchor = "http://shared-infra.example.top/gate"
    sample = Sample.from_bytes("m.bin", anchor.encode() + b" extra malware bytes")
    goodware = [b"a benign file that also references " + anchor.encode()]
    rules = generate_yara(_store_with_anchor(anchor), sample, clean_corpus=goodware)
    for r in rules:
        assert not any(anchor.encode() in doc for doc in goodware if r.matches(doc))
        assert anchor.encode() not in r.strings
