"""Synthetic adversarial sample generation (#6) — benign, label-preserving."""

from __future__ import annotations

import re
from pathlib import Path

from sandworm.core.sample import Sample
from sandworm.enrich.generate import generate_variants, label_preserved

_SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "synthetic"


def _webshell() -> Sample:
    return Sample.from_path(_SAMPLES / "benign_webshell.php")


def test_variants_are_byte_different_but_label_preserved():
    base = _webshell()
    variants = generate_variants(base, count=6, seed=1)
    assert len(variants) == 6
    seen = {base.data}
    for v in variants:
        assert v.data not in seen, "variant duplicated the base or another variant"
        seen.add(v.data)
        assert label_preserved(base, Sample.from_bytes(v.name, v.data)), v.name


def test_iocs_rotated_to_reserved_nonroutable_ranges():
    # A sample with a real-looking domain/IP must come back with reserved ones, so
    # generated test data never embeds a routable indicator.
    s = Sample.from_bytes("beacon.php", b"<?php system($_REQUEST['c']); $u='evil-c2.ru'; $ip='8.8.8.8';")
    for v in generate_variants(s, count=4, seed=3):
        text = v.data.decode("latin-1")
        assert "evil-c2.ru" not in text and "8.8.8.8" not in text
        # rotated values land in reserved space only
        assert re.search(r"\.(test|invalid|example)\b", text)
        assert "198.51.100." in text


def test_cleartext_sinks_survive_mutation():
    # On a cleartext sample the execution sink (what detection keys on) must be
    # preserved verbatim, even as identifiers/whitespace are mutated around it.
    s = Sample.from_bytes("shell.php", b"<?php $cmd = $_REQUEST['c']; system($cmd); // beacon evil-c2.ru\n")
    for v in generate_variants(s, count=4, seed=5):
        text = v.data.decode("latin-1")
        assert "system(" in text and "$_REQUEST" in text   # sink + taint source intact
        assert "evil-c2.ru" not in text                     # but IOC rotated away


def test_deterministic_for_seed():
    base = _webshell()
    a = generate_variants(base, count=3, seed=9)
    b = generate_variants(base, count=3, seed=9)
    assert [v.data for v in a] == [v.data for v in b]


def test_binary_sample_gets_inert_overlay():
    s = Sample.from_bytes("x.exe", b"MZ" + b"\x00" * 64)
    v = generate_variants(s, count=1, seed=0)[0]
    assert v.data.startswith(b"MZ")
    assert b"SANDWORM-VARIANT-" in v.data and len(v.data) > 66
