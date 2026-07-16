"""Tests for the encoded-string sweep (base64 / hex / XOR recovery)."""

from __future__ import annotations

import base64

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.decode import DecodeAnalyzer
from sandworm.core.sample import Sample


def _run(data: bytes):
    s = Sample.from_bytes("t.exe", data, format_hint="pe")
    return DecodeAnalyzer().analyze(s, Context(run_id="t"))


def _iocs(items):
    return {i.object.get("value") for i in items if i.details.get("ioc")}


def test_base64_hidden_c2_recovered():
    blob = base64.b64encode(b"http://evil-c2.example.ru/gate.php").decode().encode()
    items = _run(b"MZ" + b"\x00" * 40 + b" junk " + blob + b" more")
    assert "http://evil-c2.example.ru/gate.php" in _iocs(items)
    # hidden IOC carries a confidence bump over the plaintext base rate (0.7).
    ioc = next(i for i in items if i.details.get("ioc"))
    assert ioc.confidence > 0.7
    assert ioc.details["decoded_from"] == "base64"


def test_xor_hidden_url_recovered():
    key = 0x5A
    xored = bytes(b ^ key for b in b"http://xor-c2.example.top/beacon")
    items = _run(b"MZ" + b"\x00" * 40 + b"pad" + xored + b"pad")
    hosts = {v for v in _iocs(items)}
    assert any("xor-c2.example.top" in str(h) for h in hosts)
    assert any(i.object.get("function", "").startswith("xor:") for i in items)


def test_decode_layer_maps_to_deobfuscation():
    # The decode layer sets attack_hint T1140 (Deobfuscate/Decode).
    blob = base64.b64encode(b"http://c.somebadhost.ru/x").decode().encode()
    items = _run(b"MZ\x00\x00 " + blob + b" \x00")
    assert any(i.details.get("attack_hint") == "T1140" for i in items)


def test_ransomware_recovered_from_base64():
    note = b"Your files have been encrypted! Send bitcoin to recover your files."
    blob = base64.b64encode(note).decode().encode()
    items = _run(b"MZ" + b"\x00" * 20 + blob)
    assert any(i.object.get("capability") == "ransomware" for i in items)


def test_no_false_positives_on_plain_text():
    # Plain english + a normal file path must not manufacture decode findings.
    items = _run(b"The quick brown fox jumps over the lazy dog. C:/Program Files/app.exe")
    assert not any(i.details.get("ioc") for i in items)


def test_short_or_garbage_blobs_ignored():
    # Random high-entropy bytes should not yield "meaningful" decodes/IOCs.
    import os

    items = _run(b"MZ" + os.urandom(4096))
    assert not _iocs(items)
