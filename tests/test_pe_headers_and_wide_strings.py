"""Tests for the dependency-free PE header parser, wide-string extraction,
UTF-16 ransomware detection, and PE-signature-verified triage."""

from __future__ import annotations

import struct

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.common import (
    extract_all_strings,
    extract_wide_strings,
    is_ransomware,
    ransomware_scan,
    shannon_entropy,
)
from sandworm.analyzers.static.pe import PeAnalyzer, parse_pe_headers
from sandworm.core.sample import Sample
from sandworm.core.triage import identify


def _build_pe(
    *,
    timestamp: int = 1_600_000_000,
    section_chars: int = 0x6000_0020,  # code | execute | read
    section_data: bytes = b"\x90" * 64,
    overlay: bytes = b"",
) -> bytes:
    """A minimal but structurally valid PE: DOS header, PE sig, COFF header,
    empty optional header, one section."""
    e_lfanew = 0x40
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    opt_size = 0
    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, opt_size, 0x0102)
    raw_ptr = e_lfanew + 4 + 20 + opt_size + 40
    section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIII", len(section_data), 0x1000, len(section_data), raw_ptr)
        + b"\x00" * 12
        + struct.pack("<I", section_chars)
    )
    return dos + b"PE\x00\x00" + coff + section + section_data + overlay


def test_parse_pe_headers_sections_and_timestamp():
    pe = _build_pe()
    h = parse_pe_headers(pe)
    assert h is not None
    assert h["timestamp"] == 1_600_000_000
    assert len(h["sections"]) == 1
    assert h["sections"][0]["name"] == ".text"
    assert h["overlay_size"] == 0


def test_parse_pe_headers_rejects_dos_only():
    assert parse_pe_headers(b"MZ" + b"\x00" * 256) is None
    assert parse_pe_headers(b"not a pe at all") is None


def test_parse_pe_headers_overlay():
    overlay = bytes(range(256)) * 4  # 1KB, high entropy
    h = parse_pe_headers(_build_pe(overlay=overlay))
    assert h is not None
    assert h["overlay_size"] == len(overlay)
    assert h["overlay_entropy"] == 8.0


def _analyze(data: bytes):
    sample = Sample.from_bytes("t.exe", data, format_hint="pe")
    return PeAnalyzer().analyze(sample, Context(run_id="test"))


def test_wx_section_flagged():
    wx = 0x6000_0020 | 0x8000_0000  # + writable
    items = _analyze(_build_pe(section_chars=wx))
    hits = [i for i in items if "writable+executable" in str(i.details.get("why", ""))]
    assert hits and hits[0].details["attack_hint"] == "T1027"


def test_zeroed_timestamp_flagged():
    items = _analyze(_build_pe(timestamp=0))
    assert any(i.object.get("anomaly") == "compile_timestamp" for i in items)


def test_high_entropy_overlay_flagged():
    overlay = bytes(range(256)) * 4
    items = _analyze(_build_pe(overlay=overlay))
    hits = [i for i in items if i.object.get("anomaly") == "overlay"]
    assert hits and hits[0].details["attack_hint"] == "T1027"


def test_normal_pe_emits_no_anomalies():
    items = _analyze(_build_pe())
    assert not any(i.object.get("anomaly") for i in items)
    assert not any("writable+executable" in str(i.details.get("why", "")) for i in items)


# --- wide strings ---


def test_extract_wide_strings():
    payload = "https://evil-c2.example.ru/gate.php".encode("utf-16-le")
    data = b"\x00\x01\x02" + payload + b"\x03\x04"
    wide = extract_wide_strings(data)
    assert any("evil-c2.example.ru" in s for s in wide)
    # ASCII-only extraction must miss it; combined extraction must find it.
    assert any("evil-c2" in s for s in extract_all_strings(data))


def test_ransomware_scan_sees_utf16_needles():
    note = "All your files have been encrypted! Pay bitcoin to recover your files."
    cmd = "vssadmin delete shadows /all /quiet"
    data = b"MZ" + note.encode("utf-16-le") + cmd.encode("utf-16-le")
    recovery, cats = ransomware_scan(data)
    assert "vssadmin" in recovery
    assert "note" in cats and "payment" in cats
    assert is_ransomware(cats)


def test_ransomware_scan_still_sees_ascii():
    data = b"your files are encrypted ... vssadmin delete shadows"
    recovery, cats = ransomware_scan(data)
    assert "vssadmin" in recovery and "note" in cats


# --- entropy ---


def test_entropy_values():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    assert abs(shannon_entropy(bytes(range(256)) * 16) - 8.0) < 1e-9


# --- triage ---


def test_triage_verified_pe_high_confidence():
    r = identify(_build_pe())
    assert r.fmt == "pe" and r.confidence >= 0.99


def test_triage_mz_without_pe_sig_degraded():
    r = identify(b"MZ" + b"\x00" * 256)
    assert r.fmt == "pe" and r.confidence < 0.9


def test_triage_jar_and_apk_named():
    jar = b"PK\x03\x04" + b"META-INF/MANIFEST.MF" + b"foo.class"
    apk = b"PK\x03\x04" + b"AndroidManifest.xml" + b"classes.dex"
    assert identify(jar, "x.jar").fmt == "jar"
    r = identify(apk, "x.apk")
    assert r.fmt == "apk" and not r.supported
