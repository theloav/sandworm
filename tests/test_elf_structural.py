"""Tests for the dependency-free ELF header parser and structural findings."""

from __future__ import annotations

import struct

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.elf import ElfAnalyzer, parse_elf_headers
from sandworm.core.sample import Sample

_PF_X, _PF_W = 0x1, 0x2
_PT_LOAD, _PT_GNU_STACK, _PT_INTERP = 1, 0x6474E551, 3


def _elf64(segments: list[tuple[int, int]], *, e_type: int = 2, with_symtab: bool = False) -> bytes:
    """Build a minimal valid 64-bit LE ELF with the given (p_type, p_flags) PHs."""
    e_phoff = 0x40
    e_phentsize = 56
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    hdr += struct.pack("<HHI", e_type, 0x3E, 1)
    hdr += struct.pack("<QQQ", 0, e_phoff, 0)
    hdr += struct.pack("<IHHHHHH", 0, 64, e_phentsize, len(segments), 0, 0, 0)
    phs = b"".join(
        struct.pack("<IIQQQQQQ", ptype, flags, 0, 0, 0, 0, 0, 0) for ptype, flags in segments
    )
    tail = b".symtab\x00" if with_symtab else b""
    return hdr + phs + tail


def test_parse_rejects_non_elf():
    assert parse_elf_headers(b"MZ" + b"\x00" * 64) is None
    assert parse_elf_headers(b"\x7fELF" + b"\xff" * 4) is None  # bad class/data


def test_parse_basic_fields():
    h = parse_elf_headers(_elf64([(_PT_LOAD, _PF_X)], e_type=3, with_symtab=True))
    assert h["bits"] == 64 and h["endian"] == "little"
    assert h["type"] == 3  # DYN (PIE)
    assert h["stripped"] is False


def _findings(data: bytes):
    items = ElfAnalyzer().analyze(Sample.from_bytes("x.elf", data, format_hint="elf"), Context(run_id="t"))
    return items


def test_rwx_segment_flagged():
    items = _findings(_elf64([(_PT_LOAD, _PF_W | _PF_X)]))
    assert any(i.object.get("flags") == "RWX" for i in items)


def test_exec_stack_flagged():
    items = _findings(_elf64([(_PT_GNU_STACK, _PF_X)]))
    assert any(i.object.get("segment") == "PT_GNU_STACK" for i in items)


def test_static_stripped_profile():
    # EXEC + no PT_INTERP + no .symtab → static & stripped implant profile.
    items = _findings(_elf64([(_PT_LOAD, _PF_X)], e_type=2, with_symtab=False))
    assert any(i.object.get("anomaly") == "static_stripped" for i in items)


def test_dynamic_binary_not_flagged_static():
    # Has PT_INTERP → dynamically linked, so not the static profile.
    items = _findings(_elf64([(_PT_LOAD, _PF_X), (_PT_INTERP, _PF_X)], with_symtab=True))
    assert not any(i.object.get("anomaly") == "static_stripped" for i in items)


def test_upx_packed_elf_flagged():
    data = _elf64([(_PT_LOAD, _PF_X)]) + b"UPX!" + b"\x00" * 16
    items = _findings(data)
    assert any(i.object.get("function") == "UPX" for i in items)
