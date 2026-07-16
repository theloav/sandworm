"""Tests for emulation-assisted unpacking (Unicorn-backed, optional)."""

from __future__ import annotations

import struct

import pytest

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.emulate import emulate_unpack, unicorn_available
from sandworm.analyzers.static.pe import parse_pe_headers
from sandworm.analyzers.static.unpack import UnpackAnalyzer
from sandworm.core.sample import Sample

pytestmark = pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")


def build_pe(shellcode: bytes, *, trailer: bytes = b"", entry_rva: int = 0x1000, base: int = 0x400000) -> bytes:
    """Minimal, valid PE32 with an executable .text section holding shellcode."""
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    opt_size = 0x60 + 16 * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0x00, 0x10B)       # PE32 magic
    struct.pack_into("<I", opt, 0x10, entry_rva)   # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x1C, base)        # ImageBase
    raw_ptr = e_lfanew + 4 + 20 + opt_size + 40
    body = shellcode + b"\x00" * (0x400 - len(shellcode))
    section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIII", 0x1000, entry_rva, len(body), raw_ptr)
        + b"\x00" * 12
        + struct.pack("<I", 0x60000020)  # CODE | EXECUTE | READ
    )
    return dos + b"PE\x00\x00" + coff + bytes(opt) + section + body + trailer


# mov eax,0xDEADBEEF ; mov [0x401500],eax ; ret
_STUB_WRITE = b"\xB8\xEF\xBE\xAD\xDE\xA3\x00\x15\x40\x00\xC3"


def test_emulator_detects_self_modification():
    pe = build_pe(_STUB_WRITE)
    result = emulate_unpack(pe, parse_pe_headers(pe))
    assert result is not None
    assert result.self_modifying is True
    assert result.write_count >= 1
    assert result.unpacked_bytes == b"\xef\xbe\xad\xde"


def _stub_writing_url() -> bytes:
    # Writes "http://evil.top\0" into exec memory at 0x401500 via 4 dword stores.
    chunks = [0x70747468, 0x652F2F3A, 0x2E6C6976, 0x00706F74]  # "http", "://e", "vil.", "top\0"
    code = b""
    for i, val in enumerate(chunks):
        code += b"\xB8" + struct.pack("<I", val)                       # mov eax, val
        code += b"\xA3" + struct.pack("<I", 0x401500 + i * 4)          # mov [addr], eax
    return code + b"\xC3"                                              # ret


def test_emulator_recovers_written_string():
    result = emulate_unpack(build_pe(_stub_writing_url()), parse_pe_headers(build_pe(_stub_writing_url())))
    assert b"http://evil.top" in result.unpacked_bytes


def test_unpack_analyzer_emits_emulated_layer_and_iocs():
    # Packer signature (UPX0) triggers the unpack lane; the stub then "unpacks" a
    # URL into executable memory, which emulation recovers and mines.
    pe = build_pe(_stub_writing_url(), trailer=b"UPX0UPX1")
    items = UnpackAnalyzer().analyze(Sample.from_bytes("packed.exe", pe, format_hint="pe"), Context(run_id="t"))
    # The recovered layer replaces the "requires_emulation" pending layer.
    recovered = [i for i in items if i.details.get("status") == "recovered_by_emulation"]
    assert recovered, "expected an emulated-recovery layer"
    assert recovered[0].details["attack_hint"] == "T1140"
    assert not any(i.details.get("status") == "requires_emulation" for i in items)
    # The URL hidden in the packed layer is now an IOC.
    iocs = {i.object.get("value") for i in items if i.details.get("ioc")}
    assert any("evil.top" in str(v) for v in iocs)


def test_emulate_returns_none_without_entry():
    # No entry point ⇒ nothing to emulate.
    headers = {"sections": [{"vaddr": 0x1000, "vsize": 0x1000, "raw_ptr": 0, "raw_size": 0, "characteristics": 0x20000000}],
               "entry_rva": 0, "image_base": 0x400000, "pe32_plus": False}
    assert emulate_unpack(b"MZ", headers) is None
