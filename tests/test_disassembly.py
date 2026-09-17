"""Address-aware PE/ELF layout and bounded disassembly tests."""

from __future__ import annotations

import struct

import pytest

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.disasm import (
    DisassemblyAnalyzer,
    capstone_available,
    discover,
    elf_layout,
    pe_layout,
)
from sandworm.core.evidence import EvidenceStore
from sandworm.core.sample import Sample
from sandworm.reconstruct.graph import build_graph

pytestmark = pytest.mark.skipif(not capstone_available(), reason="capstone not installed")


def _pe32(code: bytes, *, entry_rva: int = 0x1000, base: int = 0x400000) -> bytes:
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    opt_size = 0x60 + 16 * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x0102)
    optional = bytearray(opt_size)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 0x10, entry_rva)
    struct.pack_into("<I", optional, 0x1C, base)
    raw_ptr = e_lfanew + 4 + 20 + opt_size + 40
    body = code + b"\x00" * (0x200 - len(code))
    section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIII", len(body), 0x1000, len(body), raw_ptr)
        + b"\x00" * 12
        + struct.pack("<I", 0x60000020)
    )
    return dos + b"PE\x00\x00" + coff + bytes(optional) + section + body


def _elf64(code: bytes, *, entry: int = 0x400000) -> bytes:
    code_offset = 0x100
    header = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    header += struct.pack("<HHI", 2, 0x3E, 1)
    header += struct.pack("<QQQ", entry, 0x40, 0)
    header += struct.pack("<IHHHHHH", 0, 64, 56, 1, 0, 0, 0)
    program = struct.pack(
        "<IIQQQQQQ", 1, 0x5, code_offset, 0x400000, 0x400000, len(code), len(code), 0x1000
    )
    return header + program + b"\x00" * (code_offset - len(header) - len(program)) + code


def test_pe_layout_preserves_file_rva_and_va_coordinates():
    layout = pe_layout(_pe32(b"\xc3"))
    assert layout is not None
    assert layout.entrypoint == 0x401000
    location = layout.regions[0].location(layout.entrypoint)
    assert location.file_offset == 0x1A0
    assert location.rva == 0x1000
    assert location.virtual_address == 0x401000
    assert location.section == ".text"


def test_pe_discovers_direct_call_and_two_functions():
    # call 0x401006; ret; callee: ret
    sample = Sample.from_bytes("calls.exe", _pe32(b"\xe8\x01\x00\x00\x00\xc3\xc3"), "pe")
    result = discover(sample)
    assert result is not None
    assert [(function.name, function.address) for function in result.functions] == [
        ("entry", 0x401000),
        ("sub_401006", 0x401006),
    ]
    assert result.instruction_count == 3
    assert len(result.calls) == 1
    assert (result.calls[0].caller, result.calls[0].callee, result.calls[0].callsite) == (
        0x401000,
        0x401006,
        0x401000,
    )


def test_unconditional_jump_target_is_traversed_as_a_basic_block():
    # jmp 0x401006; unreachable padding; ret
    sample = Sample.from_bytes("jump.exe", _pe32(b"\xeb\x04\xcc\xcc\xcc\xcc\xc3"), "pe")
    result = discover(sample)
    assert result is not None
    assert [instruction.address for instruction in result.functions[0].instructions] == [
        0x401000,
        0x401006,
    ]
    assert result.functions[0].basic_blocks == (0x401000, 0x401006)

    items = DisassemblyAnalyzer().analyze(sample, Context(run_id="ranges"))
    function = next(item for item in items if item.artifact == "function")
    assert function.details["address_ranges"] == [
        {"start_va": 0x401000, "end_va": 0x401002, "start_rva": 0x1000, "end_rva": 0x1002},
        {"start_va": 0x401006, "end_va": 0x401007, "start_rva": 0x1006, "end_rva": 0x1007},
    ]


def test_elf_layout_and_discovery_preserve_virtual_address():
    sample = Sample.from_bytes("tiny.elf", _elf64(b"\xc3"), "elf")
    layout = elf_layout(sample.data)
    assert layout is not None
    assert layout.architecture == "x86" and layout.bits == 64
    location = layout.regions[0].location(layout.entrypoint)
    assert location.file_offset == 0x100
    assert location.virtual_address == 0x400000
    assert location.rva is None
    result = discover(sample)
    assert result is not None
    assert len(result.functions) == 1
    assert result.functions[0].instructions[0].mnemonic == "ret"


def test_entrypoint_outside_executable_region_is_rejected():
    assert elf_layout(_elf64(b"\xc3", entry=0x500000)) is None
    assert pe_layout(_pe32(b"\xc3", entry_rva=0x2000)) is None


def test_analyzer_emits_addressed_evidence_and_call_graph():
    sample = Sample.from_bytes("calls.exe", _pe32(b"\xe8\x01\x00\x00\x00\xc3\xc3"), "pe")
    items = DisassemblyAnalyzer().analyze(sample, Context(run_id="disasm-test"))
    functions = [item for item in items if item.artifact == "function"]
    calls = [item for item in items if item.operation == "call"]
    assert len(functions) == 2 and len(calls) == 1
    assert all(item.locations for item in items)
    assert calls[0].locations[0].instruction_address == 0x401000

    store = EvidenceStore()
    store.extend(items)
    graph = build_graph(store, mappings=[], sample_name=sample.name)
    assert {node.props["display"] for node in graph.find_nodes(label="Function")} == {
        "entry",
        "sub_401006",
    }
    call_edges = [edge for edge in graph.edges if edge.rel == "CALLS"]
    assert len(call_edges) == 1
    evidence_nodes = graph.find_nodes(label="Evidence")
    assert any(node.props["locations"] for node in evidence_nodes)
