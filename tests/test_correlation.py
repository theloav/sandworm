"""Static-to-runtime address correlation and native CAPE normalization."""

from __future__ import annotations

import json
import struct

import pytest

from sandworm.analyzers.base import Context
from sandworm.analyzers.dynamic.windows_cape import normalize_cape_report
from sandworm.analyzers.memory.vol3 import normalize_memory_report
from sandworm.analyzers.static.disasm import DisassemblyAnalyzer, capstone_available
from sandworm.core.evidence import EvidenceItem, EvidenceLocation, EvidenceStore
from sandworm.core.pipeline import analyze_sample, build_report_inputs
from sandworm.core.sample import Sample
from sandworm.reconstruct.correlation import annotate_runtime_addresses
from sandworm.reconstruct.graph import build_graph
from sandworm.reporting.report import render_html


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


def _native_report(sample: Sample, caller: str = "0x501000") -> dict:
    return {
        "target_sha256": sample.sha256,
        "target": {"file": {"name": sample.name, "sha256": sample.sha256}},
        "behavior": {
            "processes": [
                {
                    "process_id": 1840,
                    "parent_id": 1200,
                    "process_name": sample.name,
                    "module_path": rf"C:\sandbox\{sample.name}",
                    "environ": {"DllBase": "0x500000"},
                    "calls": [
                        {
                            "id": 7,
                            "thread_id": "44",
                            "caller": caller,
                            "api": "VirtualAllocEx",
                            "category": "memory",
                            "status": True,
                            "arguments": [
                                {"name": "Size", "value": "4096"},
                            ],
                        }
                    ],
                }
            ]
        },
    }


def test_native_cape_process_calls_keep_address_context():
    sample = Sample.from_bytes("tiny.exe", _pe32(b"\xc3"), "pe")
    items = list(normalize_cape_report(_native_report(sample), Context(run_id="r"), "sample:x"))
    process = next(item for item in items if item.artifact == "process")
    call = next(item for item in items if item.artifact == "api_call")
    assert process.object["pid"] == 1840
    assert process.subject["pid"] == 1200
    assert call.subject["name"] == "tiny.exe"
    assert call.details["arguments"] == [{"name": "Size", "value": "4096"}]
    assert call.locations == [
        EvidenceLocation(
            rva=0x1000,
            virtual_address=0x501000,
            instruction_address=0x501000,
            module=r"C:\sandbox\tiny.exe",
            module_base=0x500000,
            pid=1840,
            thread_id=44,
            event_id="7",
            artifact_sha256=sample.sha256,
        )
    ]


def test_pipeline_accepts_native_cape_target_hash_location(tmp_path):
    sample = Sample.from_bytes("tiny.exe", _pe32(b"\xc3"))
    native = _native_report(sample)
    native.pop("target_sha256")
    report = tmp_path / "native-cape.json"
    report.write_text(json.dumps(native))
    result = analyze_sample(sample, enable_dynamic=False, cape_report=str(report))
    assert "dynamic.windows.cape(replay)" in result.analyzers_run
    assert not any("refused" in note for note in result.notes)


@pytest.mark.skipif(not capstone_available(), reason="capstone not installed")
def test_pipeline_correlates_aslr_rebased_call_to_entry_function(tmp_path):
    sample = Sample.from_bytes("tiny.exe", _pe32(b"\xc3"))
    report = tmp_path / "cape.json"
    report.write_text(json.dumps(_native_report(sample)))
    result = analyze_sample(
        sample,
        enable_dynamic=False,
        cape_report=str(report),
        use_cache=False,
    )
    call = next(
        item
        for item in result.store
        if item.source == "dynamic.windows.cape" and item.artifact == "api_call"
    )
    correlations = call.details["address_correlations"]
    assert len(correlations) == 1
    assert correlations[0]["function"] == "entry"
    assert correlations[0]["runtime_event"] == "VirtualAllocEx"
    assert correlations[0]["match_basis"] == "module_rva"
    assert call.locations[0].function == "entry"
    assert any("correlated 1 dynamic" in note for note in result.notes)
    assert any(edge.rel == "OBSERVED_AT" for edge in result.graph.edges)
    html = render_html(build_report_inputs(result))
    assert "Static ↔ runtime address correlation" in html
    assert "module rva" in html

    persisted = tmp_path / "evidence.jsonl"
    result.store.dump(str(persisted))
    rebuilt = build_graph(EvidenceStore.load(str(persisted)), mappings=[])
    assert any(edge.rel == "OBSERVED_AT" for edge in rebuilt.edges)


@pytest.mark.skipif(not capstone_available(), reason="capstone not installed")
def test_preferred_va_match_works_without_a_load_base():
    sample = Sample.from_bytes("tiny.exe", _pe32(b"\xc3"), "pe")
    store = EvidenceStore()
    store.extend(DisassemblyAnalyzer().analyze(sample, Context(run_id="r")))
    runtime = EvidenceItem(
            run_id="r",
            source="dynamic.test",
            artifact="api_call",
            operation="exec",
            subject={"name": sample.name, "pid": 1},
            object={"api": "Example"},
            confidence=0.8,
            locations=[
                EvidenceLocation(
                    virtual_address=0x401000,
                    instruction_address=0x401000,
                    module=sample.name,
                )
            ],
        )
    annotated, count = annotate_runtime_addresses(store, [runtime], sample)
    assert count == 1
    assert annotated[0].details["address_correlations"][0]["match_basis"] == "preferred_va"


@pytest.mark.skipif(not capstone_available(), reason="capstone not installed")
def test_hash_mismatch_and_undecoded_gap_are_not_correlated():
    sample = Sample.from_bytes("jump.exe", _pe32(b"\xeb\x04\xcc\xcc\xcc\xcc\xc3"), "pe")
    store = EvidenceStore()
    store.extend(DisassemblyAnalyzer().analyze(sample, Context(run_id="r")))
    runtime_items = []
    for rva, digest in ((0x1000, "f" * 64), (0x1004, sample.sha256)):
        runtime_items.append(
            EvidenceItem(
                run_id="r",
                source="dynamic.test",
                artifact="api_call",
                operation="exec",
                subject={"name": sample.name},
                object={"api": f"At{rva:x}"},
                confidence=0.8,
                locations=[
                    EvidenceLocation(
                        rva=rva,
                        virtual_address=0x500000 + rva,
                        instruction_address=0x500000 + rva,
                        module=sample.name,
                        module_base=0x500000,
                        artifact_sha256=digest,
                    )
                ],
            )
        )
    annotated, count = annotate_runtime_addresses(store, runtime_items, sample)
    assert count == 0
    assert all("address_correlations" not in item.details for item in annotated)


def test_memory_rows_preserve_pid_and_virtual_address():
    report = {
        "sections": [
            {
                "plugin": "windows.malfind.Malfind",
                "rows": [{"PID": 42, "Process": "x.exe", "Start VPN": "0x700000"}],
            }
        ]
    }
    items = list(normalize_memory_report(report, Context(run_id="r"), "memory:x"))
    item = next(row for row in items if row.operation == "inject")
    assert item.locations[0].pid == 42
    assert item.locations[0].virtual_address == 0x700000


@pytest.mark.skipif(not capstone_available(), reason="capstone not installed")
@pytest.mark.parametrize("module,rva,base", [
    ("kernel32.dll", 0x1000, 0x400000),
    ("tiny.exe", 0x2000, 0x3FF000),
    ("tiny.exe", None, 0x500000),
])
def test_conflicting_module_or_rebase_cannot_fall_back_to_process_va(module, rva, base):
    sample = Sample.from_bytes("tiny.exe", _pe32(b"\xc3"), "pe")
    store = EvidenceStore()
    store.extend(DisassemblyAnalyzer().analyze(sample, Context(run_id="r")))
    runtime = EvidenceItem(
        run_id="r", source="dynamic.test", artifact="api_call", operation="exec",
        subject={"name": sample.name}, confidence=0.8,
        locations=[EvidenceLocation(
            module=module, rva=rva, module_base=base,
            instruction_address=0x401000, virtual_address=0x401000,
        )],
    )
    annotated, count = annotate_runtime_addresses(store, [runtime], sample)
    assert count == 0
    assert "address_correlations" not in annotated[0].details
