from __future__ import annotations

import io
import json
import struct
import zipfile

import pytest

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.containers import ContainerAnalyzer, class_strings, dex_strings
from sandworm.analyzers.static.firmware import firmware_volumes
from sandworm.analyzers.static.macho import parse_macho
from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.pipeline import analyze_sample
from sandworm.core.sample import Sample
from sandworm.enrich.intelligence import enrich_snapshot
from sandworm.sandbox.provision import cloud_config


def test_sample_bound_linux_replay_and_foreign_refusal(tmp_path):
    sample = Sample.from_bytes("x.sh", b"#!/bin/sh\necho hello\n")
    document = {"target_sha256": sample.sha256, "traces": [{"kind": "linux", "text": '42 openat(AT_FDCWD, "/tmp/test", O_RDONLY) = 3\n42 execve("/bin/echo", ["echo"], []) = 0'}]}
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(document))
    result = analyze_sample(sample, runtime_report=str(path))
    assert any(e.source == "dynamic.linux" and e.operation == "spawn" for e in result.store)
    document["target_sha256"] = "0" * 64
    path.write_text(json.dumps(document))
    refused = analyze_sample(sample, runtime_report=str(path))
    assert not any(e.source.startswith("dynamic.") for e in refused.store)
    assert any("different sample" in note for note in refused.notes)


def test_archive_constant_pool_ioc_and_expansion_limit():
    value = b"https://192.0.2.10/path"
    klass = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 2) + b"\x01" + struct.pack(">H", len(value)) + value
    assert class_strings(klass) == [value.decode()]
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Main-Class: Demo")
        archive.writestr("Demo.class", klass)
        archive.writestr("large.class", b"A" * (9 * 1024**2))
    items = ContainerAnalyzer().run(Sample.from_bytes("demo.jar", blob.getvalue()), Context("r"))
    assert any(e.object.get("value") == value.decode() for e in items)
    assert not any(e.object.get("member") == "large.class" for e in items)
    assert dex_strings(b"dex\n" + b"\x00" * 108) == []


def test_macho_dependencies_and_bad_command():
    dep = b"/usr/lib/libSystem.B.dylib\x00"
    cmd = struct.pack("<6I", 12, 24 + len(dep), 24, 0, 0, 0) + dep
    header = struct.pack("<8I", 0xFEEDFACF, 0x1000007, 3, 2, 1, len(cmd), 0, 0)
    assert parse_macho(header + cmd)[1]["name"] == dep[:-1].decode()
    with pytest.raises(ValueError):
        parse_macho(header + struct.pack("<II", 12, 0) + cmd[8:])


def test_firmware_volume_checksum_and_bounds():
    data = bytearray(b"\x00" * 56 + b"\xff" * 200)
    struct.pack_into("<Q", data, 32, len(data))
    data[40:44] = b"_FVH"
    struct.pack_into("<H", data, 48, 56)
    checksum = (-sum(struct.unpack_from("<28H", data))) & 0xFFFF
    struct.pack_into("<H", data, 50, checksum)
    rows = firmware_volumes(bytes(data))
    assert len(rows) == 1 and rows[0]["header_checksum_valid"]
    assert not firmware_volumes(bytes(data[:60]))


def test_offline_intel_is_cited_and_stale(tmp_path):
    store = EvidenceStore()
    item = EvidenceItem(run_id="r", source="static.test", artifact="string", operation="read",
                        object={"kind": "domain", "value": "example.test"}, confidence=0.7)
    store.append(item)
    snapshot = tmp_path / "intel.json"
    snapshot.write_text(json.dumps({"schema_version": 1, "source": "lab", "created_at": "2020-01-01T00:00:00Z",
                                    "indicators": [{"kind": "domain", "value": "example.test", "confidence": 0.8}]}))
    evidence = enrich_snapshot(store, snapshot, "r")
    assert evidence[0].details["stale"]
    assert evidence[0].confidence == 0.4
    assert evidence[0].evidence_refs == ["evidence:" + item.id]


def test_cloud_config_has_guest_only_agent_and_no_sample():
    cfg = json.loads(cloud_config().split("\n", 1)[1])
    assert "strace" in cfg["packages"]
    assert cfg["ssh_pwauth"] is False
    assert not any("sudo" in u for u in cfg["users"])


def test_graph_clustering_repeated_samples():
    pytest.importorskip("sklearn")
    from sandworm.reconstruct.clustering import cluster_runs
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.test", artifact="api_call", operation="exec",
                              object={"api": "example"}, confidence=0.7))
    result = cluster_runs({"a": store, "b": store})
    assert sorted(next(iter(result["clusters"].values()))) == ["a", "b"]


def test_hypotheses_reject_fabricated_evidence_ids():
    from sandworm.copilot.hypotheses import propose
    class Provider:
        name = "test"
        def complete(self, system, prompt, *, max_tokens=1024):
            return json.dumps({"hypotheses": [{"claim": "invented", "evidence_ids": ["missing"], "validation": "inspect"}]})
    assert propose(EvidenceStore(), Provider())["hypotheses"] == []


def test_decompiler_report_is_sample_bound(tmp_path):
    sample = Sample.from_bytes("test.bin", b"test")
    report = tmp_path / "decompiler.json"
    report.write_text(json.dumps({"target_sha256": sample.sha256, "image_base": "00400000", "functions": [
        {"name": "main", "entry": "00401000", "completed": True, "c": "int main() { return 0; }",
         "instructions": [{"address": "00401000", "size": 1, "pcode": []}]}]}))
    result = analyze_sample(sample, decompiler_report=str(report))
    assert any(e.source == "static.ghidra" and e.object["function"] == "main" for e in result.store)
    with pytest.raises(ValueError, match="another sample"):
        analyze_sample(Sample.from_bytes("other", b"different"), decompiler_report=str(report))
