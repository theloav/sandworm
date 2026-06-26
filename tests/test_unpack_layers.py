"""Multi-stage unpacking & layered packer detection (#1)."""

from __future__ import annotations

import os

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.unpack import UnpackAnalyzer
from sandworm.core.evidence import EvidenceStore
from sandworm.core.sample import Sample
from sandworm.reconstruct.attack_map import map_evidence


def _layers(data: bytes):
    s = Sample.from_bytes("x.exe", data)
    s.format_hint = "pe"
    return UnpackAnalyzer().run(s, Context(run_id="t"))


def test_signature_packer_emits_two_linked_layers_with_decay():
    items = _layers(b"MZ" + b"\x00" * 64 + b"UPX0\x00UPX1\x00" + b"\x00" * 64)
    assert len(items) == 2
    l0, l1 = items
    assert l0.object["layer"] == 0 and "UPX" in l0.object["function"]
    assert l1.object["layer"] == 1 and l1.details["parent_layer"] == 0
    assert l1.confidence < l0.confidence            # confidence decays per layer
    assert l0.id in l1.evidence_refs                # parent → child link
    # layer 0 maps to Obfuscated Files (T1027); the pending layer 1 does not invent one
    assert l0.details["attack_hint"] == "T1027"
    assert "attack_hint" not in l1.details


def test_entropy_only_detects_unknown_packer_at_lower_confidence():
    packed = b"MZ" + os.urandom(8192)             # high-entropy body, no signature
    items = _layers(packed)
    assert items and "unknown" in items[0].object["function"]
    assert items[0].confidence < 0.95              # heuristic, not signature-certain


def test_benign_low_entropy_binary_is_not_flagged_packed():
    # loader_demo-style stub (MZ + zeros): no packer signature, low entropy → no layers.
    assert _layers(b"MZ" + b"\x00" * 4096) == []


def test_packer_layer_drives_t1027():
    items = _layers(b"MZ\x00.vmp0\x00.vmp1\x00" + b"\x00" * 64)
    store = EvidenceStore()
    store.extend(items)
    assert "T1027" in {m.technique_id for m in map_evidence(store)}
