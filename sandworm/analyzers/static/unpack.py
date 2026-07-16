"""Multi-stage unpacking & layered packer detection (static).

The PHP lane already peels ``eval(base64(...))`` chains one layer at a time. This
brings the same layered model to binaries: treat every PE as potentially packed
and emit each layer as its own evidence with a parent→child link, so the reasoning
graph shows *what the packed layer contained that made the next layer knowable*.

We are honest about what static analysis can and cannot recover:

* **Layer 0 (raw):** the packed/encrypted image. Detected by packer signatures
  (UPX/Themida/VMProtect/ASPack/…) and by entropy, at full confidence.
* **Layer 1 (unpacked):** we *know* an unpacked image exists, but recovering its
  bytes needs emulation of the unpacking stub or a dynamic unpack — so it is
  emitted as a confidence-decayed, explicitly *pending* layer, never fabricated.

Confidence decays per layer (Layer 0 = detection confidence, Layer 1 = ×0.7),
matching the rule that deeper, less-certain layers should weigh less.
"""

from __future__ import annotations

import re

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .common import shannon_entropy

# Packer fingerprints: byte markers that appear in the section table / overlay of
# a packed image. Substring scan keeps this dependency-free (no PE parser needed).
_PACKER_SIGS: list[tuple[str, tuple[bytes, ...]]] = [
    ("UPX", (b"UPX0", b"UPX1", b"UPX!")),
    ("Themida/WinLicense", (b".themida", b"Themida", b"WinLicense")),
    ("VMProtect", (b".vmp0", b".vmp1", b"VMProtect")),
    ("ASPack", (b".aspack", b".adata")),
    ("MPRESS", (b".MPRESS1", b".MPRESS2")),
    ("PECompact", (b"PEC2", b"PECompact2")),
    ("Petite", (b".petite",)),
    ("FSG", (b"FSG!",)),
    ("MEW", (b"MEW",)),
    ("NSPack", (b".nsp0", b".nsp1")),
    ("Enigma", (b".enigma1", b".enigma2")),
    ("ConfuserEx (.NET)", (b"ConfusedByAttribute", b"ConfuserEx")),
]

_ENTROPY_PACKED = 7.2   # max-block entropy above which a region looks packed/encrypted
_BLOCK = 4096

# One alternation regex over every packer signature (with a reverse map back to
# the label) turns ~30 full-file passes into a single scan that stops at the
# first hit.
_SIG_TO_LABEL: dict[bytes, str] = {sig: label for label, sigs in _PACKER_SIGS for sig in sigs}
_PACKER_RE = re.compile(b"|".join(re.escape(sig) for sig in sorted(_SIG_TO_LABEL, key=len, reverse=True)))


def _max_block_entropy(data: bytes) -> float:
    if len(data) <= _BLOCK:
        return shannon_entropy(data)
    return max(shannon_entropy(data[i:i + _BLOCK]) for i in range(0, len(data), _BLOCK))


def _detect_packer(data: bytes) -> tuple[str, float]:
    """Return (packer_label, detection_confidence). Signature match is near-certain;
    a high-entropy body with no signature is a lower-confidence 'unknown packer'."""
    m = _PACKER_RE.search(data)
    if m:
        return _SIG_TO_LABEL[m.group()], 0.95
    if len(data) > _BLOCK and _max_block_entropy(data) >= _ENTROPY_PACKED:
        return "unknown (high-entropy / custom packer)", 0.65
    return "", 0.0


class UnpackAnalyzer(BaseAnalyzer):
    name = "static.unpack"
    handles = {"pe", "dll"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        packer, det_conf = _detect_packer(sample.data)
        if not packer:
            return []  # not packed — stay quiet rather than emit a non-finding
        ent = round(_max_block_entropy(sample.data), 3)

        # Layer 0 — the packed image (full detection confidence). Maps to T1027.
        layer0 = ctx.ev(
            source="static.unpack",
            artifact="module",
            operation="decode",
            subject={"analyzer": self.name},
            object={"layer": 0, "function": packer},
            details={
                "evidence_type": "unpack_layer",
                "wrapper": "packed image",
                "decoded_preview": f"packed/encrypted {packer} image (max-block entropy {ent})",
                "decoded_len": len(sample.data),
                "attack_hint": "T1027",
                "why": f"{packer} packer detected — the on-disk code is packed/obfuscated",
            },
            confidence=det_conf,
            evidence_refs=[ref],
        )

        # Layer 1 — the unpacked image. We know it exists; recovering its bytes
        # needs emulation/dynamic unpack, so it is pending and confidence-decayed.
        # It links back to layer 0 (parent → child) for the layered graph.
        layer1 = ctx.ev(
            source="static.unpack",
            artifact="module",
            operation="decode",
            subject={"analyzer": self.name},
            object={"layer": 1, "function": "unpacked image"},
            details={
                "evidence_type": "unpack_layer",
                "parent_layer": 0,
                "wrapper": "unpacked",
                "status": "requires_emulation",
                "decoded_preview": "<unpacked PE / shellcode — recover by emulating the unpack stub or via a dynamic unpack>",
                "why": "an unpacked layer exists beneath the packer; static analysis sees only the packed "
                       "bytes — emulate the stub or detonate to recover the real code, imports and config",
            },
            confidence=round(det_conf * 0.7, 3),
            evidence_refs=[ref, layer0.id],
        )
        return [layer0, layer1]


def register(registry) -> None:
    registry.register(UnpackAnalyzer())


ANALYZER = UnpackAnalyzer()
