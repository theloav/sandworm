"""Encoded-string sweep (FLOSS-lite) for binaries.

The PHP lane already peels ``eval(base64(...))`` chains; this brings the same idea
to compiled samples. Malware routinely hides its C2 URLs, dropped-file paths and
ransom notes as **base64**, **hex**, or **single-byte XOR** blobs so a plain
``strings`` sweep sees nothing. This analyzer:

1. finds encoded regions (base64 / hex bodies, and XOR-obfuscated text located by
   brute-forcing a single-byte key against known plaintext markers),
2. decodes them, and
3. feeds the *decoded* bytes back through IOC extraction and the ransomware
   heuristics.

Each recovered layer is emitted as ``operation="decode"`` evidence (→ T1027 /
T1140) with a parent link, and any indicator found *inside* a decoded layer is
higher-signal than the same string in cleartext — an attacker went to the trouble
of hiding it — so it carries a confidence bump and a ``decoded_from`` marker.

Everything is static and bounded (blob count and decode size are capped) so a
20 MB sample can never blow up the pass.
"""

from __future__ import annotations

import base64
import binascii
import re

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .common import extract_all_strings, extract_iocs_classified, is_ransomware, ransomware_scan

_HANDLES = {"pe", "dll", "elf", "macho", "generic", "office"}

# base64 body: at least 24 chars so we skip short accidental matches; optional
# padding. Scanned over extracted strings (base64 is ASCII), never raw binary.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
# hex body: even length, >=32 nibbles (16 bytes).
_HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){16,}")

# Known-plaintext markers used to recover a single-byte XOR key. If any of these
# appears in the file XORed with a constant key, we've found the key and can
# decode the surrounding region. High-signal, low-cost (255 short searches).
_XOR_MARKERS = (b"http://", b"https://", b"\\Microsoft\\", b"cmd.exe", b"powershell", b".onion")

_MAX_BLOBS = 40          # cap decode attempts per kind
_MIN_DECODED = 8         # ignore trivially short decodes
_MAX_DECODED = 1 << 16   # don't carry more than 64 KB of any one decoded layer


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 0x20 <= c < 0x7F or c in (9, 10, 13))
    return printable / len(b)


def _looks_meaningful(decoded: bytes) -> bool:
    """A decode is worth surfacing if it is mostly text, or carries a marker that
    static analysis cares about (URL, path, PE magic, known API)."""
    if len(decoded) < _MIN_DECODED:
        return False
    low = decoded.lower()
    if any(m in low for m in (b"http://", b"https://", b"\\", b"/", b".exe", b".dll", b"cmd", b"powershell", b"mz")):
        return True
    return _printable_ratio(decoded) > 0.85


def _b64_candidates(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for m in _B64_RE.finditer(text):
        blob = m.group()
        if len(blob) % 4:
            blob = blob[: len(blob) - (len(blob) % 4)]
        if len(blob) < 24:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _looks_meaningful(decoded):
            out.append((blob[:48], decoded[:_MAX_DECODED]))
        if len(out) >= _MAX_BLOBS:
            break
    return out


def _hex_candidates(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for m in _HEX_RE.finditer(text):
        blob = m.group()
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            decoded = bytes.fromhex(blob)
        except ValueError:
            continue
        if _looks_meaningful(decoded):
            out.append((blob[:48], decoded[:_MAX_DECODED]))
        if len(out) >= _MAX_BLOBS:
            break
    return out


def _xor_candidates(data: bytes) -> list[tuple[int, bytes]]:
    """Recover single-byte-XOR-obfuscated text by locating a known marker under a
    constant key, then decoding the region around it."""
    out: list[tuple[int, bytes]] = []
    seen_keys: set[int] = set()
    for key in range(1, 256):
        for marker in _XOR_MARKERS:
            enc = bytes(b ^ key for b in marker)
            idx = data.find(enc)
            if idx == -1:
                continue
            if key in seen_keys:
                break
            seen_keys.add(key)
            # Decode a window around the hit and trim to the printable run.
            start = max(0, idx - 64)
            window = bytes(b ^ key for b in data[start:idx + 512])
            printable = re.findall(rb"[\x20-\x7e]{6,}", window)
            if printable:
                out.append((key, b" ".join(printable)[:_MAX_DECODED]))
            break
        if len(out) >= _MAX_BLOBS:
            break
    return out


class DecodeAnalyzer(BaseAnalyzer):
    name = "static.decode"
    handles = _HANDLES
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        data = sample.data
        text = "\n".join(extract_all_strings(data))
        items: list[EvidenceItem] = []

        layers: list[tuple[str, str, bytes]] = []
        for blob, decoded in _b64_candidates(text):
            layers.append(("base64", blob, decoded))
        for blob, decoded in _hex_candidates(text):
            layers.append(("hex", blob, decoded))
        for key, decoded in _xor_candidates(data):
            layers.append((f"xor:0x{key:02x}", f"key=0x{key:02x}", decoded))

        for encoding, blob, decoded in layers:
            preview = decoded.decode("latin-1", "replace")[:200]
            layer = ctx.ev(
                source="static.decode",
                artifact="string",
                operation="decode",
                subject={"analyzer": self.name},
                object={"function": encoding, "wrapper": blob},
                details={
                    "evidence_type": "decoded_layer",
                    "encoding": encoding,
                    "decoded_len": len(decoded),
                    "decoded_preview": preview,
                    "attack_hint": "T1140",
                    "why": f"recovered a {encoding}-encoded string the sample tried to hide",
                },
                confidence=0.75,
                evidence_refs=[ref],
            )
            items.append(layer)
            items.extend(self._indicators_from_decoded(decoded, ctx, ref, layer.id, encoding))

        return items

    def _indicators_from_decoded(
        self, decoded: bytes, ctx: Context, ref: str, parent_id: str, encoding: str
    ) -> list[EvidenceItem]:
        """Re-run IOC + ransomware heuristics over a decoded layer. Indicators
        hidden behind encoding are higher-signal than cleartext ones."""
        items: list[EvidenceItem] = []
        decoded_text = decoded.decode("latin-1", "replace")

        for kind, val, conf, fp, category in extract_iocs_classified(decoded_text):
            if category != "ioc":
                continue
            items.append(
                ctx.ev(
                    source="static.decode",
                    artifact="network" if kind in {"url", "domain", "ipv4"} else "string",
                    operation="resolve",
                    subject={"analyzer": self.name},
                    object={"kind": kind, "value": val},
                    details={
                        "ioc": True,
                        "false_positive_risk": fp,
                        "decoded_from": encoding,
                        "why": f"indicator recovered from a {encoding}-encoded layer (deliberately hidden)",
                    },
                    # Bump: a hidden IOC is stronger evidence than a plaintext one.
                    confidence=round(min(0.95, conf + 0.2), 3),
                    evidence_refs=[ref, parent_id],
                )
            )

        _, cats = ransomware_scan(decoded)
        if is_ransomware(cats):
            cat_names = sorted(c for c in cats if cats[c])
            items.append(
                ctx.ev(
                    source="static.decode",
                    artifact="file",
                    operation="write",
                    subject={"analyzer": self.name},
                    object={"capability": "ransomware", "indicators": [h for v in cats.values() for h in v][:8]},
                    details={
                        "decoded_from": encoding,
                        "categories": cat_names,
                        "why": f"ransomware indicators recovered from a {encoding}-encoded layer: "
                               f"{', '.join(cat_names)}",
                    },
                    confidence=0.85,
                    evidence_refs=[ref, parent_id],
                )
            )
        return items


def register(registry) -> None:
    registry.register(DecodeAnalyzer())


ANALYZER = DecodeAnalyzer()
