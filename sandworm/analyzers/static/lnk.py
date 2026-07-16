"""Windows Shell Link (.lnk) static analyzer.

Malicious ``.lnk`` files are a top phishing initial-access vector: the icon looks
like a document, but the link's command-line arguments launch
``powershell``/``cmd``/``mshta`` with an encoded payload. This analyzer parses the
LNK structure enough to recover the target path and — the high-signal part — the
**command-line arguments**, then flags interpreter abuse. Dependency-free: the
LNK binary format is parsed directly.

Reference: MS-SHLLINK. We read the fixed header flags, skip the optional
structures (LinkTargetIDList, LinkInfo), and pull the UTF-16 StringData blocks
(NAME/RELATIVE_PATH/…/COMMAND_LINE_ARGUMENTS) that carry the interesting text.
"""

from __future__ import annotations

import struct

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

# HasLinkTargetIDList, HasLinkInfo, HasName, HasRelativePath, HasWorkingDir,
# HasArguments, HasIconLocation — the StringData blocks appear in this bit order.
_F_TARGET_IDLIST = 0x01
_F_LINKINFO = 0x02
_STRING_FLAGS = [
    (0x04, "name"),
    (0x08, "relative_path"),
    (0x10, "working_dir"),
    (0x20, "arguments"),
    (0x40, "icon_location"),
]
_UNICODE = 0x80  # IsUnicode

_INTERP_MARKERS = ("powershell", "cmd.exe", "cmd /", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil")


def parse_lnk(data: bytes) -> dict:
    """Return ``{"flags", "arguments", "relative_path", "working_dir", ...}``.
    Best-effort: any block we cannot parse cleanly is simply omitted."""
    out: dict[str, str] = {}
    if len(data) < 0x4C:
        return out
    flags = struct.unpack_from("<I", data, 0x14)[0]
    out["flags"] = str(flags)
    is_unicode = bool(flags & _UNICODE)
    off = 0x4C  # end of the fixed header

    # Skip LinkTargetIDList (a size-prefixed block).
    if flags & _F_TARGET_IDLIST:
        if off + 2 > len(data):
            return out
        idlist_size = struct.unpack_from("<H", data, off)[0]
        off += 2 + idlist_size

    # Skip LinkInfo (a size-prefixed block).
    if flags & _F_LINKINFO:
        if off + 4 > len(data):
            return out
        linkinfo_size = struct.unpack_from("<I", data, off)[0]
        off += linkinfo_size if linkinfo_size else 4

    # StringData: each present block is CountCharacters (u16) + string.
    for bit, key in _STRING_FLAGS:
        if not flags & bit:
            continue
        if off + 2 > len(data):
            break
        count = struct.unpack_from("<H", data, off)[0]
        off += 2
        nbytes = count * 2 if is_unicode else count
        raw = data[off:off + nbytes]
        off += nbytes
        try:
            out[key] = raw.decode("utf-16-le" if is_unicode else "latin-1", "replace")
        except Exception:
            pass
    return out


class LnkAnalyzer(BaseAnalyzer):
    name = "static.lnk"
    handles = {"lnk"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        parsed = parse_lnk(sample.data)
        items: list[EvidenceItem] = []

        args = parsed.get("arguments", "")
        target = parsed.get("relative_path") or parsed.get("working_dir") or ""
        items.append(
            ctx.ev(
                source="static.lnk",
                artifact="file",
                operation="read",
                subject={"analyzer": self.name},
                object={"format": "LNK", "name": sample.name},
                details={
                    "target": target[:200],
                    "arguments": args[:400],
                    "note": "Windows shortcut — arguments are the payload surface",
                },
                confidence=0.8,
                evidence_refs=[ref],
            )
        )

        low = (args + " " + target).lower()
        interp = next((m for m in _INTERP_MARKERS if m in low), None)
        if interp:
            items.append(
                ctx.ev(
                    source="static.lnk",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"sink": "shell_run", "interpreter": interp, "command": args[:400]},
                    details={
                        "attack_hint": "T1059",
                        "why": f"shortcut launches an interpreter ({interp}) with arguments — "
                               "classic malicious-LNK phishing execution",
                    },
                    confidence=0.85,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(LnkAnalyzer())


ANALYZER = LnkAnalyzer()
