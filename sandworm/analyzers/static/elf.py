"""ELF static analyzer (C / Rust / Go).

Parses sections and dynamic symbols, fingerprints the toolchain (Go/Rust/C),
notes high-entropy sections, and flags libc/syscall capabilities tied to common
malware behaviors. Uses pyelftools when present; otherwise falls back to header +
string heuristics so it still emits evidence offline.
"""

from __future__ import annotations

import struct

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .common import shannon_entropy

# Program-header types / flags we care about.
_PT_LOAD = 1
_PT_GNU_STACK = 0x6474E551
_PF_X = 0x1
_PF_W = 0x2

_SUSPECT_SYMBOLS = {
    "ptrace": ("T1622", "anti-debugging via ptrace", 0.6),
    "fork": ("T1059", "process spawning", 0.3),
    "execve": ("T1059.004", "command execution", 0.5),
    "system": ("T1059.004", "shell command execution", 0.6),
    "socket": ("T1071", "network capability", 0.35),
    "connect": ("T1071", "outbound connection capability", 0.4),
    "inotify_add_watch": ("T1083", "filesystem monitoring", 0.3),
    "setuid": ("T1548", "privilege manipulation", 0.4),
}


def parse_elf_headers(data: bytes) -> dict | None:
    """Dependency-free parse of the ELF header + program headers.

    Returns ``{"bits", "endian", "type", "stripped", "static", "segments":
    [{type, flags}]}`` or ``None`` if the magic/structure is invalid. Mirrors the
    PE header parser so the ELF lane gets the same structural checks (RWX
    segments, executable stack, static+stripped implant profile) with zero deps.
    """
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]   # 1=LE, 2=BE
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    e_type = struct.unpack_from(endian + "H", data, 16)[0]

    try:
        if is64:
            e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 0x36)
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 0x2A)
    except struct.error:
        return None

    segments: list[dict] = []
    has_interp = False
    for i in range(min(e_phnum, 128)):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, off)[0]
        # p_flags sits at a different offset for 32- vs 64-bit program headers.
        p_flags = struct.unpack_from(endian + "I", data, off + (4 if is64 else 24))[0]
        segments.append({"type": p_type, "flags": p_flags})
        if p_type == 3:  # PT_INTERP → dynamically linked
            has_interp = True

    # Stripped ≈ no symbol table. Cheap heuristic without full section parsing:
    # the ".symtab" section name is absent from the string table region.
    stripped = b".symtab" not in data
    return {
        "bits": 64 if is64 else 32,
        "endian": "little" if ei_data == 1 else "big",
        "type": e_type,  # 2=EXEC, 3=DYN(PIE/so)
        "stripped": stripped,
        "static": not has_interp and e_type == 2,
        "segments": segments,
    }


def _toolchain(data: bytes) -> str:
    if b"go.buildid" in data or b"runtime.main" in data or b"Go build ID" in data:
        return "go"
    if b"rustc" in data or b"cargo" in data or b"/rust/" in data:
        return "rust"
    if b"GCC:" in data or b"clang version" in data:
        return "c/c++"
    return "unknown"


class ElfAnalyzer(BaseAnalyzer):
    name = "static.elf"
    handles = {"elf"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []
        data = sample.data
        symbols: list[str] = []
        sections_info: list[dict] = []

        try:  # pragma: no cover - optional dep
            import io

            from elftools.elf.elffile import ELFFile

            elf = ELFFile(io.BytesIO(data))
            for sec in elf.iter_sections():
                sd = sec.data()
                sections_info.append({"name": sec.name, "entropy": round(shannon_entropy(sd), 3), "size": sec.data_size})
            for sec in elf.iter_sections():
                if sec.name in (".dynsym", ".symtab") and hasattr(sec, "iter_symbols"):
                    for sym in sec.iter_symbols():
                        if sym.name:
                            symbols.append(sym.name)
        except Exception:
            for sym in _SUSPECT_SYMBOLS:
                if sym.encode() in data:
                    symbols.append(sym)

        toolchain = _toolchain(data)
        headers = parse_elf_headers(data)
        items.append(
            ctx.ev(
                source="static.elf",
                artifact="module",
                operation="read",
                subject={"analyzer": self.name},
                object={"format": "ELF", "name": sample.name},
                details={
                    "toolchain": toolchain,
                    "sections": sections_info[:40],
                    "symbol_count": len(symbols),
                    "bits": headers["bits"] if headers else None,
                    "stripped": headers["stripped"] if headers else None,
                    "static": headers["static"] if headers else None,
                },
                confidence=0.8,
                evidence_refs=[ref],
            )
        )
        if headers:
            items.extend(self._header_findings(headers, ctx, ref))

        # UPX packs ELF as well as PE. The stub leaves "UPX!" / "UPX0"/"UPX1" in
        # the image; a UPX-packed ELF is high-signal (droppers/implants).
        if any(sig in data for sig in (b"UPX!", b"UPX0", b"UPX1", b"$Info: This file is packed with the UPX")):
            items.append(
                ctx.ev(
                    source="static.elf",
                    artifact="module",
                    operation="decode",
                    subject={"analyzer": self.name},
                    object={"function": "UPX", "layer": 0},
                    details={
                        "evidence_type": "unpack_layer",
                        "attack_hint": "T1027",
                        "why": "UPX-packed ELF — the on-disk code is compressed/obfuscated; "
                               "unpack with `upx -d` or by emulation to recover the real code",
                        "decoded_preview": "packed UPX ELF image",
                    },
                    confidence=0.9,
                    evidence_refs=[ref],
                )
            )

        for sym in set(symbols):
            if sym in _SUSPECT_SYMBOLS:
                tid, why, conf = _SUSPECT_SYMBOLS[sym]
                items.append(
                    ctx.ev(
                        source="static.elf",
                        artifact="api_call",
                        operation="resolve",
                        subject={"analyzer": self.name},
                        object={"symbol": sym},
                        details={"attack_hint": tid, "why": why},
                        confidence=conf,
                        evidence_refs=[ref],
                    )
                )
        return items


    def _header_findings(self, headers: dict, ctx: Context, ref: str) -> list[EvidenceItem]:
        """Structural anomalies from the program headers: RWX / executable-stack
        segments and the static+stripped Linux-implant profile."""
        items: list[EvidenceItem] = []

        for seg in headers["segments"]:
            flags = seg["flags"]
            if seg["type"] == _PT_LOAD and flags & _PF_W and flags & _PF_X:
                items.append(
                    ctx.ev(
                        source="static.elf",
                        artifact="module",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"segment": "PT_LOAD", "flags": "RWX"},
                        details={
                            "attack_hint": "T1027",
                            "why": "writable+executable (RWX) load segment — self-modifying / packed "
                                   "code; standard toolchains emit W^X segments",
                        },
                        confidence=0.65,
                        evidence_refs=[ref],
                    )
                )
            if seg["type"] == _PT_GNU_STACK and flags & _PF_X:
                items.append(
                    ctx.ev(
                        source="static.elf",
                        artifact="module",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"segment": "PT_GNU_STACK", "flags": "executable"},
                        details={
                            "attack_hint": "T1027",
                            "why": "executable stack requested — enables shellcode execution on the "
                                   "stack (rare in benign modern binaries)",
                        },
                        confidence=0.55,
                        evidence_refs=[ref],
                    )
                )

        # A statically-linked AND stripped executable is the classic Linux
        # implant profile: no imports to fingerprint, no symbols to read, drops
        # onto a host with no library dependencies.
        if headers["static"] and headers["stripped"]:
            items.append(
                ctx.ev(
                    source="static.elf",
                    artifact="module",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"anomaly": "static_stripped"},
                    details={
                        "note": "statically linked + symbol-stripped — self-contained, "
                                "analysis-resistant profile common to Linux implants/droppers",
                    },
                    confidence=0.45,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(ElfAnalyzer())
