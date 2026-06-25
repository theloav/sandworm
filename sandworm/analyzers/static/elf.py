"""ELF static analyzer (C / Rust / Go).

Parses sections and dynamic symbols, fingerprints the toolchain (Go/Rust/C),
notes high-entropy sections, and flags libc/syscall capabilities tied to common
malware behaviors. Uses pyelftools when present; otherwise falls back to header +
string heuristics so it still emits evidence offline.
"""

from __future__ import annotations

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .common import shannon_entropy

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
        items.append(
            ctx.ev(
                source="static.elf",
                artifact="module",
                operation="read",
                subject={"analyzer": self.name},
                object={"format": "ELF", "name": sample.name},
                details={"toolchain": toolchain, "sections": sections_info[:40], "symbol_count": len(symbols)},
                confidence=0.8,
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


def register(registry) -> None:
    registry.register(ElfAnalyzer())
