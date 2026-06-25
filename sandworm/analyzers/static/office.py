"""Office macro analyzer.

Extracts VBA macros with olevba when available, then feeds the extracted code
back through the script analyzer's deobfuscation + sink detection (macros are
just another script lane). Without oletools it falls back to scraping printable
VBA-looking text from the container so the synthetic demo still works offline.
"""

from __future__ import annotations

import re

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .script import ScriptAnalyzer

_VBA_SINKS = {
    r"\bShell\b": ("process", "VBA Shell()", 0.85),
    r"WScript\.Shell|CreateObject\(": ("process", "CreateObject", 0.7),
    r"AutoOpen|Document_Open|Workbook_Open": ("execution", "auto-exec macro", 0.8),
    r"URLDownloadToFile|MSXML2|WinHttp": ("network", "remote download", 0.7),
    r"\.Run\b": ("process", "WScript Run", 0.7),
    r"Environ\(|GetObject\(": ("discovery", "environment probe", 0.4),
}


def _extract_macros_olevba(data: bytes) -> list[str]:  # pragma: no cover - optional dep
    from oletools.olevba import VBA_Parser

    macros: list[str] = []
    vba = VBA_Parser("sample", data=data)
    if vba.detect_vba_macros():
        for _f, _s, _name, code in vba.extract_macros():
            if code:
                macros.append(code)
    vba.close()
    return macros


def _extract_macros_fallback(data: bytes) -> list[str]:
    """Scrape VBA-looking lines from the raw container. Crude but offline-safe."""
    text = data.decode("latin-1", "replace")
    keep = []
    for line in text.splitlines():
        if re.search(r"\b(Sub|Function|End Sub|Shell|CreateObject|Dim|AutoOpen|Document_Open|MsgBox|Open|Print)\b", line):
            keep.append(line.strip("\x00 "))
    return ["\n".join(keep)] if keep else []


class OfficeAnalyzer(BaseAnalyzer):
    name = "static.office"
    handles = {"office"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []
        try:
            macros = _extract_macros_olevba(sample.data)
        except Exception:
            macros = _extract_macros_fallback(sample.data)

        if not macros:
            items.append(
                ctx.ev(
                    source="static.office",
                    artifact="macro",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"name": sample.name},
                    details={"macros_found": 0, "note": "no VBA macros extracted"},
                    confidence=0.3,
                    evidence_refs=[ref],
                )
            )
            return items

        script_analyzer = ScriptAnalyzer()
        for idx, code in enumerate(macros):
            items.append(
                ctx.ev(
                    source="static.office",
                    artifact="macro",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"macro_index": idx},
                    details={"preview": code[:300], "lines": code.count("\n") + 1},
                    confidence=0.7,
                    evidence_refs=[ref, f"macro:{idx}"],
                )
            )
            # VBA-specific sinks
            for pat, (cat, name, conf) in _VBA_SINKS.items():
                if re.search(pat, code, re.IGNORECASE):
                    items.append(
                        ctx.ev(
                            source="static.office",
                            artifact="macro",
                            operation="exec" if cat in {"process", "execution"} else "connect" if cat == "network" else "read",
                            subject={"analyzer": self.name},
                            object={"sink": name, "category": cat},
                            details={"why": f"VBA construct '{name}'", "macro_index": idx},
                            confidence=conf,
                            evidence_refs=[ref, f"macro:{idx}"],
                        )
                    )
            # Feed the macro body through the script lane (treat as shell-ish/PS-ish)
            items.extend(script_analyzer.analyze_code(code, "powershell", sample.sha256, ctx))
        return items


def register(registry) -> None:
    registry.register(OfficeAnalyzer())
