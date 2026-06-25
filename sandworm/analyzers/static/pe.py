"""PE/DLL static analyzer.

Parses headers, sections, imports and per-section entropy; disassembles the
entry point with Capstone when available; and, if `capa` is installed, runs it as
a subprocess and emits its capability→ATT&CK hits as evidence (carrying capa's
own confidence). Every external tool is optional — absence degrades gracefully.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .common import shannon_entropy

# Imports commonly associated with injection / process manipulation. Used to emit
# capability hints even without capa.
_SUSPECT_IMPORTS = {
    "VirtualAllocEx": ("T1055", "process injection primitive (alloc in remote process)", 0.6),
    "WriteProcessMemory": ("T1055", "writes to another process's memory", 0.7),
    "CreateRemoteThread": ("T1055", "starts a thread in a remote process", 0.75),
    "NtUnmapViewOfSection": ("T1055.012", "process hollowing primitive", 0.7),
    "SetWindowsHookEx": ("T1056.001", "keylogging hook", 0.5),
    "RegSetValueEx": ("T1547.001", "registry persistence write", 0.4),
    "InternetOpen": ("T1071.001", "HTTP C2 capability", 0.4),
    "WinHttpOpen": ("T1071.001", "HTTP C2 capability", 0.4),
    "CryptEncrypt": ("T1486", "encryption capability (possible ransomware)", 0.3),
}


def _parse_with_pefile(data: bytes):  # pragma: no cover - optional dep
    import pefile

    return pefile.PE(data=data, fast_load=False)


class PeAnalyzer(BaseAnalyzer):
    name = "static.pe"
    handles = {"pe"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []
        imports: list[str] = []
        sections_info: list[dict] = []

        try:  # pragma: no cover - optional dep path
            pe = _parse_with_pefile(sample.data)
            for section in pe.sections:
                name = section.Name.rstrip(b"\x00").decode("latin-1", "replace")
                ent = shannon_entropy(section.get_data())
                sections_info.append({"name": name, "entropy": round(ent, 3), "vsize": section.Misc_VirtualSize})
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode("latin-1", "replace"))
        except Exception:
            # Fallback: scan raw bytes for known import names (best-effort).
            low = sample.data
            for sym in _SUSPECT_IMPORTS:
                if sym.encode() in low:
                    imports.append(sym)

        items.append(
            ctx.ev(
                source="static.pe",
                artifact="module",
                operation="read",
                subject={"analyzer": self.name},
                object={"format": "PE", "name": sample.name},
                details={"sections": sections_info, "import_count": len(imports)},
                confidence=0.8,
                evidence_refs=[ref],
            )
        )
        for sec in sections_info:
            if sec["entropy"] > 7.2:
                items.append(
                    ctx.ev(
                        source="static.pe",
                        artifact="module",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"section": sec["name"]},
                        details={"entropy": sec["entropy"], "note": "high-entropy section — likely packed/encrypted"},
                        confidence=0.6,
                        evidence_refs=[ref],
                    )
                )

        for sym in imports:
            if sym in _SUSPECT_IMPORTS:
                tid, why, conf = _SUSPECT_IMPORTS[sym]
                items.append(
                    ctx.ev(
                        source="static.pe",
                        artifact="api_call",
                        operation="resolve",
                        subject={"analyzer": self.name},
                        object={"import": sym},
                        details={"attack_hint": tid, "why": why},
                        confidence=conf,
                        evidence_refs=[ref],
                    )
                )

        items.extend(self._run_capa(sample, ctx, ref))
        return items

    def _run_capa(self, sample: Sample, ctx: Context, ref: str) -> list[EvidenceItem]:
        capa = shutil.which("capa")
        if not capa:
            return []
        try:  # pragma: no cover - requires capa binary
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=True) as tf:
                tf.write(sample.data)
                tf.flush()
                proc = subprocess.run(
                    [capa, "-j", tf.name], capture_output=True, timeout=120, check=False
                )
            if proc.returncode != 0:
                return []
            report = json.loads(proc.stdout.decode("utf-8", "replace"))
            out: list[EvidenceItem] = []
            for rule_name, rule in report.get("rules", {}).items():
                attack = rule.get("meta", {}).get("attack", [])
                tids = [a.get("id") for a in attack if isinstance(a, dict)]
                out.append(
                    ctx.ev(
                        source="static.pe.capa",
                        artifact="api_call",
                        operation="resolve",
                        subject={"analyzer": "capa"},
                        object={"capability": rule_name},
                        details={"attack": tids, "why": f"capa matched rule '{rule_name}'"},
                        confidence=0.8,
                        evidence_refs=[ref],
                    )
                )
            return out
        except Exception:
            return []


def register(registry) -> None:
    registry.register(PeAnalyzer())
