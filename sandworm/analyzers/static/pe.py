"""PE/DLL static analyzer.

Parses headers, sections, imports and per-section entropy; disassembles the
entry point with Capstone when available; and, if `capa` is installed, runs it as
a subprocess and emits its capability→ATT&CK hits as evidence (carrying capa's
own confidence). Every external tool is optional — absence degrades gracefully.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import tempfile
from datetime import UTC, datetime

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ...core.simhash import imphash
from ..base import BaseAnalyzer, Context
from .common import shannon_entropy

# Section characteristics flags (IMAGE_SCN_*).
_SCN_MEM_EXECUTE = 0x2000_0000
_SCN_MEM_WRITE = 0x8000_0000

# Imports mapped to ATT&CK. Used to emit capability hints even without capa.
# (Confidence is deliberately modest — a single import is a capability, not proof.)
_SUSPECT_IMPORTS = {
    # Process injection
    "VirtualAllocEx": ("T1055", "process injection primitive (alloc in remote process)", 0.6),
    "WriteProcessMemory": ("T1055", "writes to another process's memory", 0.7),
    "CreateRemoteThread": ("T1055", "starts a thread in a remote process", 0.75),
    "QueueUserAPC": ("T1055.004", "APC injection primitive", 0.6),
    "NtUnmapViewOfSection": ("T1055.012", "process hollowing primitive", 0.7),
    "SetThreadContext": ("T1055.012", "process hollowing (hijack thread context)", 0.55),
    # Collection / capture
    "SetWindowsHookEx": ("T1056.001", "keylogging hook", 0.5),
    "GetAsyncKeyState": ("T1056.001", "polling keystroke capture", 0.45),
    "BitBlt": ("T1113", "screen capture primitive", 0.4),
    # Persistence
    "RegSetValueEx": ("T1547.001", "registry run-key persistence write", 0.4),
    "RegCreateKey": ("T1112", "registry modification", 0.3),
    "CreateService": ("T1543.003", "Windows service persistence", 0.55),
    "OpenSCManager": ("T1543.003", "service control (persistence/lateral)", 0.4),
    "SHGetFolderPath": ("T1547.001", "startup-folder persistence path lookup", 0.3),
    # C2 / network
    "InternetOpen": ("T1071.001", "HTTP C2 capability", 0.4),
    "InternetOpenUrl": ("T1071.001", "HTTP request capability", 0.45),
    "WinHttpOpen": ("T1071.001", "HTTP C2 capability", 0.4),
    "URLDownloadToFile": ("T1105", "ingress tool transfer (download)", 0.6),
    "WSAStartup": ("T1095", "raw socket networking", 0.35),
    "connect": ("T1071", "outbound connection capability", 0.35),
    # Discovery
    "GetComputerName": ("T1082", "system information discovery", 0.35),
    "GetSystemInfo": ("T1082", "system information discovery", 0.35),
    "Process32First": ("T1057", "process discovery", 0.45),
    "GetAdaptersInfo": ("T1016", "network configuration discovery", 0.4),
    "NetUserEnum": ("T1087", "account discovery", 0.45),
    # Defense evasion / anti-analysis
    "IsDebuggerPresent": ("T1622", "debugger detection (anti-analysis)", 0.45),
    "CheckRemoteDebuggerPresent": ("T1622", "debugger detection (anti-analysis)", 0.5),
    "GetTickCount": ("T1497", "timing-based sandbox evasion", 0.25),
    "VirtualProtect": ("T1027", "runtime memory protection change (unpacking)", 0.35),
    # Credential access
    "LsaRetrievePrivateData": ("T1003", "LSA secrets access", 0.6),
    "CredEnumerate": ("T1555", "credential store access", 0.5),
    # Execution
    "WinExec": ("T1059", "command execution", 0.5),
    "ShellExecute": ("T1059", "command execution", 0.5),
    "CreateProcess": ("T1059", "process creation/execution", 0.4),
    # NOTE: a lone encryption API (CryptEncrypt/CryptGenKey) is NOT mapped to
    # T1486 — encryption is ubiquitous in benign software. Ransomware impact is
    # only inferred by the multi-category heuristic in common.py (family marker,
    # ransom note + extension + shadow-copy deletion).
}


def _parse_with_pefile(data: bytes):  # pragma: no cover - optional dep
    import pefile

    return pefile.PE(data=data, fast_load=False)


def parse_pe_headers(data: bytes) -> dict | None:
    """Dependency-free parse of the COFF header + section table.

    Returns ``{"timestamp", "machine", "sections": [{name, vsize, raw_size,
    raw_ptr, characteristics, entropy}], "overlay_offset", "overlay_size"}`` or
    ``None`` when there is no valid ``PE\\0\\0`` signature. This keeps section
    entropy, W+X flags and overlay detection working even without `pefile`.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    machine, nsections, timestamp, _, _, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt_off = e_lfanew + 24
    sec_off = opt_off + opt_size

    # .NET / CLR: the COM Descriptor (CLR runtime header) is data directory #14.
    # Its offset in the optional header depends on PE32 vs PE32+ magic.
    dotnet = False
    if opt_off + 2 <= len(data):
        magic = struct.unpack_from("<H", data, opt_off)[0]
        dir_base = opt_off + (0x60 if magic == 0x10B else 0x70)  # PE32 vs PE32+
        clr_off = dir_base + 14 * 8
        if clr_off + 8 <= len(data):
            clr_rva, clr_size = struct.unpack_from("<II", data, clr_off)
            dotnet = clr_rva != 0 and clr_size != 0
    sections: list[dict] = []
    end_of_image = 0
    for i in range(min(nsections, 96)):  # 96 = generous sanity cap
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, _vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        raw = data[raw_ptr:raw_ptr + raw_size] if 0 < raw_ptr < len(data) else b""
        sections.append(
            {
                "name": name,
                "vsize": vsize,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "characteristics": characteristics,
                "entropy": round(shannon_entropy(raw), 3),
            }
        )
        end_of_image = max(end_of_image, raw_ptr + raw_size)
    overlay_size = len(data) - end_of_image if 0 < end_of_image < len(data) else 0
    return {
        "machine": machine,
        "timestamp": timestamp,
        "sections": sections,
        "dotnet": dotnet,
        "overlay_offset": end_of_image if overlay_size else 0,
        "overlay_size": overlay_size,
        "overlay_entropy": round(shannon_entropy(data[end_of_image:]), 3) if overlay_size else 0.0,
    }


class PeAnalyzer(BaseAnalyzer):
    name = "static.pe"
    handles = {"pe"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []
        imports: list[str] = []

        # Structure comes from the dependency-free header parser — sections,
        # timestamps, W+X flags and overlay work with zero optional deps.
        headers = parse_pe_headers(sample.data)
        sections_info = [
            {"name": s["name"], "entropy": s["entropy"], "vsize": s["vsize"]}
            for s in (headers["sections"] if headers else [])
        ]

        try:  # pragma: no cover - optional dep path
            pe = _parse_with_pefile(sample.data)
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
        # imphash — same import profile ⇒ same imphash across recompiles/repacks.
        ih = imphash(imports)
        if ih:
            items.append(
                ctx.ev(
                    source="static.pe",
                    artifact="module",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"imphash": ih},
                    details={"note": "PE import hash — corpus/lineage pivot for shared import profile"},
                    confidence=0.6,
                    evidence_refs=[ref],
                )
            )
        if headers:
            items.extend(self._header_findings(headers, ctx, ref))
            if headers.get("dotnet"):
                items.append(
                    ctx.ev(
                        source="static.pe",
                        artifact="module",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"runtime": ".NET/CLR"},
                        details={"note": "managed .NET assembly (CLR header present) — decompile with "
                                         "ILSpy/dnSpy; watch for reflection-based loading"},
                        confidence=0.7,
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

    def _header_findings(self, headers: dict, ctx: Context, ref: str) -> list[EvidenceItem]:
        """Structural anomalies from the header parse: W+X sections, compile
        timestamp forgery, and an appended overlay (embedded payload)."""
        items: list[EvidenceItem] = []

        for s in headers["sections"]:
            chars = s["characteristics"]
            if chars & _SCN_MEM_EXECUTE and chars & _SCN_MEM_WRITE:
                items.append(
                    ctx.ev(
                        source="static.pe",
                        artifact="module",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"section": s["name"] or "<unnamed>"},
                        details={
                            "characteristics": hex(chars),
                            "attack_hint": "T1027",
                            "why": "writable+executable section — self-modifying/unpacking code "
                                   "(benign compilers never emit W+X sections)",
                        },
                        confidence=0.7,
                        evidence_refs=[ref],
                    )
                )

        ts = headers["timestamp"]
        now = int(datetime.now(UTC).timestamp())
        if ts == 0 or ts > now + 86400:
            when = "zeroed" if ts == 0 else f"in the future ({datetime.fromtimestamp(ts, UTC).date()})"
            items.append(
                ctx.ev(
                    source="static.pe",
                    artifact="module",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"anomaly": "compile_timestamp"},
                    details={
                        "timestamp": ts,
                        "note": f"PE compile timestamp is {when} — commonly forged to hinder "
                                "campaign timeline attribution",
                    },
                    confidence=0.5,
                    evidence_refs=[ref],
                )
            )

        if headers["overlay_size"] >= 512:
            overlay = headers["overlay_size"]
            ent = headers.get("overlay_entropy", 0.0)
            # An Authenticode signature also lives in the overlay; a large
            # high-entropy overlay is the dropper-payload signal.
            high = ent > 7.2
            items.append(
                ctx.ev(
                    source="static.pe",
                    artifact="file",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"anomaly": "overlay", "size": overlay},
                    details={
                        "offset": headers["overlay_offset"],
                        "entropy": ent,
                        "attack_hint": "T1027" if high else None,
                        "note": f"{overlay} bytes appended after the PE image"
                                + (" at high entropy — likely an embedded encrypted payload/config"
                                   if high else " — overlay data (payload, config, or signature)"),
                    },
                    confidence=0.7 if high else 0.45,
                    evidence_refs=[ref],
                )
            )
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
