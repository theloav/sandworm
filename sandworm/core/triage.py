"""THE FORMAT ROUTER — detect sample type and dispatch analyzers.

Type detection uses magic bytes / structure, NOT extension alone (extensions lie
on malware). The router returns the *set* of analyzers to run; it never executes
anything itself. Unknown types still get the common analyzer (strings / entropy /
YARA / IOCs) so every sample yields some evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Canonical format tags used across triage + analyzers.
FORMAT_PE = "pe"
FORMAT_ELF = "elf"
FORMAT_MACHO = "macho"
FORMAT_PHP = "php"
FORMAT_SCRIPT_PS = "powershell"
FORMAT_SCRIPT_JS = "javascript"
FORMAT_SCRIPT_SH = "shell"
FORMAT_OFFICE = "office"
FORMAT_GENERIC = "generic"

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # fat/universal
}

# OLE Compound File (legacy .doc/.xls) magic.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


@dataclass
class TriageResult:
    fmt: str
    confidence: float
    reasons: list[str]
    supported: bool  # False -> "not yet supported" notice (e.g. Mach-O)


def _looks_like_php(text: str) -> bool:
    return "<?php" in text or bool(re.search(r"<\?(?!xml)", text)) and "php" in text.lower()


def _looks_like_powershell(text: str) -> bool:
    indicators = [
        r"\$[A-Za-z_]\w*\s*=",  # variable assignment
        r"\b(Invoke-Expression|IEX|Invoke-WebRequest|Get-\w+|Set-\w+|New-Object)\b",
        r"-[Ee]nc(odedCommand)?\b",
        r"\[System\.",
    ]
    return any(re.search(p, text) for p in indicators)


def _looks_like_js(text: str) -> bool:
    indicators = [r"\bfunction\b", r"=>", r"\bvar\b|\blet\b|\bconst\b", r"document\.", r"eval\(", r"unescape\("]
    hits = sum(bool(re.search(p, text)) for p in indicators)
    return hits >= 2


def _looks_like_shell(text: str) -> bool:
    if text.startswith("#!") and ("sh" in text.splitlines()[0]):
        return True
    indicators = [r"\bcurl\b", r"\bwget\b", r"\|\s*(bash|sh)\b", r"\bchmod\b", r"\bexport\b", r"\$\(", r"`"]
    hits = sum(bool(re.search(p, text)) for p in indicators)
    return hits >= 2


def identify(data: bytes, name: str | None = None) -> TriageResult:
    """Identify a sample's format from its bytes (and name as a weak tiebreaker)."""
    head = data[:4]
    reasons: list[str] = []

    # --- Binary magics first (most reliable) ---
    if data[:2] == b"MZ":
        # Could still be a DOS stub; PE if it has a PE header pointer.
        reasons.append("MZ DOS header")
        return TriageResult(FORMAT_PE, 0.98, reasons, supported=True)
    if data[:4] == b"\x7fELF":
        reasons.append("\\x7fELF magic")
        return TriageResult(FORMAT_ELF, 0.99, reasons, supported=True)
    if head in _MACHO_MAGICS:
        reasons.append("Mach-O magic")
        return TriageResult(FORMAT_MACHO, 0.95, reasons, supported=False)
    if data[:8] == _OLE_MAGIC:
        reasons.append("OLE compound file (legacy Office)")
        return TriageResult(FORMAT_OFFICE, 0.9, reasons, supported=True)
    if data[:2] == b"PK":
        # OOXML (.docm/.xlsm) is a ZIP. Peek for office markers.
        lower = data[:4096].lower()
        if b"word/" in lower or b"xl/" in lower or b"vbaproject" in lower or b"[content_types]" in lower:
            reasons.append("ZIP container with OOXML markers")
            return TriageResult(FORMAT_OFFICE, 0.75, reasons, supported=True)

    # --- Text formats ---
    try:
        text = data.decode("utf-8", errors="strict")
        is_text = True
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        is_text = sum(c < 9 or (13 < c < 32) for c in data[:1024]) < 32

    nm = (name or "").lower()
    if is_text:
        if _looks_like_php(text) or nm.endswith(".php"):
            reasons.append("PHP open tag / .php")
            return TriageResult(FORMAT_PHP, 0.9, reasons, supported=True)
        if _looks_like_powershell(text) or nm.endswith((".ps1", ".psm1")):
            reasons.append("PowerShell cmdlet/idiom")
            return TriageResult(FORMAT_SCRIPT_PS, 0.8, reasons, supported=True)
        if _looks_like_shell(text) or nm.endswith(".sh"):
            reasons.append("shell shebang/idiom")
            return TriageResult(FORMAT_SCRIPT_SH, 0.78, reasons, supported=True)
        if _looks_like_js(text) or nm.endswith((".js", ".jse")):
            reasons.append("JavaScript idiom")
            return TriageResult(FORMAT_SCRIPT_JS, 0.75, reasons, supported=True)

    reasons.append("no known structure matched")
    return TriageResult(FORMAT_GENERIC, 0.3, reasons, supported=True)


# Map each format to the static format-tags an analyzer might claim. Script
# sub-formats all share the "script" analyzer tag plus their specific tag.
def analyzer_tags_for(fmt: str) -> set[str]:
    if fmt in {FORMAT_SCRIPT_PS, FORMAT_SCRIPT_JS, FORMAT_SCRIPT_SH}:
        return {"script", fmt}
    if fmt == FORMAT_OFFICE:
        return {"office", fmt}
    return {fmt}
