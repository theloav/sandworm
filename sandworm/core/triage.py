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
FORMAT_JAR = "jar"
FORMAT_APK = "apk"
FORMAT_LNK = "lnk"
FORMAT_PDF = "pdf"
FORMAT_HTA = "hta"
FORMAT_VBS = "vbscript"
FORMAT_GENERIC = "generic"

# Windows Shell Link (.lnk): HeaderSize 0x4C followed by the LNK CLSID.
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # fat/universal
}

# OLE Compound File (legacy .doc/.xls) magic.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _has_pe_signature(data: bytes) -> bool:
    """True iff a valid ``PE\\0\\0`` signature sits at ``e_lfanew``."""
    if len(data) < 0x40:
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    return 0 < e_lfanew <= len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


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


def _looks_like_vbscript(text: str) -> bool:
    indicators = [
        r"\bCreateObject\s*\(", r"\bWScript\.", r"\bDim\b\s+\w+", r"\bSet\b\s+\w+\s*=",
        r"\bEnd\s+(Sub|Function)\b", r"\bExecuteGlobal\b", r"\bChrW?\s*\(",
    ]
    hits = sum(bool(re.search(p, text, re.IGNORECASE)) for p in indicators)
    return hits >= 2


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
        # Verify the PE\0\0 signature at e_lfanew — "MZ" alone also matches
        # DOS-only executables and coincidental text. Still routed to the PE
        # lane either way, but the confidence reflects what was verified.
        if _has_pe_signature(data):
            reasons.append("MZ DOS header + verified PE signature at e_lfanew")
            return TriageResult(FORMAT_PE, 0.99, reasons, supported=True)
        reasons.append("MZ DOS header (no PE signature — DOS-only, truncated, or corrupt)")
        return TriageResult(FORMAT_PE, 0.6, reasons, supported=True)
    if data[:4] == b"\x7fELF":
        reasons.append("\\x7fELF magic")
        return TriageResult(FORMAT_ELF, 0.99, reasons, supported=True)
    if head in _MACHO_MAGICS:
        reasons.append("Mach-O magic")
        return TriageResult(FORMAT_MACHO, 0.95, reasons, supported=False)
    if data[:8] == _OLE_MAGIC:
        reasons.append("OLE compound file (legacy Office)")
        return TriageResult(FORMAT_OFFICE, 0.9, reasons, supported=True)
    if data[:20] == _LNK_MAGIC:
        reasons.append("Windows Shell Link (.lnk) header CLSID")
        return TriageResult(FORMAT_LNK, 0.98, reasons, supported=True)
    if data[:5] == b"%PDF-":
        reasons.append("%PDF- magic")
        return TriageResult(FORMAT_PDF, 0.95, reasons, supported=True)
    if data[:2] == b"PK":
        # OOXML (.docm/.xlsm) is a ZIP. Peek for office markers.
        lower = data[:4096].lower()
        if b"word/" in lower or b"xl/" in lower or b"vbaproject" in lower or b"[content_types]" in lower:
            reasons.append("ZIP container with OOXML markers")
            return TriageResult(FORMAT_OFFICE, 0.75, reasons, supported=True)
        # Name the archive type instead of silently degrading to 'generic'.
        if b"androidmanifest.xml" in lower or b"classes.dex" in lower:
            reasons.append("ZIP container with Android (APK) markers")
            return TriageResult(FORMAT_APK, 0.85, reasons, supported=False)
        if b"meta-inf/" in lower and (b".class" in lower or b"manifest.mf" in lower):
            reasons.append("ZIP container with Java archive (JAR) markers")
            return TriageResult(FORMAT_JAR, 0.8, reasons, supported=False)

    # --- Text formats ---
    try:
        text = data.decode("utf-8", errors="strict")
        is_text = True
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        is_text = sum(c < 9 or (13 < c < 32) for c in data[:1024]) < 32

    nm = (name or "").lower()
    if is_text:
        # HTA before generic HTML/JS: an <hta:application> tag (or .hta) is a
        # Windows script host application, a common phishing initial-access vector.
        if "hta:application" in text.lower() or nm.endswith(".hta"):
            reasons.append("HTML Application (<hta:application> / .hta)")
            return TriageResult(FORMAT_HTA, 0.85, reasons, supported=True)
        if _looks_like_vbscript(text) or nm.endswith((".vbs", ".vbe")):
            reasons.append("VBScript idiom / .vbs")
            return TriageResult(FORMAT_VBS, 0.78, reasons, supported=True)
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
    if fmt in {FORMAT_SCRIPT_PS, FORMAT_SCRIPT_JS, FORMAT_SCRIPT_SH, FORMAT_VBS, FORMAT_HTA}:
        # HTA and VBScript are script-host formats; they share the script lane
        # (plus their own tag) so their embedded code is deobfuscated + sink-scanned.
        return {"script", fmt}
    if fmt == FORMAT_OFFICE:
        return {"office", fmt}
    return {fmt}
