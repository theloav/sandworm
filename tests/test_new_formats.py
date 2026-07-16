"""Tests for LNK, PDF, HTA, VBScript analyzers, triage, and .NET PE detection."""

from __future__ import annotations

import struct

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.lnk import LnkAnalyzer, parse_lnk
from sandworm.analyzers.static.pdf import PdfAnalyzer
from sandworm.analyzers.static.pe import parse_pe_headers
from sandworm.analyzers.static.script import ScriptAnalyzer
from sandworm.core.sample import Sample
from sandworm.core.triage import identify


def _ctx():
    return Context(run_id="t")


# --- triage ---


def test_triage_lnk_pdf_hta_vbs():
    lnk = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000C000000000000046") + b"\x00" * 64
    assert identify(lnk).fmt == "lnk"
    assert identify(b"%PDF-1.7\n...").fmt == "pdf"
    assert identify(b"<html><hta:application id=x/></html>", "x.hta").fmt == "hta"
    vbs = b'Dim x\nSet y = CreateObject("WScript.Shell")\n'
    assert identify(vbs, "x.vbs").fmt == "vbscript"


# --- LNK ---


def _lnk_with_args(args: str) -> bytes:
    flags = 0x20 | 0x80  # HasArguments | IsUnicode
    hdr = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000C000000000000046")
    hdr += struct.pack("<I", flags)
    hdr += b"\x00" * (0x4C - len(hdr))
    return hdr + struct.pack("<H", len(args)) + args.encode("utf-16-le")


def test_lnk_recovers_arguments():
    data = _lnk_with_args("powershell -enc SQBFAFgA")
    parsed = parse_lnk(data)
    assert "powershell" in parsed.get("arguments", "")


def test_lnk_flags_interpreter_execution():
    data = _lnk_with_args("cmd.exe /c calc")
    items = LnkAnalyzer().analyze(Sample.from_bytes("a.lnk", data, format_hint="lnk"), _ctx())
    exec_items = [i for i in items if i.details.get("attack_hint") == "T1059"]
    assert exec_items and exec_items[0].object["interpreter"] == "cmd.exe"


def test_lnk_benign_no_execution_flag():
    data = _lnk_with_args("--open document.txt")
    items = LnkAnalyzer().analyze(Sample.from_bytes("a.lnk", data, format_hint="lnk"), _ctx())
    assert not any(i.details.get("attack_hint") == "T1059" for i in items)


# --- PDF ---


def test_pdf_flags_js_and_autoexec():
    pdf = b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (evil()) >> >>\n"
    items = PdfAnalyzer().analyze(Sample.from_bytes("x.pdf", pdf, format_hint="pdf"), _ctx())
    sinks = {i.object.get("sink") for i in items}
    assert "javascript" in sinks and "auto_action" in sinks
    assert any(i.object.get("capability") == "auto_execute_javascript" for i in items)


def test_pdf_launch_flagged():
    pdf = b"%PDF-1.4\n<< /Launch << /F (cmd.exe) >> >>\n"
    items = PdfAnalyzer().analyze(Sample.from_bytes("x.pdf", pdf, format_hint="pdf"), _ctx())
    assert any(i.object.get("sink") == "launch" for i in items)


def test_pdf_benign_no_action_markers():
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    items = PdfAnalyzer().analyze(Sample.from_bytes("x.pdf", pdf, format_hint="pdf"), _ctx())
    assert not any(i.details.get("attack_hint") for i in items)


# --- VBScript / HTA ---


def test_vbscript_sinks():
    code = 'Set s = CreateObject("WScript.Shell")\ns.Run "powershell -enc AAAA"\n'
    items = ScriptAnalyzer().analyze_code(code, "vbscript", "h", _ctx())
    sinks = {i.object.get("sink") for i in items}
    assert "wscript_shell" in sinks


def test_hta_scans_vbscript_and_js():
    code = '<script language="VBScript">CreateObject("WScript.Shell").Run "calc"</script>' \
           '<script>eval(atob("YWxlcnQoMSk="))</script>'
    items = ScriptAnalyzer().analyze_code(code, "hta", "h", _ctx())
    sinks = {i.object.get("sink") for i in items}
    assert "wscript_shell" in sinks and "eval" in sinks


def test_vbscript_chr_deobfuscation():
    code = "x = Chr(99) & Chr(109) & Chr(100)\n"  # "cmd"
    items = ScriptAnalyzer().analyze_code(code, "vbscript", "h", _ctx())
    decoded = [i for i in items if i.operation == "decode"]
    assert decoded and "cmd" in decoded[0].details["decoded_preview"]


# --- .NET PE ---


def _pe_with_clr(clr: bool) -> bytes:
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    opt_size = 0x60 + 16 * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x0102)
    opt = struct.pack("<H", 0x10B) + b"\x00" * (0x60 - 2)
    clr_dir = struct.pack("<II", 0x2000, 0x48) if clr else struct.pack("<II", 0, 0)
    dirs = b"\x00" * (14 * 8) + clr_dir + b"\x00" * 8
    raw_ptr = e_lfanew + 4 + 20 + opt_size + 40
    section = b".text\x00\x00\x00" + struct.pack("<IIII", 16, 0x1000, 16, raw_ptr) + b"\x00" * 12 + struct.pack("<I", 0x60000020)
    return dos + b"PE\x00\x00" + coff + opt + dirs + section + b"\x90" * 16


def test_dotnet_detected():
    assert parse_pe_headers(_pe_with_clr(True))["dotnet"] is True
    assert parse_pe_headers(_pe_with_clr(False))["dotnet"] is False
