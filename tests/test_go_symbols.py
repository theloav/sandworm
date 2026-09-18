import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from sandworm.analyzers.static.go_symbols import parse_pclntab, recover_go_functions


def table_fixture():
    data = bytearray(200)
    struct.pack_into("<IBBBB", data, 0, 0xFFFFFFF1, 0, 0, 1, 8)
    struct.pack_into("<8Q", data, 8, 1, 0, 0x1000, 72, 96, 96, 96, 104)
    data[72:82] = b"main.test\0"
    struct.pack_into("<III", data, 104, 0, 16, 16)
    struct.pack_into("<II", data, 120, 0, 0)
    return data


def test_go_bounds_and_declared_ranges():
    text = {"address": 0x1000, "offset": 0x200, "size": 32}
    result = parse_pclntab(bytes(table_fixture()), text)
    assert result["functions"] == [{"name": "main.test", "start_va": 0x1000, "end_va": 0x1010, "file_offset": 0x200}]
    broken = table_fixture()
    struct.pack_into("<I", broken, 124, 0xFFFFFFFF)
    with pytest.raises(ValueError, match="name offset"):
        parse_pclntab(bytes(broken), text)
    broken = table_fixture()
    struct.pack_into("<I", broken, 112, 0xFFFFFF)
    with pytest.raises(ValueError, match="range"):
        parse_pclntab(bytes(broken), text)
    with pytest.raises(ValueError):
        parse_pclntab(bytes(table_fixture()[:90]), text)
    with pytest.raises(ValueError):
        recover_go_functions(b"not an ELF")


@pytest.mark.skipif(shutil.which("go") is None, reason="Go compiler not installed")
def test_names_recovered_from_real_stripped_go_elf(tmp_path):
    binary = tmp_path / "stripped"
    source = Path(__file__).parent / "fixtures/go_names.go"
    env = {**os.environ, "GOPROXY": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), str(source)], env=env, check=True, capture_output=True, timeout=120)
    data = binary.read_bytes()
    assert b".symtab\0" not in data
    report = recover_go_functions(data)
    assert report is not None
    names = {row["name"] for row in report["functions"]}
    assert {"main.main", "main.addNumbers", "runtime.main"} <= names
    assert len(names) > 100
    assert all(row["file_offset"] < len(data) for row in report["functions"])
    # No execution of the compiled program is needed for validation.
