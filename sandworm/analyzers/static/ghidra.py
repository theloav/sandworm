"""Optional Ghidra headless decompilation with address/p-code export."""

from __future__ import annotations

import json
import os
import tempfile
from importlib.resources import files
from pathlib import Path

from ...core.evidence import EvidenceLocation
from ...core.sample import Sample
from ..base import Context
from ..external import run_parser


def decompile(sample: Sample, ghidra_home: Path | None = None) -> dict:
    home = ghidra_home or Path(os.environ.get("GHIDRA_HOME", ""))
    executable = home / "support" / "analyzeHeadless"
    if not executable.is_file():
        raise RuntimeError("set GHIDRA_HOME to an installed Ghidra distribution")
    with tempfile.TemporaryDirectory(prefix="sw-ghidra-") as tmp:
        directory = Path(tmp)
        binary = directory / "sample.bin"
        binary.write_bytes(sample.data)
        script = directory / "SandwormExport.java"
        script.write_text(files("sandworm.analyzers.static").joinpath("scripts/SandwormExport.java").read_text())
        result = directory / "decompiled.json"
        run_parser([str(executable.resolve()), str(directory), "project", "-import", str(binary),
                    "-scriptPath", str(directory), "-postScript", script.name, str(result),
                    "-analysisTimeoutPerFile", "240", "-max-cpu", "2", "-deleteProject"], directory / "ghidra.log", timeout=600)
        if not result.is_file() or result.stat().st_size > 32 * 1024**2:
            raise RuntimeError("Ghidra did not produce a bounded export")
        document = json.loads(result.read_text())
        document["target_sha256"] = sample.sha256
        document["scope"] = "up to 256 functions; decompiled C and p-code are analysis approximations"
        return document


def normalize_decompilation(document: dict, ctx: Context):
    base = int(document["image_base"], 16)
    for row in document.get("functions", [])[:256]:
        address = int(row["entry"], 16)
        ranges = []
        for instruction in row.get("instructions", [])[:512]:
            start = int(instruction["address"], 16)
            size = int(instruction.get("size", 0))
            if 0 < size <= 32 and start >= base:
                ranges.append({"start_va": start, "end_va": start + size,
                               "start_rva": start - base, "end_rva": start - base + size})
        location = EvidenceLocation(virtual_address=address, rva=address - base if address >= base else None, function=row["name"])
        yield ctx.ev(source="static.ghidra", artifact="function", operation="decompile",
                     object={"function": row["name"]}, locations=[location], confidence=0.8,
                     details={"completed": row.get("completed", False), "decompiled_c": row.get("c", "")[:32768],
                              "address_ranges": ranges, "pcode": row.get("instructions", [])[:128],
                              "why": "Ghidra decompilation and p-code; static analysis approximation"})
