"""Run Volatility against a captured image and emit a sample-bound replay report."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from ...core.sample import Sample
from ..external import run_parser

PLUGINS = {
    "windows": ["windows.pslist.PsList", "windows.psscan.PsScan", "windows.malfind.Malfind", "windows.netscan.NetScan"],
    "linux": ["linux.pslist.PsList", "linux.psscan.PsScan", "linux.malfind.Malfind"],
}


def flatten(rows: list) -> list[dict]:
    result: list[dict] = []
    pending = list(rows)
    while pending and len(result) < 50000:
        row = pending.pop()
        if not isinstance(row, dict):
            continue
        children = row.get("__children", [])
        if isinstance(children, list):
            pending.extend(children)
        result.append({k: v for k, v in row.items() if k != "__children"})
    return result


def collect_memory(sample: Sample, image: Path, *, platform: str = "windows", symbols: Path | None = None) -> dict:
    if platform not in PLUGINS or not image.is_file():
        raise ValueError("valid platform and memory image are required")
    executable = shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility3")
    if not executable:
        raise RuntimeError("Volatility CLI unavailable; install the memory extra")
    sections, errors = [], []
    with tempfile.TemporaryDirectory(prefix="sw-vol-") as tmp:
        for i, plugin in enumerate(PLUGINS[platform]):
            log = Path(tmp) / f"plugin-{i}.json"
            command = [executable, "--offline", "-q", "-r", "json", "-f", str(image.resolve())]
            if symbols:
                command += ["-s", str(symbols.resolve())]
            try:
                run_parser([*command, plugin], log)
                raw = log.read_text()
                # Volatility may prepend its banner; require a JSON array after it.
                start = raw.find("[")
                rows = json.loads(raw[start:]) if start >= 0 else []
                sections.append({"plugin": plugin, "rows": flatten(rows)})
            except (RuntimeError, ValueError) as exc:
                errors.append({"plugin": plugin, "error": str(exc)})
    if not sections:
        raise RuntimeError("no memory plugins completed; install matching offline symbols and inspect the image format")
    return {"target_sha256": sample.sha256, "platform": platform, "sections": sections,
            "errors": errors, "provenance": "operator-associated captured memory image"}
