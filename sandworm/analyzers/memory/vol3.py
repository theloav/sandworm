"""Volatility3 orchestration.

Runs a curated set of vol3 plugins (pslist/psscan/malfind/netscan/cmdline) over a
memory image via subprocess and normalizes the JSON renderer output into
EvidenceItems. This is opt-in: it needs a memory image path passed via
``ctx.extra['memory_image']`` and volatility3 installed. Absent either, it emits a
single 'skipped' note so the pipeline never hard-fails.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

SOURCE = "memory.vol3"

_PLUGINS = {
    "windows.pslist.PsList": ("process", "spawn"),
    "windows.malfind.Malfind": ("process", "inject"),
    "windows.netscan.NetScan": ("network", "connect"),
    "windows.cmdline.CmdLine": ("process", "exec"),
}

# Which vol3 plugin a recorded-report section came from → (artifact, operation,
# optional attack_hint). Lets a recorded memory report drive ATT&CK directly:
# malfind => injected memory (T1055), so memory evidence upgrades the standing of
# an injection technique from inferred → observed.
_PLUGIN_MAP = {
    "windows.pslist.PsList": ("process", "spawn", None),
    "windows.psscan.PsScan": ("process", "spawn", None),
    "windows.malfind.Malfind": ("process", "inject", "T1055"),
    "windows.netscan.NetScan": ("network", "connect", None),
    "windows.cmdline.CmdLine": ("process", "exec", None),
}


def normalize_memory_report(report: list | dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Normalize a *recorded* vol3 report into EvidenceItems (offline replay).

    Reads a JSON file shaped as ``[{"plugin": "...", "rows": [...]}, ...]`` (the
    output an operator captures from a prior memory-forensics run). Like the CAPE
    replay path, this executes nothing — it ingests prior evidence, so it is safe
    to run without the isolation gate.
    """
    sections = report if isinstance(report, list) else report.get("sections", [])
    for section in sections:
        plugin = section.get("plugin", "")
        art, op, hint = _PLUGIN_MAP.get(plugin, ("process", "read", None))
        for row in section.get("rows", [])[:500]:
            details: dict = {"plugin": plugin}
            if hint:
                details["attack_hint"] = hint
                details["why"] = f"{plugin} found a memory region consistent with code injection"
            yield ctx.ev(
                source=SOURCE,
                artifact=art,
                operation=op,
                subject={"analyzer": plugin, "pid": row.get("PID") or row.get("pid")},
                object={k: v for k, v in row.items() if isinstance(v, (str, int, float, bool))},
                details=details,
                confidence=0.8,
                evidence_refs=[ref],
            )


class Vol3Analyzer(BaseAnalyzer):
    name = "memory.vol3"
    handles = {"*"}
    requires_isolation = False  # reads a static image; no detonation

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        image = ctx.extra.get("memory_image")
        vol = shutil.which("vol") or shutil.which("volatility3")
        if not image or not Path(image).exists() or not vol:
            return [
                ctx.ev(
                    source="memory.vol3",
                    artifact="process",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "no memory image or volatility3 not installed"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]
        items: list[EvidenceItem] = []
        for plugin, (art, op) in _PLUGINS.items():  # pragma: no cover - needs vol3 + image
            try:
                proc = subprocess.run(
                    [vol, "-r", "json", "-f", str(image), plugin],
                    capture_output=True,
                    timeout=300,
                    check=False,
                )
                rows = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
            except Exception:
                continue
            for row in rows[:500]:
                items.append(
                    ctx.ev(
                        source="memory.vol3",
                        artifact=art,
                        operation=op,
                        subject={"analyzer": plugin},
                        object=row,
                        details={"plugin": plugin},
                        confidence=0.75,
                        evidence_refs=[ref],
                    )
                )
        return items


def register(registry) -> None:
    registry.register(Vol3Analyzer())
