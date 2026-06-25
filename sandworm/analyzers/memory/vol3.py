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
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

_PLUGINS = {
    "windows.pslist.PsList": ("process", "spawn"),
    "windows.malfind.Malfind": ("process", "inject"),
    "windows.netscan.NetScan": ("network", "connect"),
    "windows.cmdline.CmdLine": ("process", "exec"),
}


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
