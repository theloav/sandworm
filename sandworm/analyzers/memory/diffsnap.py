"""Differential snapshot diffing (process diff only, for v1).

Given a baseline process list and a post-detonation process list (each a list of
{pid, name, ppid}), emit EvidenceItems for processes that appeared after
detonation — the cheap, high-signal "what's new" view. Snapshots are passed via
``ctx.extra['snap_baseline']`` / ``ctx.extra['snap_post']``.
"""

from __future__ import annotations

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context


def diff_processes(baseline: list[dict], post: list[dict]) -> list[dict]:
    base_keys = {(p.get("pid"), p.get("name")) for p in baseline}
    return [p for p in post if (p.get("pid"), p.get("name")) not in base_keys]


class DiffSnapAnalyzer(BaseAnalyzer):
    name = "memory.diffsnap"
    handles = {"*"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        baseline = ctx.extra.get("snap_baseline")
        post = ctx.extra.get("snap_post")
        if not baseline or not post:
            return []
        items: list[EvidenceItem] = []
        for proc in diff_processes(baseline, post):
            items.append(
                ctx.ev(
                    source="memory.diffsnap",
                    artifact="process",
                    operation="spawn",
                    subject={"pid": proc.get("ppid"), "name": proc.get("parent_name")},
                    object={"pid": proc.get("pid"), "name": proc.get("name")},
                    details={"note": "process present post-detonation but absent at baseline"},
                    confidence=0.7,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(DiffSnapAnalyzer())
