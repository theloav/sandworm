"""Normalize PHP call traces returned by a sandbox backend.

The old in-process PHP launcher was unsafe and could not override PHP builtins.
This module now performs inert JSONL transformation only.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context


class PhpRuntimeAnalyzer(BaseAnalyzer):
    name = "dynamic.php"
    handles = {"php"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        return []


def normalize_php_trace(trace: str, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Convert backend-produced JSONL call records into evidence."""
    for line in trace.splitlines():
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(record, dict) or not record.get("fn"):
            continue
        yield ctx.ev(
            source="dynamic.php",
            artifact="api_call",
            operation="exec",
            subject={"analyzer": "dynamic.php", "pid": record.get("pid", "php")},
            object={"function": record["fn"]},
            details={"args": record.get("args"), "observed": "sandbox trace artifact"},
            confidence=0.9,
            evidence_refs=[ref],
        )


def register(registry) -> None:
    registry.register(PhpRuntimeAnalyzer())
