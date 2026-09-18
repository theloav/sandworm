"""Offline indicator enrichment with source, timestamp and evidence citations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..core.evidence import EvidenceItem, EvidenceStore


def enrich_snapshot(store: EvidenceStore, path: str | Path, run_id: str) -> list[EvidenceItem]:
    file = Path(path)
    if file.stat().st_size > 32 * 1024**2:
        raise ValueError("intelligence snapshot exceeds 32 MiB")
    data = json.loads(file.read_text())
    if data.get("schema_version") != 1 or not data.get("source") or not data.get("created_at"):
        raise ValueError("snapshot requires schema_version=1, source, and created_at")
    created = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
    if created.tzinfo is None:
        raise ValueError("snapshot timestamp must include timezone")
    age = max(0, (datetime.now(UTC) - created).days)
    index: dict[tuple[str, str], dict] = {}
    for row in data.get("indicators", [])[:100000]:
        index[(row["kind"].lower(), row["value"].lower())] = row
    out = []
    for item in store:
        row = index.get((str(item.object.get("kind", "")).lower(), str(item.object.get("value", "")).lower()))
        if row is None:
            continue
        out.append(EvidenceItem(run_id=run_id, source="enrich.intelligence", artifact="indicator",
                                operation="lookup", object={"kind": row["kind"], "value": row["value"]},
                                details={"source": data["source"], "created_at": data["created_at"],
                                         "age_days": age, "stale": age > 90, "labels": row.get("labels", []),
                                         "why": "indicator matches an offline intelligence snapshot; not proof of attribution"},
                                confidence=min(float(row.get("confidence", 0.6)), 0.8) * (0.5 if age > 90 else 1),
                                evidence_refs=["evidence:" + item.id]))
    return out
