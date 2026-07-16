"""The architectural spine: the EvidenceItem schema and the EvidenceStore.

Every engine in SANDWORM emits exactly one shape of data — the EvidenceItem —
instead of talking to other engines directly. Producers (analyzers) only *write*
EvidenceItems; consumers (graph, timeline, ATT&CK mapper, detection generators,
LLM copilot) only *read* from the store. This decoupling is what makes the whole
system extensible and explainable. Nothing bypasses this module.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Controlled vocabularies. Kept permissive (str fallbacks are allowed via the
# Literal-or-str unions below) so new analyzers/plugins are not blocked, while
# still documenting the canonical values the rest of the pipeline understands.
Artifact = Literal[
    "process", "file", "registry", "network", "api_call", "string",
    "thread", "module", "macro", "callback",
]
Operation = Literal[
    "create", "write", "read", "connect", "inject", "spawn",
    "decode", "resolve", "exec",
]


class EvidenceItem(BaseModel):
    """The one schema everything produces and consumes.

    ``confidence`` is REQUIRED on every item and validated to lie in [0, 1] —
    explainability depends on it. ``evidence_refs`` point back to the raw
    artifacts (files, offsets, log lines) that back the claim.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., description="Identifies the analysis run.")
    ts: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 timestamp or monotonic offset.",
    )
    source: str = Field(..., description="e.g. static.pe | dynamic.php | memory.vol3 | network")
    artifact: str = Field(..., description="process | file | registry | network | api_call | ...")
    operation: str = Field(..., description="create | write | read | connect | inject | ...")
    subject: dict[str, Any] = Field(default_factory=dict, description="who acted")
    object: dict[str, Any] = Field(default_factory=dict, description="what was acted on")
    details: dict[str, Any] = Field(default_factory=dict, description="format-specific free-form")
    confidence: float = Field(..., ge=0.0, le=1.0, description="0..1 — REQUIRED")
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def _finite_confidence(cls, v: float) -> float:
        # Guard against NaN/inf slipping past the ge/le bounds.
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("confidence must be a finite number in [0, 1]")
        return v

    @property
    def id(self) -> str:
        """A stable, content-derived id. Two identical observations collapse to
        the same id, which keeps the behavioral graph from exploding on dupes."""
        payload = json.dumps(
            {
                "source": self.source,
                "artifact": self.artifact,
                "operation": self.operation,
                "subject": self.subject,
                "object": self.object,
                "details": self.details,
            },
            sort_keys=True,
            default=str,
        )
        return "ev_" + hashlib.sha256(payload.encode()).hexdigest()[:16]


class EvidenceStore:
    """In-memory, append-only store with stable ids and simple querying.

    Thread-safe append so the (gated) dynamic analyzers can stream from worker
    threads. Persistence is JSONL via :meth:`dump`/:meth:`load`.
    """

    def __init__(self) -> None:
        self._items: dict[str, EvidenceItem] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._subscribers: list = []
        # Secondary index on (artifact, operation). map_evidence and query() are
        # otherwise O(items × rules); a real CAPE trace has thousands of events,
        # so consumers that know the facet they want skip the full scan.
        self._by_facet: dict[tuple[str, str], list[str]] = {}

    def subscribe(self, callback) -> None:
        """Register ``callback(item)`` to fire once per newly-appended item.

        Enables real-time consumers (a streaming CLI, an SSE endpoint) to act on
        early signals while deeper analysis is still running — incident responders
        do not have to wait for the full report. Callbacks fire *outside* the lock
        so a subscriber may safely read the store; duplicates are not re-notified.
        """
        self._subscribers.append(callback)

    def append(self, item: EvidenceItem) -> str:
        with self._lock:
            iid = item.id
            is_new = iid not in self._items
            if is_new:
                self._items[iid] = item
                self._order.append(iid)
                self._by_facet.setdefault((item.artifact, item.operation), []).append(iid)
        if is_new and self._subscribers:
            for cb in self._subscribers:
                cb(item)
        return iid

    def by_facet(self, artifact: str, operation: str) -> list[EvidenceItem]:
        """O(k) lookup of items with a given (artifact, operation), in insertion
        order. Returns a fresh list, safe to iterate without holding the lock."""
        with self._lock:
            ids = list(self._by_facet.get((artifact, operation), ()))
        return [self._items[i] for i in ids]

    def extend(self, items: Iterable[EvidenceItem]) -> list[str]:
        return [self.append(i) for i in items]

    def get(self, item_id: str) -> EvidenceItem | None:
        return self._items.get(item_id)

    def __len__(self) -> int:
        return len(self._order)

    def __iter__(self) -> Iterator[EvidenceItem]:
        return (self._items[i] for i in self._order)

    @property
    def items(self) -> list[EvidenceItem]:
        return [self._items[i] for i in self._order]

    def query(
        self,
        *,
        source: str | None = None,
        artifact: str | None = None,
        operation: str | None = None,
        subject_match: dict[str, Any] | None = None,
        min_confidence: float = 0.0,
    ) -> list[EvidenceItem]:
        """Filter by any combination of facets. ``subject_match`` is a subset
        match against the subject dict."""
        # Use the (artifact, operation) index when both are pinned — turns a full
        # scan into a k-item probe.
        candidates: Iterable[EvidenceItem]
        if artifact is not None and operation is not None:
            candidates = self.by_facet(artifact, operation)
        else:
            candidates = self
        out: list[EvidenceItem] = []
        for it in candidates:
            if source is not None and it.source != source:
                continue
            if artifact is not None and it.artifact != artifact:
                continue
            if operation is not None and it.operation != operation:
                continue
            if it.confidence < min_confidence:
                continue
            if subject_match and not all(it.subject.get(k) == v for k, v in subject_match.items()):
                continue
            out.append(it)
        return out

    def dump(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for it in self:
                fh.write(it.model_dump_json() + "\n")

    @classmethod
    def load(cls, path: str) -> EvidenceStore:
        store = cls()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    store.append(EvidenceItem.model_validate_json(line))
        return store
