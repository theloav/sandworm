"""Real-time evidence streaming.

Analysis is batch today: run a sample, wait, read the report. For incident
response that latency is the problem — an analyst wants to act on the first C2
contact or persistence write, not five minutes later. Subscribing to the
EvidenceStore turns the run into a live feed: each finding is emitted as it is
discovered, and the high-signal ones (C2 egress, injection, persistence, an
execution sink, ransomware capability) are flagged ALERT so they stand out.

This is the consumer side; the store's pub/sub does the plumbing. The same
``format_event``/``StreamFeed`` could back an SSE/WebSocket endpoint that renders
the behavioural graph incrementally — the CLI printer is just one subscriber.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.evidence import EvidenceItem
from ..core.provenance import provenance_of

# (artifact, operation) → an ALERT reason for findings a responder should see now.
_ALERT = {
    ("network", "connect"): "C2 / network egress",
    ("network", "resolve"): "C2 / network egress",
    ("process", "inject"): "code injection",
    ("registry", "write"): "persistence (registry)",
    ("api_call", "inject"): "in-memory hook / injection",
}


def _alert_reason(it: EvidenceItem) -> str | None:
    if (r := _ALERT.get((it.artifact, it.operation))):
        return r
    o = it.object
    if o.get("sink"):
        return "execution sink"
    if o.get("capability") == "ransomware":
        return "ransomware capability"
    if o.get("verdict") == "php_webshell":
        return "web shell"
    if o.get("hidden") or it.details.get("hidden"):
        return "hidden process"
    return None


def format_event(it: EvidenceItem, *, t0: float | None = None) -> str:
    """A single human-readable feed line; ALERT-prefixed for high-signal items."""
    clock = f"[{time.time() - t0:6.3f}s] " if t0 is not None else ""
    standing = provenance_of(it.source, it.confidence)
    o = it.object
    target = (o.get("value") or o.get("host") or o.get("path") or o.get("key") or o.get("sink")
              or o.get("api") or o.get("import") or o.get("capability") or o.get("name")
              or o.get("verdict") or f"{it.artifact}/{it.operation}")
    line = f"{clock}[{it.source}] {it.operation} {target} ({it.confidence:.2f}, {standing})"
    reason = _alert_reason(it)
    return f"ALERT {line}  ⟵ {reason}" if reason else line


@dataclass
class StreamFeed:
    """Collects formatted lines (and counts alerts) as evidence streams in. Usable
    as the subscriber callback directly: ``store.subscribe(feed)``."""

    sink: Callable[[str], None] | None = None      # e.g. typer.echo / print; None just buffers
    t0: float = field(default_factory=time.time)
    lines: list[str] = field(default_factory=list)
    alerts: int = 0

    def __call__(self, it: EvidenceItem) -> None:
        line = format_event(it, t0=self.t0)
        self.lines.append(line)
        if line.startswith("ALERT"):
            self.alerts += 1
        if self.sink is not None:
            self.sink(line)
