"""Temporal behavioural timeline from dynamic traces.

The lifecycle view answers *which* phases were reached; this answers *when*, and
in *what order*. Malware is a story — "it checked for a sandbox, called home,
installed persistence, then encrypted" is a narrative defenders can act on, where
"it encrypted files" is not. We reconstruct that story from the relative offsets
(``details.t_offset``, seconds from process start) the dynamic lane records.

This is a pure consumer of the EvidenceStore: only items that carry a recorded
offset appear, so a static-only run yields an empty (pending) timeline rather than
inventing timing it never observed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..core.evidence import EvidenceStore
from ..core.provenance import provenance_of

# artifact/operation → (timeline kind, colour) for the SVG strip.
_KIND = {
    ("process", "spawn"): ("process", "#7ee787"),
    ("process", "inject"): ("memory", "#bc8cff"),
    ("process", "exec"): ("process", "#7ee787"),
    ("api_call", "exec"): ("api", "#58a6ff"),
    ("api_call", "inject"): ("memory", "#bc8cff"),
    ("network", "connect"): ("network", "#f85149"),
    ("file", "create"): ("file", "#e3b341"),
    ("file", "write"): ("file", "#e3b341"),
    ("registry", "write"): ("registry", "#d2a8ff"),
}


@dataclass
class TemporalEvent:
    offset: float          # seconds from start
    label: str             # "T+0.120s"
    abs_time: str          # absolute clock time when start_time was recorded, else ""
    text: str              # human description
    kind: str              # process | api | network | file | registry | memory
    color: str
    status: str
    source: str
    evidence_id: str


@dataclass
class TemporalTimeline:
    observed: bool
    duration: float
    events: list[TemporalEvent] = field(default_factory=list)


def _text(it) -> str:
    o = it.object
    if it.artifact == "process" and it.operation == "spawn":
        return f"Process {o.get('name', '?')} (pid {o.get('pid', '?')}) created"
    if it.artifact == "api_call":
        return f"{o.get('api') or o.get('hooked', 'API')} called"
    if it.artifact == "network":
        return f"Network egress → {o.get('value') or o.get('host', '?')}"
    if it.artifact == "file":
        return f"File written: {o.get('path', '?')}"
    if it.artifact == "registry":
        return f"Registry write: {o.get('key', '?')}"
    return f"{it.artifact}/{it.operation}"


def build_temporal_timeline(store: EvidenceStore) -> TemporalTimeline:
    events: list[TemporalEvent] = []
    for it in store:
        t = it.details.get("t_offset")
        if not isinstance(t, (int, float)):
            continue
        kind, color = _KIND.get((it.artifact, it.operation), ("event", "#8b949e"))
        abs_time = ""
        start = it.details.get("t_start")
        if isinstance(start, str):
            try:
                base = datetime.fromisoformat(start.replace("Z", "+00:00"))
                abs_time = (base + timedelta(seconds=float(t))).strftime("%H:%M:%S.%f")[:-3]
            except ValueError:
                abs_time = ""
        events.append(
            TemporalEvent(
                offset=float(t),
                label=it.details.get("t_label") or f"T+{float(t):.3f}s",
                abs_time=abs_time,
                text=_text(it),
                kind=kind,
                color=color,
                status=provenance_of(it.source, it.confidence),
                source=it.source,
                evidence_id=it.id,
            )
        )
    events.sort(key=lambda e: e.offset)
    duration = events[-1].offset if events else 0.0
    return TemporalTimeline(observed=bool(events), duration=duration, events=events)


def render_timeline_svg(tl: TemporalTimeline, width: int = 1100) -> str:
    """A compact horizontal SVG strip: time on the x-axis, one dot per event with
    alternating above/below labels so dense bursts stay legible."""
    if not tl.events:
        return ""
    left, right, mid = 60, width - 30, 70
    span = right - left
    dur = tl.duration or 1.0
    parts = [
        f"<svg viewBox='0 0 {width} 150' xmlns='http://www.w3.org/2000/svg'>",
        f"<line x1='{left}' y1='{mid}' x2='{right}' y2='{mid}' stroke='#30363d' stroke-width='1'/>",
    ]
    # axis ticks
    for i in range(6):
        x = left + span * i / 5
        t = dur * i / 5
        parts.append(f"<line x1='{x:.0f}' y1='{mid - 4}' x2='{x:.0f}' y2='{mid + 4}' stroke='#484f58'/>")
        parts.append(f"<text x='{x:.0f}' y='{mid + 18}' fill='#6e7681' font-size='9' text-anchor='middle'>T+{t:.2f}s</text>")
    for i, e in enumerate(tl.events):
        x = left + span * (e.offset / dur)
        up = i % 2 == 0
        ly = mid - 14 if up else mid + 30
        anchor = "middle"
        label = e.text if len(e.text) <= 34 else e.text[:33] + "…"
        parts.append(f"<circle cx='{x:.0f}' cy='{mid}' r='5' fill='{e.color}'><title>{e.label} — {e.text}</title></circle>")
        parts.append(f"<text x='{x:.0f}' y='{ly}' fill='#c9d1d9' font-size='9' text-anchor='{anchor}'>{label}</text>")
        parts.append(f"<text x='{x:.0f}' y='{ly + (-11 if up else 11)}' fill='#6e7681' font-size='8' text-anchor='{anchor}'>{e.label}</text>")
    parts.append("</svg>")
    return "".join(parts)
