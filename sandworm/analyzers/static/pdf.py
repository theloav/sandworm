"""PDF static analyzer.

Weaponised PDFs carry their payload in a handful of tell-tale structures:
``/JavaScript`` + ``/JS`` (embedded script), ``/OpenAction`` + ``/AA`` (fires on
open), ``/Launch`` (runs an external command), ``/EmbeddedFile`` (dropped payload)
and ``/URI`` (phishing links). This analyzer scans the raw PDF for those markers
— dependency-free — and emits each as evidence with an ATT&CK hint. It deliberately
does not execute or fully parse the PDF; presence of these structures is the
signal defenders triage on.
"""

from __future__ import annotations

import re

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

# marker (regex over raw bytes) → (label, attack_hint, why, confidence)
_PDF_MARKERS: list[tuple[bytes, str, str | None, str, float]] = [
    (rb"/OpenAction", "auto_action", "T1204.002", "action fires automatically when the document opens", 0.5),
    (rb"/AA\b", "additional_actions", "T1204.002", "additional automatic actions (open/close/page triggers)", 0.5),
    (rb"/JavaScript", "javascript", "T1059.007", "embedded JavaScript", 0.6),
    (rb"/JS\b", "javascript", "T1059.007", "embedded JavaScript stream", 0.6),
    (rb"/Launch\b", "launch", "T1059", "launches an external application/command", 0.8),
    (rb"/EmbeddedFile", "embedded_file", "T1027.001", "embedded/dropped file payload", 0.6),
    (rb"/URI\s*\(", "uri", None, "embedded URI (potential phishing link)", 0.3),
]


class PdfAnalyzer(BaseAnalyzer):
    name = "static.pdf"
    handles = {"pdf"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        data = sample.data
        items: list[EvidenceItem] = []

        # Count objects/streams for context; cheap structural summary.
        n_obj = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
        n_stream = len(re.findall(rb"\bstream\b", data))
        items.append(
            ctx.ev(
                source="static.pdf",
                artifact="file",
                operation="read",
                subject={"analyzer": self.name},
                object={"format": "PDF", "name": sample.name},
                details={"objects": n_obj, "streams": n_stream},
                confidence=0.7,
                evidence_refs=[ref],
            )
        )

        for pattern, label, hint, why, conf in _PDF_MARKERS:
            if re.search(pattern, data):
                details: dict = {"why": f"PDF {why}"}
                if hint:
                    details["attack_hint"] = hint
                items.append(
                    ctx.ev(
                        source="static.pdf",
                        artifact="api_call" if label in {"javascript", "launch"} else "file",
                        operation="exec" if label in {"javascript", "launch", "auto_action", "additional_actions"} else "read",
                        subject={"analyzer": self.name},
                        object={"sink": label, "structure": pattern.decode("latin-1").strip("\\b")},
                        details=details,
                        confidence=conf,
                        evidence_refs=[ref],
                    )
                )

        # A JavaScript-bearing PDF that also auto-fires on open is the classic
        # exploit/dropper shape — surface it as a combined higher-signal finding.
        labels = {it.object.get("sink") for it in items}
        if "javascript" in labels and (labels & {"auto_action", "additional_actions"}):
            items.append(
                ctx.ev(
                    source="static.pdf",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"capability": "auto_execute_javascript"},
                    details={
                        "attack_hint": "T1059.007",
                        "why": "PDF runs embedded JavaScript automatically on open (OpenAction/AA + /JS)",
                    },
                    confidence=0.75,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(PdfAnalyzer())


ANALYZER = PdfAnalyzer()
