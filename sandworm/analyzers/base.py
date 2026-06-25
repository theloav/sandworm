"""The plugin SDK contract.

Every analyzer — static, dynamic, memory, or a community plugin — implements
:class:`Analyzer` and returns a list of :class:`EvidenceItem`. Analyzers MUST NOT
talk to each other; they only read the sample (and the shared Context) and write
EvidenceItems. This is the entire extensibility story; see
``docs/writing-an-analyzer.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..core.audit import AuditLogger
from ..core.config import Config, get_config
from ..core.evidence import EvidenceItem, EvidenceStore
from ..core.sample import Sample


@dataclass
class Context:
    """Shared, read-mostly context handed to every analyzer.

    ``requires_isolation`` lets the registry decide whether an analyzer is part
    of the dynamic lane (gated by the isolation check) vs. the always-on static
    lane. ``isolated`` reports whether the gate passed for this run.
    """

    run_id: str
    config: Config = field(default_factory=get_config)
    audit: AuditLogger | None = None
    isolated: bool = False
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.audit is None:
            self.audit = AuditLogger(self.config)

    def ev(self, **kwargs) -> EvidenceItem:
        """Convenience factory that stamps the run_id onto an EvidenceItem."""
        kwargs.setdefault("run_id", self.run_id)
        return EvidenceItem(**kwargs)


@runtime_checkable
class Analyzer(Protocol):
    name: str
    handles: set[str]  # format tags this analyzer claims, e.g. {"php"}
    requires_isolation: bool  # True for dynamic/detonation analyzers

    def analyze(self, sample: Sample, ctx: Context) -> list[EvidenceItem]: ...


class BaseAnalyzer:
    """Optional convenience base. Implements the audit-on-run boilerplate so
    concrete analyzers just override :meth:`run`."""

    name: str = "base"
    handles: set[str] = set()
    requires_isolation: bool = False

    def analyze(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        assert ctx.audit is not None
        ctx.audit.log(
            run_id=ctx.run_id,
            action="analyzer_start",
            analyzer=self.name,
            sample_hash=sample.sha256,
        )
        try:
            items = self.run(sample, ctx)
        except Exception as exc:  # analyzers must never crash the pipeline
            ctx.audit.log(
                run_id=ctx.run_id,
                action="analyzer_error",
                analyzer=self.name,
                sample_hash=sample.sha256,
                error=repr(exc),
            )
            return []
        ctx.audit.log(
            run_id=ctx.run_id,
            action="analyzer_done",
            analyzer=self.name,
            sample_hash=sample.sha256,
            evidence_count=len(items),
        )
        return items

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:  # pragma: no cover
        raise NotImplementedError


def write_all(items: list[EvidenceItem], store: EvidenceStore) -> list[str]:
    return store.extend(items)
