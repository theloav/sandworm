"""File-similarity fingerprint (runs on every sample).

Emits a fuzzy byte-similarity MinHash of the whole file as evidence. Lineage then
finds byte-similar samples in the persisted corpus even when the sha256 differs
(recompiles, IOC rotation, minor packing). Import-profile fingerprints (imphash)
are emitted by the format analyzers that already parse imports (e.g. the PE lane).
"""

from __future__ import annotations

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ...core.simhash import file_minhash
from ..base import BaseAnalyzer, Context


class FingerprintAnalyzer(BaseAnalyzer):
    name = "static.fingerprint"
    handles = {"*"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        digest = file_minhash(sample.data)
        return [
            ctx.ev(
                source="static.fingerprint",
                artifact="file",
                operation="read",
                subject={"analyzer": self.name},
                object={"fingerprint": "file_minhash"},
                details={"file_minhash": list(digest), "note": "fuzzy byte-similarity digest for lineage"},
                confidence=0.5,
                evidence_refs=[f"sample:{sample.sha256}"],
            )
        ]


def register(registry) -> None:
    registry.register(FingerprintAnalyzer())


ANALYZER = FingerprintAnalyzer()
