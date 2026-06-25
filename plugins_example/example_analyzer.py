"""Example community plugin — the Analyzer SDK in ~30 lines.

Drop this file (or your own copy) into a directory and point SANDWORM at it:

    sandworm plugins --dir plugins_example

No core changes are required. A plugin module may expose either a top-level
``ANALYZER`` instance (shown here) or a ``register(registry)`` hook.

This toy analyzer flags any sample that mentions a cryptocurrency wallet address
pattern — purely to demonstrate the contract.
"""

from __future__ import annotations

import re

# Plugins import from the installed `sandworm` package.
from sandworm.analyzers.base import BaseAnalyzer, Context
from sandworm.core.evidence import EvidenceItem
from sandworm.core.sample import Sample

_BTC = re.compile(rb"\b(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")


class WalletAnalyzer(BaseAnalyzer):
    name = "plugin.wallet"
    handles = {"*"}          # claim every format
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        for m in _BTC.finditer(sample.data):
            items.append(
                ctx.ev(
                    source="plugin.wallet",
                    artifact="string",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"kind": "btc_wallet", "value": m.group().decode("ascii", "replace")},
                    details={"ioc": True, "false_positive_risk": "medium", "why": "looks like a BTC address"},
                    confidence=0.5,
                )
            )
        return items


# The registry picks up this top-level instance automatically.
ANALYZER = WalletAnalyzer()
