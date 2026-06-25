"""Canary-token tainting: plant fake secrets, detect access.

Plants benign-looking but unique canaries (fake AWS keys, fake credentials, a
fake browser-history file) into the detonation environment. If the sample reads
or exfiltrates any of them, we emit a HIGH-confidence intent finding (credential
harvesting / browser profiling) — intent is far stronger signal than capability.

The plant step writes files into a provided env dir; the detect step scans
collected evidence (and any exfil capture) for the canary tokens.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path

from ..core.evidence import EvidenceItem, EvidenceStore


@dataclass
class Canary:
    kind: str  # aws_key | credential | browser_history
    token: str
    placement: str


@dataclass
class CanarySet:
    canaries: list[Canary] = field(default_factory=list)

    def tokens(self) -> dict[str, Canary]:
        return {c.token: c for c in self.canaries}


def plant(env_dir: str | Path) -> CanarySet:
    """Write canaries into the (isolated) detonation env. Returns the set so the
    detect step knows what to look for."""
    env = Path(env_dir)
    env.mkdir(parents=True, exist_ok=True)
    aws = "AKIA" + secrets.token_hex(8).upper()[:16]
    cred = f"svc_admin:{secrets.token_urlsafe(12)}"
    hist = secrets.token_hex(8)

    (env / ".aws_credentials").write_text(f"[default]\naws_access_key_id={aws}\n")
    (env / ".netrc").write_text(f"machine internal login {cred}\n")
    (env / "History").write_text(f"http://intranet.local/secret-{hist}\n")

    return CanarySet(
        canaries=[
            Canary("aws_key", aws, str(env / ".aws_credentials")),
            Canary("credential", cred, str(env / ".netrc")),
            Canary("browser_history", hist, str(env / "History")),
        ]
    )


def detect(store: EvidenceStore, canaries: CanarySet, run_id: str, *, exfil_blobs: list[str] | None = None) -> list[EvidenceItem]:
    """Emit findings for any canary that shows up in evidence or exfil capture."""
    findings: list[EvidenceItem] = []
    tokens = canaries.tokens()
    haystacks: list[tuple[str, str]] = []
    for it in store:
        haystacks.append((it.id, (str(it.object) + str(it.details))))
    for i, blob in enumerate(exfil_blobs or []):
        haystacks.append((f"exfil:{i}", blob))

    for token, canary in tokens.items():
        for src_id, hay in haystacks:
            if token in hay:
                intent = {
                    "aws_key": ("credential harvesting", 0.95),
                    "credential": ("credential harvesting", 0.95),
                    "browser_history": ("browser profiling", 0.9),
                }[canary.kind]
                findings.append(
                    EvidenceItem(
                        run_id=run_id,
                        source="enrich.canary",
                        artifact="file",
                        operation="read",
                        subject={"analyzer": "enrich.canary"},
                        object={"canary_kind": canary.kind, "placement": canary.placement},
                        details={
                            "intent": intent[0],
                            "canary_kind": canary.kind,
                            "observed_in": src_id,
                            "why": f"sample accessed planted {canary.kind} canary — strong intent signal",
                        },
                        confidence=intent[1],
                        evidence_refs=[src_id],
                    )
                )
                break
    return findings
