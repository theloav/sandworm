"""Detection-coverage score per ATT&CK tactic.

Compares behaviors we *observed* (ATT&CK mappings) against behaviors our
*generated rules* would catch (Sigma technique tags + YARA for static-detectable
techniques). The score is intentionally honest: a technique only counts as covered
if a generated rule plausibly fires on it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..detect.sigma_gen import SigmaRule
from ..detect.yara_gen import YaraRule
from ..reconstruct.attack_map import TACTICS, AttackMapping

# Techniques a static YARA signature can realistically catch on its own.
_YARA_DETECTABLE = {"T1027", "T1140", "T1505.003", "T1059.001", "T1059"}


@dataclass
class TacticCoverage:
    tactic: str
    observed: list[str]
    covered: list[str]
    score: float


@dataclass
class CoverageReport:
    per_tactic: list[TacticCoverage]
    overall: float

    def to_dict(self) -> dict:
        return {"per_tactic": [asdict(t) for t in self.per_tactic], "overall": self.overall}


def _covered_ids(sigma: list[SigmaRule], yara: list[YaraRule], observed_ids: set[str]) -> set[str]:
    covered: set[str] = set()
    sigma_tags = {t.lower() for r in sigma for t in r.tags}
    for tid in observed_ids:
        if f"attack.{tid.lower()}" in sigma_tags:
            covered.add(tid)
        elif yara and tid in _YARA_DETECTABLE:
            covered.add(tid)
    return covered


def compute_coverage(
    mappings: list[AttackMapping],
    sigma_rules: list[SigmaRule],
    yara_rules: list[YaraRule],
) -> CoverageReport:
    by_tactic: dict[str, list[str]] = {}
    for m in mappings:
        by_tactic.setdefault(m.tactic, []).append(m.technique_id)

    observed_ids = {m.technique_id for m in mappings}
    covered_ids = _covered_ids(sigma_rules, yara_rules, observed_ids)

    per_tactic: list[TacticCoverage] = []
    total_obs = 0
    total_cov = 0
    for tactic in TACTICS:
        obs = sorted(set(by_tactic.get(tactic, [])))
        if not obs:
            continue
        cov = sorted(t for t in obs if t in covered_ids)
        total_obs += len(obs)
        total_cov += len(cov)
        per_tactic.append(
            TacticCoverage(tactic=tactic, observed=obs, covered=cov, score=round(len(cov) / len(obs), 3))
        )
    overall = round(total_cov / total_obs, 3) if total_obs else 0.0
    return CoverageReport(per_tactic=per_tactic, overall=overall)
