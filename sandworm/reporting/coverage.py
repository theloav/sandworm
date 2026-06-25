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
class RuleInventory:
    techniques: int
    behavioral_rules: int
    ioc_rules: int
    yara_rules: int
    runtime_rules: int  # rules derived from observed runtime/memory evidence


@dataclass
class CoverageReport:
    per_tactic: list[TacticCoverage]
    overall: float                    # detection coverage of MAPPED (mostly inferred) techniques
    inventory: RuleInventory
    observed_techniques: int = 0      # techniques confirmed by runtime/memory
    inferred_techniques: int = 0      # techniques supported only by static evidence
    runtime_coverage: float | None = None  # coverage of OBSERVED techniques; None when none observed
    detectable: bool = False          # would ANY generated rule (YARA/Sigma) flag this sample?

    def to_dict(self) -> dict:
        return {
            "per_tactic": [asdict(t) for t in self.per_tactic],
            "overall": self.overall,
            "inventory": asdict(self.inventory),
            "observed_techniques": self.observed_techniques,
            "inferred_techniques": self.inferred_techniques,
            "runtime_coverage": self.runtime_coverage,
            "detectable": self.detectable,
        }


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

    # Epistemic split: "observed" techniques are runtime/memory-confirmed. On a
    # static-only run there are none, so runtime coverage is N/A (None) rather
    # than a misleading 100%.
    obs_ids = {m.technique_id for m in mappings if m.status == "observed"}
    inf_ids = {m.technique_id for m in mappings if m.status != "observed"}

    # A rule is "runtime-derived" once it covers a technique we actually OBSERVED
    # (i.e. it would fire on captured runtime/memory data). Zero on a static run.
    behavioral = sum(1 for r in sigma_rules if r.kind == "behavioral")
    ioc = sum(1 for r in sigma_rules if r.kind == "ioc")
    runtime_rules = 0
    if obs_ids:
        for r in sigma_rules:
            tags = {t.replace("attack.", "").upper() for t in r.tags}
            if tags & {t.upper() for t in obs_ids}:
                runtime_rules += 1
    inventory = RuleInventory(
        techniques=len(observed_ids),
        behavioral_rules=behavioral,
        ioc_rules=ioc,
        yara_rules=len(yara_rules),
        runtime_rules=runtime_rules,
    )

    runtime_cov: float | None
    if obs_ids:
        runtime_cov = round(len(obs_ids & covered_ids) / len(obs_ids), 3)
    else:
        runtime_cov = None

    return CoverageReport(
        per_tactic=per_tactic,
        overall=overall,
        inventory=inventory,
        observed_techniques=len(obs_ids),
        inferred_techniques=len(inf_ids),
        runtime_coverage=runtime_cov,
        detectable=bool(yara_rules) or bool(sigma_rules),
    )
