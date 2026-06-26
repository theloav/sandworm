"""Genetic optimisation of generated detection rules.

Rule generation is one-shot today: take the evidence strings, drop any that hit
the clean corpus, ship it. That yields *a* rule, not the *best* rule. Here we
treat rule construction as a multi-objective search: given a pool of candidate
strings, a malicious corpus the rule should catch, and a clean corpus it must not
hit, evolve a population of rules and return the **Pareto frontier** — the set of
non-dominated precision/recall/cost trade-offs. The analyst then picks a point on
the frontier: *strict* (zero false positives), *balanced*, or *loose* (catch the
most variants).

Three objectives, all offline and deterministic for a given seed:
  • recall   — fraction of the malicious corpus matched   (maximise)
  • fp_rate  — fraction of the clean corpus matched        (minimise)
  • cost     — rule size / match work                      (minimise)

This optimises *our* detections for precision/recall against local corpora; it
does not evolve malware to evade anything.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .yara_gen import YaraRule


@dataclass(frozen=True)
class RuleCandidate:
    strings: tuple[bytes, ...]
    condition_min: int

    def matches(self, data: bytes) -> bool:
        hits = sum(1 for s in self.strings if s and s in data)
        return bool(self.strings) and hits >= self.condition_min

    def to_rule(self, name: str, meta: dict | None = None) -> YaraRule:
        return YaraRule(name=name, strings=list(self.strings),
                        condition_min=self.condition_min, meta=meta or {})


@dataclass
class Scored:
    candidate: RuleCandidate
    recall: float
    fp_rate: float
    cost: float

    def objectives(self) -> tuple[float, float, float]:
        # higher is better for all three (recall up, fp down, cost down)
        return (self.recall, -self.fp_rate, -self.cost)

    def dominates(self, other: Scored) -> bool:
        a, b = self.objectives(), other.objectives()
        return all(x >= y for x, y in zip(a, b, strict=True)) and any(x > y for x, y in zip(a, b, strict=True))


@dataclass
class Frontier:
    points: list[Scored] = field(default_factory=list)

    def pick(self) -> dict[str, Scored]:
        """Three named operating points off the frontier."""
        if not self.points:
            return {}
        strict = min(self.points, key=lambda s: (s.fp_rate, -s.recall, s.cost))
        loose = max(self.points, key=lambda s: (s.recall, -s.fp_rate, -s.cost))
        balanced = max(self.points, key=lambda s: s.recall - 1.5 * s.fp_rate - 0.1 * s.cost)
        return {"strict": strict, "balanced": balanced, "loose": loose}


def _evaluate(cand: RuleCandidate, malicious: list[bytes], clean: list[bytes], pool_size: int) -> Scored:
    recall = (sum(cand.matches(m) for m in malicious) / len(malicious)) if malicious else 0.0
    fp_rate = (sum(cand.matches(c) for c in clean) / len(clean)) if clean else 0.0
    cost = len(cand.strings) / max(1, pool_size)
    return Scored(cand, round(recall, 4), round(fp_rate, 4), round(cost, 4))


def _nondominated(scored: list[Scored]) -> list[Scored]:
    front: list[Scored] = []
    for s in scored:
        if any(o.dominates(s) for o in scored if o is not s):
            continue
        # de-dupe identical objective points
        if not any(o.objectives() == s.objectives() for o in front):
            front.append(s)
    return front


def _random_candidate(pool: list[bytes], rng: random.Random) -> RuleCandidate:
    k = rng.randint(1, len(pool))
    chosen = tuple(rng.sample(pool, k))
    return RuleCandidate(chosen, rng.randint(1, len(chosen)))


def _mutate(cand: RuleCandidate, pool: list[bytes], rng: random.Random) -> RuleCandidate:
    strings = list(cand.strings)
    if rng.random() < 0.5 and len(pool) > len(strings):
        strings.append(rng.choice([s for s in pool if s not in strings]))
    elif len(strings) > 1:
        strings.pop(rng.randrange(len(strings)))
    cmin = min(len(strings), max(1, cand.condition_min + rng.choice((-1, 0, 1))))
    return RuleCandidate(tuple(dict.fromkeys(strings)), cmin)


def _crossover(a: RuleCandidate, b: RuleCandidate, rng: random.Random) -> RuleCandidate:
    union = list(dict.fromkeys(a.strings + b.strings))
    k = max(1, rng.randint(min(len(a.strings), len(b.strings)), len(union)))
    chosen = tuple(rng.sample(union, min(k, len(union))))
    cmin = max(1, min(len(chosen), (a.condition_min + b.condition_min) // 2))
    return RuleCandidate(chosen, cmin)


def optimize(
    pool: list[bytes],
    malicious: list[bytes],
    clean: list[bytes],
    *,
    generations: int = 25,
    population: int = 40,
    seed: int = 0,
) -> Frontier:
    """Evolve rules over the corpora and return the Pareto frontier."""
    pool = [s for s in dict.fromkeys(pool) if s]
    if not pool:
        return Frontier()
    rng = random.Random(seed)
    pop = [_random_candidate(pool, rng) for _ in range(population)]
    archive: list[Scored] = []
    for _ in range(generations):
        scored = [_evaluate(c, malicious, clean, len(pool)) for c in pop]
        archive = _nondominated(archive + scored)
        # parents: bias toward the current frontier, then breed
        parents = [s.candidate for s in archive] or [s.candidate for s in scored]
        nxt: list[RuleCandidate] = list(parents)[:population]
        while len(nxt) < population:
            a, b = rng.choice(parents), rng.choice(parents)
            child = _crossover(a, b, rng)
            if rng.random() < 0.6:
                child = _mutate(child, pool, rng)
            nxt.append(child)
        pop = nxt
    final = [_evaluate(c, malicious, clean, len(pool)) for c in pop]
    return Frontier(_nondominated(archive + final))
