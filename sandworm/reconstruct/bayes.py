"""Bayesian confidence aggregation across evidence lanes.

Each ATT&CK technique is a hypothesis H. Instead of an ad-hoc ``max(conf)+0.03``,
we update belief in H by combining the supporting evidence in **log-odds**:

    logit(P(H)) = logit(prior) + Σ_lane  w_lane · Σ_i (logit(s_i) − logit(prior))

where ``s_i`` is how strongly one item supports H and ``w_lane`` weights the lane
(runtime observation outweighs a static inference). Two consequences the analyst
wants fall out for free:

* a technique inferred from static at 0.40 becomes believable when dynamic and
  memory independently corroborate it (the posterior climbs past either lane);
* a lone weak single-import inference stays near the prior — it never inflates.

The prior is a single documented base rate (no corpus is assumed offline); it is
reported alongside the posterior so the update is auditable, not a magic number.
"""

from __future__ import annotations

import math

# Documented base rate that an arbitrary technique is genuinely present in a
# sample before any evidence — deliberately low so weak signals can't masquerade
# as findings. Exposed in the report so the prior→posterior step is auditable.
PRIOR = 0.12

# Runtime-observed lanes carry more weight than a static inference of the same
# nominal strength: seeing it happen beats inferring it could.
LANE_WEIGHT = {"static": 1.0, "dynamic": 1.35, "memory": 1.3}

# Within one lane, repeated signals for the same technique are correlated (three
# injection imports are one capability, not three independent confirmations), so
# each additional item's log-odds contribution is discounted geometrically. Cross-
# lane corroboration is treated as independent (full weight) — that is the signal
# that should compound.
_CORR_DISCOUNT = 0.55

_EPS = 1e-6


def _logit(p: float) -> float:
    p = min(1 - _EPS, max(_EPS, p))
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def fuse(
    supports_by_lane: dict[str, list[float]],
    *,
    prior: float = PRIOR,
    weights: dict[str, float] | None = None,
) -> tuple[float, dict[str, float]]:
    """Return ``(aggregate_posterior, {lane: lane_posterior})``.

    ``supports_by_lane`` maps a lane (static/dynamic/memory) to the per-item
    support values that fired for the technique in that lane. Within a lane the
    items are pooled in log-odds; across lanes the pooled deltas are weighted and
    summed. The result is capped at 0.99 (we never claim certainty).
    """
    weights = weights or LANE_WEIGHT
    base = _logit(prior)
    agg = base
    lane_post: dict[str, float] = {}
    for lane, supports in supports_by_lane.items():
        if not supports:
            continue
        # Strongest item full weight; each further (correlated) item discounted.
        ordered = sorted((_logit(s) - base for s in supports), reverse=True)
        delta = sum(d * (_CORR_DISCOUNT ** i) for i, d in enumerate(ordered))
        lane_post[lane] = round(min(0.99, _sigmoid(base + delta)), 3)
        agg += weights.get(lane, 1.0) * delta
    return round(min(0.99, _sigmoid(agg)), 3), lane_post
