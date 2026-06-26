"""Genetic optimisation of detection rules (#9)."""

from __future__ import annotations

from sandworm.detect.optimize import RuleCandidate, Scored, optimize


def _corpora():
    # 'evil_marker' and 'c2.evil.ru' are specific to malware; 'http' and 'data'
    # also appear in goodware (FP-prone). A good strict rule uses the specific
    # atoms; a loose rule may include the noisy ones to catch more variants.
    pool = [b"evil_marker", b"c2.evil.ru", b"http", b"data", b"ransom_note"]
    malicious = [
        b"...evil_marker... beacon to c2.evil.ru ... http ... data",
        b"variant: evil_marker http data ransom_note",
        b"third: c2.evil.ru ransom_note http",
    ]
    clean = [
        b"normal app uses http and data everywhere",
        b"another benign http data http data",
        b"GET / HTTP/1.1 data: ok",
    ]
    return pool, malicious, clean


def test_frontier_is_nondominated_and_nonempty():
    pool, mal, clean = _corpora()
    front = optimize(pool, mal, clean, generations=20, population=30, seed=1)
    assert front.points
    # no point on the frontier dominates another
    for a in front.points:
        assert not any(b.dominates(a) for b in front.points if b is not a)


def test_strict_has_no_false_positives_loose_has_higher_recall():
    pool, mal, clean = _corpora()
    picks = optimize(pool, mal, clean, generations=30, population=40, seed=2).pick()
    assert picks["strict"].fp_rate == 0.0           # strict: zero FP
    assert picks["loose"].recall >= picks["strict"].recall
    # the balanced point is a sensible middle (no worse FP than loose at >= its recall band)
    assert picks["balanced"].fp_rate <= picks["loose"].fp_rate or picks["balanced"].recall >= picks["strict"].recall


def test_deterministic_for_a_seed():
    pool, mal, clean = _corpora()
    a = optimize(pool, mal, clean, seed=7).pick()["strict"]
    b = optimize(pool, mal, clean, seed=7).pick()["strict"]
    assert a.candidate == b.candidate


def test_candidate_serialises_to_yara():
    cand = RuleCandidate((b"evil_marker", b"c2.evil.ru"), 2)
    rule = cand.to_rule("SANDWORM_OPT")
    assert rule.matches(b"x evil_marker y c2.evil.ru z")
    assert not rule.matches(b"only evil_marker here")  # needs 2 of them
    assert "rule SANDWORM_OPT" in rule.to_yara()


def test_empty_pool_yields_empty_frontier():
    assert optimize([], [b"x"], [b"y"]).points == []


def test_dominance_relation():
    better = Scored(RuleCandidate((b"a",), 1), recall=0.9, fp_rate=0.0, cost=0.2)
    worse = Scored(RuleCandidate((b"b",), 1), recall=0.8, fp_rate=0.1, cost=0.4)
    assert better.dominates(worse) and not worse.dominates(better)
