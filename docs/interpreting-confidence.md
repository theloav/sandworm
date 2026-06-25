# Interpreting confidence

Every `EvidenceItem` and every ATT&CK mapping carries a `confidence` in `[0, 1]`.
Confidence is **required** precisely so that nothing in SANDWORM is a bare,
unqualified claim. Read it as: *how much should a defender trust this single
observation on its own?*

## Bands

| Range | Reading | Typical source |
|-------|---------|----------------|
| 0.85–0.99 | Strong, near-deterministic | observed injection API pair, deobfuscated sink, canary access, runtime syscall trace |
| 0.6–0.85 | Probable | static import of a suspicious API, a single decoder layer, YARA heuristic hit |
| 0.4–0.6 | Suggestive | bare domain/IP IOC, generic flag, high entropy |
| < 0.4 | Weak / contextual | skipped lanes, ambiguous tokens |

We never emit `1.0` — certainty is reserved for ground truth we don't have.

## How mapping confidence is combined

`reconstruct/attack_map.py` computes a technique's confidence from its rule's base
confidence scaled by the backing evidence's confidence, then **raises it when
multiple independent items corroborate** (capped at 0.99). So
`WriteProcessMemory` + `CreateRemoteThread` → T1055 scores higher than either
alone, and the mapping's `why` lists *every* contributing observation.

## False-positive risk vs confidence

These are different axes. An IOC can be high-confidence-as-extracted but
high-false-positive-**risk** as a detection (e.g. a bare domain). IOC evidence
carries a separate `false_positive_risk` note (`low`/`medium`/`high`) in
`details`; the report shows both. YARA generation uses this idea directly: a rule
that matches the bundled clean corpus is **dropped**, regardless of how confident
the underlying evidence was.

## Coverage score

`reporting/coverage.py` is deliberately conservative: a technique counts as
"covered" only if a generated Sigma rule is tagged with it (or a YARA rule plausibly
fires for a statically-detectable technique). A 60% coverage score means 40% of
what we *observed* would slip past the detections we *generated* — that gap is the
honest, actionable output.
