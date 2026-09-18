# Reproducible, narrowly scoped measurements

Read [methods and caveats](../docs/measurement.md) before interpreting these files.

- `manifest.json`: eight manually labeled script fixtures, hash-pinned; only the
  listed positive/negative techniques are judged. Never execute these fixtures.
- `results/metrics.json`, `summary.md`, `reliability.svg`: regression baseline,
  including the four known false negatives. This is not a held-out malware corpus.
- `audited-rules.yar`: frozen generated rules from `fixtures/download.ps1` and
  `samples/synthetic/benign_webshell.php`. Their source sample hashes are in rule
  metadata. These two rules do not represent all families or future generated rules.
- `linux-goodware-manifest.json`: paths relative to the measured local `/usr/bin`,
  full-file SHA-256s, sizes and explicit assumed-benign provenance. No binaries
  included. Reproduction requires exactly these file versions; a different machine
  needs a separately named inventory/result rather than silently substituting files.
- `linux-goodware-results.json`: YARA-X 1.20.0 audit of all 1,267 unique files,
  with manifest/rule hashes, per-rule hits, error accounting and descriptive intervals.
- `matcher-results.json`: fixed-seed 8 MiB data, five repetitions, alternating
  engine order, parity check, normalization/copy costs included. Not a pipeline
  throughput or peak-memory benchmark.

Labels and baseline are intentionally separate from model tuning. A baseline
update should explain each label/threshold/rule change; CI must not regenerate a
passing baseline from current predictions automatically. Expand evaluation with
independently reviewed samples and family/time-disjoint held-out sets before
claiming calibrated probabilities, malware recall or production FP rates.
