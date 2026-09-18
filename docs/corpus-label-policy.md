# Annotation policy and independent evaluation

## Existing baseline is provisional

The eight-script manifest intentionally remains unchanged. It mixes broad language
presence with behavior-specific capability labels and is useful for regression,
not for fitting confidence weights or claiming malware recall. Its four misses
must not automatically become new detection rules. In particular, a shell file
containing `printf` or an ordinary PowerShell inventory script does not by itself
prove adversarial interpreter use. The correct response is explicit policy and
independent review, not silently relabeling the old test to improve scores.

## `static-behavior-capability-v1`

- A positive label means the sample implements the technique-specific behavior
  under a statically supported interpretation. It does not mean execution occurred
  or the sample is malicious. Cite code/evidence locations in the rationale.
- Language/extension, an import, a string mention or a comment alone is not enough.
  For interpreter sub-techniques, require an explicit interpreter invocation or
  code-evaluation/command-execution behavior—not just source language membership.
- `Get-Process` in operative code can support process enumeration (T1057); it does
  not automatically add T1059.001. `Invoke-Expression` on external data can support
  interpreter execution; `eval` in operative JavaScript can support T1059.007.
  Distinguish calls from examples/comments and specify feasibility constraints.
- Negative means reviewed absence within the explicitly documented analysis scope.
  Packed, encrypted, incomplete or unanalyzable portions are **unknown**, not negative.
  Unknown techniques are absent from both judgment lists and excluded from scoring.
- Sub-techniques and parents are separate judgments; no automatic credit or expansion.
- Static capability and runtime observation need separate datasets/labels. Neither
  should be used as a proxy for maliciousness or malware-family attribution.

This is an explicit project evaluation convention, not a claim that ATT&CK supplies
a unique ground-truth labeling procedure for arbitrary benign source files.

## Reviewed corpus metadata

Keep the existing manifest sample fields (`id`, `path`, `sha256`, `positive`,
`negative`, `rationale`) and add top-level
`"label_policy": "static-behavior-capability-v1"`. Each case additionally needs:

```json
{
  "family": "reviewed-family-or-benign-project-group",
  "first_seen": "2024-01-15",
  "split": "test",
  "provenance": "acquisition source, license/handling permission, date source",
  "reviews": [
    {"annotator": "reviewer-a", "positive": ["T1057"], "negative": ["T1486"]},
    {"annotator": "reviewer-b", "positive": ["T1057"], "negative": ["T1486"]}
  ]
}
```

Reviews should be authored without seeing current model predictions. Disagreements
need a separate `adjudication` object with a third identified `annotator` and
`rationale`; never resolve by copying mapper output. Hash-pin the final manifest
before running the held-out evaluation. Record genuine acquisition/first-seen
provenance rather than using repository download dates as malware first-seen dates.

```bash
sandworm audit-corpus /path/to/manifest.json /tmp/corpus-review.json
sandworm benchmark /path/to/manifest.json --split test --out /tmp/test-results
```

The auditor checks sample hashes, duplicate IDs/hashes, two distinct declared
reviewers, adjudication, split membership, family/project disjointness and strict
date ordering across train/validation/test. Held-out evaluation requires a passing
audit and at least 100 dated test cases. This threshold prevents a tiny fixture set
being passed off as a scaled evaluation; it is **not** a statistical sufficiency
guarantee. Hundreds of cases, diverse negative controls, enough positive/negative
claims per technique, and held-out family/time variation remain necessary.

The checker cannot verify that named reviewers are independent humans or that
family labels/dates/judgments are correct. No independent labeled malware corpus
or second annotator has been supplied, so no such result is claimed or fabricated.
