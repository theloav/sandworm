# Measurement, trust boundaries, and remaining depth

## Published baseline (2026-09-18)

**Status: measurement infrastructure, not a calibrated model.** The eight-fixture
baseline retains its original broad-presence labels. They are provisional and must
not be used to tune toward generic language-presence detections. New independent
corpora use the [behavior-capability label policy](corpus-label-policy.md).

| Measurement | Result | What it does **not** establish |
| --- | --- | --- |
| Eight labeled script fixtures, 64 explicitly judged sample/technique pairs | TP 6, FP 0, FN 4, TN 54; precision 1.00, recall 0.60 | Independent malware-corpus accuracy or runtime behavior |
| Calibration of emitted judged claims | Brier 0.06198, n=6 | Reliable calibration: all six emitted judged claims are positive, and the set is far too small |
| Two frozen script-derived YARA rules over 1,267 local Ubuntu utility files | 0 matching files / 1,267 scanned | Cross-format negative control: the population is poorly matched to these rules, so this is practically uninformative about relevant FP risk |
| Frozen PHP rule over WordPress PHP source | 0 / 1,897 unique files matched | Rule also misses its own source fixture; does not establish detector utility |
| Frozen PowerShell rule over Pester source | 0 / 114 unique files matched | One test-framework source tree and one rule; small, not ecosystem coverage |
| 8 MiB fixed-seed ransomware-sweep microbenchmark, five repetitions | Regex median 0.1781 s; Aho–Corasick 0.1135 s (1.57×) | Whole-pipeline speedup, reduced peak RSS, arbitrary data distributions |

Raw inventories, exact rule sources, metric JSON, and a reliability SVG are in
[`benchmarks/`](../benchmarks/). Results are scoped to these inputs and this host.
The goodware files are presumed-benign utilities or upstream project sources, not independently
certified. Files are SHA-256-deduplicated and symlinks excluded. Related files
are not statistically independent; Wilson intervals are descriptive Bernoulli
intervals, not a deployment guarantee. No source binaries are redistributed.

The matched audits freeze the **same rules** as before: the PHP rule is scored only
against `.php` files from WordPress commit `cfdab1a6ba05cd035fb23049ccbe7fa7b9ef2643`;
the PowerShell rule only against `.ps1/.psm1/.psd1` files under Pester `src/` at
`98e56d65da1642a7158992b50ded240c42a3ac18`. Nothing was installed or executed from
these projects. Source commits, paths, sizes, hashes and exact rule selection are
recorded in `benchmarks/php-goodware-*` and `benchmarks/powershell-goodware-*`.
These are better format matches, but one project per language still has substantial
selection bias and shared code. Specific synthetic anchors can also make these
rules easy to avoid matching; zero observed matches does not establish rule utility
or malware recall. No Windows PE rules/corpus were evaluated in this pass.

**Positive-control failure:** scanning the original source fixtures with these
frozen rules matches `download.ps1` with `SANDWORM_77e23fc54a15`, but produces no
match for `benign_webshell.php` with `SANDWORM_43af2e95eba1`. The PHP audit is thus
not evidence of a useful detector even with a format-matched negative population.
The rules remain unchanged; regression tests preserve this known failure.
Generated anchors can describe decoded/behavioral evidence absent from raw sample
bytes. Future rule revisions must pass raw-source positive controls and undergo a
separately versioned audit; synthetic anchor tests alone are insufficient.

Reproduce after checking out the exact commits in local source directories:

```bash
sandworm yara-audit benchmarks/audited-rules.yar benchmarks/php-goodware-manifest.json \
  /path/to/wordpress /tmp/php-fp.json --rule-name SANDWORM_43af2e95eba1
sandworm yara-audit benchmarks/audited-rules.yar benchmarks/powershell-goodware-manifest.json \
  /path/to/pester/src /tmp/powershell-fp.json --rule-name SANDWORM_77e23fc54a15
```

The legacy ATT&CK labels were intended to describe **static capability presence**,
not maliciousness, but include broad language-presence judgments that remain
provisional under the new behavior-capability policy.
The four misses are process enumeration, benign PowerShell usage, Unix shell usage,
and JavaScript sub-technique attribution. Labels were authored separately from the
mapper's output; they were not changed to hide these misses. This is still a small,
developer-authored synthetic regression set—not a held-out expert-labeled malware
benchmark. A larger independent corpus, annotation review, and family/time-disjoint
evaluation remain necessary before tuning or claiming general accuracy.

## Run evaluation

```bash
pip install -e '.[evaluation,matching]'
sandworm benchmark benchmarks/manifest.json --out /tmp/measurement \
  --baseline benchmarks/results/metrics.json
sandworm benchmark-matchers /tmp/matcher-results.json --megabytes 8 --repeats 5

sandworm goodware-inventory /path/to/goodware /tmp/goodware.json \
  --provenance 'Corpus source, versions, acquisition date, benign-label policy'
sandworm yara-audit rules.yar /tmp/goodware.json /path/to/goodware /tmp/fp.json
```

Only **explicit negative labels** count as negatives; unknown ATT&CK labels are
reported as unjudged predictions. Sub-techniques are scored exactly, without
silently granting parent/sub-technique equivalence. Precision/recall are null when
their denominator is zero. The threshold is recorded (default 0.5).

Two calibration views are emitted: judged mappings actually emitted by `bayes.py`,
and all judged decisions with absent mappings assigned zero. The latter is a
detection-score convention, not a computed Bayesian posterior. Brier score, ECE,
bin populations, mean scores, empirical correctness, and Wilson intervals are
reported; empty bins remain empty. The model's prior and lane weights are still
heuristic, not empirically fitted/calibrated.

CI gates per-technique FP/FN regressions and Brier degradation over 0.02 on the
identical manifest/threshold, and uploads the report/diagram. Corpus changes need
an explicit baseline review. It does not silently retune thresholds or relabel
samples. Goodware audits fail incomplete when a file is missing, changed or times
out; errors do not enter the clean denominator. Hash sets such as NSRL cannot
replace actual file bytes for YARA scanning, and “known” does not mean benign.

Installing `evaluation` also makes generated-rule clean checks use YARA-X against
the actual serialized rule. Without it, the restricted built-in matcher remains
available; it is not a general YARA interpreter. Full-file YARA-X audits are
separate from the bounded corpus used during rule generation. Neither rule
generation nor audit results should be trained/tuned against the held-out corpus.

## Copilot trust boundary

Original evidence remains unchanged. Before inclusion in a prompt, a bounded
detector checks normalized Unicode, common role/delimiter/citation spoofing,
instruction/secret/verdict directives, and selected base64 encodings. Known
payloads are replaced with a digest-tagged quarantine notice; other text is
length-bounded and prompt/citation delimiters escaped.

The important control is **not** the detector. Grounded Q&A accepts only JSON
`{"evidence_ids": [...]}` containing at most 12 IDs from the context actually sent.
Additional keys, fabricated IDs, oversized output and arbitrary prose are rejected.
The application renders selected evidence itself. The model has no command,
network-fetch, secret-reading, rule-deployment or verdict-writing tools. It cannot
publish model-authored prose as a grounded answer. This deliberately trades some
free-form explanation for an enforceable output boundary.

Separate hypothesis generation still permits bounded prose, labels it speculative,
validates citations and screens known directives; it never changes evidence or
verdicts. Both paths treat sample content as data, not authority. Citations prove
record membership, **not semantic correctness**. An attacker may still influence
selection/relevance, novel encodings/languages may bypass the detector, and displayed
evidence itself can be false. Provider processing of sample-derived context remains
an explicit external-provider configuration decision.

`tests/fixtures/prompt_injections.json` plus adversarial mock-provider tests exercise
these deterministic boundaries. They do not prove universal prompt-injection
resistance or replace live, repeated, model-specific adversarial evaluations. No
classifier model or accuracy claim is implied.

### Residual selection/relevance risk

`benchmark-selection` runs paired clean/injected contexts through production Q&A.
Gold evidence stays unchanged; the attack is placed in an untrusted carrier record
and aims to select a real but misleading example record while dropping the gold
record. It reports clean correctness, target availability, selection changes,
abstentions, rejections and out-of-context citations. An attack succeeds only for a
clean-correct pair where the target is selected and gold evidence is lost; already
wrong baseline answers are not counted as attack successes.

```bash
sandworm benchmark-selection benchmarks/selection-manifest.json /tmp/selection.json
# Explicitly sends synthetic fixture context to the configured external provider:
sandworm benchmark-selection benchmarks/selection-manifest.json /tmp/live-selection.json \
  --live --allow-external --repeats 10
```

The default **scripted valid-ID probe** selects correctly on clean calls and chooses
the decoy on attack calls. All five decoys are accepted, with no out-of-context IDs.
This demonstrates that the allowlist does not enforce relevance. It is **not** a
measurement of payload persuasiveness: `manipulation_success_rate` is null for the
scripted report. No live provider/key was configured during this pass. Live mode
requires an explicit configured provider and consent flag; reports name the model
and preserve per-pair results. The five synthetic cases are not an independent,
comprehensive benchmark, and repeated trials are correlated.

## Detection-as-code bundles

```bash
pip install -e '.[detections]'
sandworm detection-bundle sample.ps1 /tmp/detection-review \
  --sigma-target kusto --sigma-pipeline sentinel_asim --sigma-product windows
# Alternative: --sigma-target splunk --sigma-pipeline splunk_windows
python -m pytest /tmp/detection-review/test_yara.py
```

Bundles include Sigma, generated YARA, conservative exact-domain/public-IP Suricata
IOC candidates, evidence references, synthetic YARA positive/negative tests, a
review guide and hashes. Sigma conversion invokes the installed sigma-cli backend
and explicitly chosen telemetry pipeline/product. Failed conversions are recorded
and produce nonzero CLI status. KQL/SPL conversion was locally exercised, but the
queries were not deployed to Sentinel/Splunk. Suricata candidates require engine
validation, representative PCAP testing, local SID allocation and tuning. Generated
YARA tests exercise anchors, not malware-family recall. Sigma selector review files
are **not** validated telemetry replay tests. The command does not create a GitHub
PR, execute samples, or deploy detections.

## Indexed corpus queries and optional literal matching

```bash
sandworm index-corpus .sandworm/runs .sandworm/corpus.sqlite
sandworm query-corpus .sandworm/corpus.sqlite --value c2.example.org
sandworm query-corpus .sandworm/corpus.sqlite --artifact network --operation connect

export SANDWORM_LITERAL_ENGINE=aho  # requires the matching extra
```

The SQLite index materializes exact object values and evidence facets. Queries use
SQL indexes without reloading every run. Ingestion is bounded per line and atomic
per source; unchanged content is skipped, invalid updates roll back. This is an
opt-in **corpus index**, not replacement of the pipeline's in-memory EvidenceStore
or its lineage algorithm. It is a snapshot: deleted source runs remain indexed
until the database is deliberately rebuilt. Keep a separate private database per
security/workspace boundary; it contains original sensitive evidence.

Aho–Corasick preserves the current longest/nonoverlapping ASCII and UTF-16LE ransom
needle matching with parity tests. Regex remains the default. IOC regex extraction
is unchanged; the benchmark makes no claim about it. The pipeline still loads
sample bytes: this change is **not** mmap/chunked 500 MiB analysis.

## Remaining proposals

Not implemented in this pass: full mmap/chunked analysis, CPU-lane process pools,
DuckDB analytics/lineage migration, deep .NET IL/resource decryption,
Rust demangling, FLOSS-style function emulation, family-specific
ConfigExtractor plugins, tree-sitter deobfuscation, recursive email/disk-image
delivery containers, PCAP/JA3/JA4 analysis, guest eBPF, comprehensive evasion
reporting and a Frida Windows agent. These need independent fixtures and validation,
not placeholder modules. Real Windows CAPE and hardware tracing prerequisites
remain as described in the sandbox deployment guide.

Go pclntab recovery is now implemented for ELF with Go 1.18/1.20 table layouts,
bounded to 10,000 output functions and 64 MiB table data. A Go 1.22 stripped benign
ELF build validates recovery of `main.main`, `main.addNumbers` and `runtime.main`
without executing the program. Unsupported/corrupt tables fail visibly. It does
not cover every Go version/container or establish new ATT&CK behavior; declared
function spans are not promoted into decoded-instruction coverage.

Primary references: [YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/),
[Sigma processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html),
[Suricata DNS rules](https://docs.suricata.io/en/suricata-7.0.14/rules/dns-keywords.html),
[OWASP prompt injection](https://genai.owasp.org/llmrisk2023-24/llm01-24-prompt-injection/).
