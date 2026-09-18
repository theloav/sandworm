# Advanced analysis workflows

## Decompilation and data-flow inspection

Install [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and its
required JDK; set `GHIDRA_HOME`. Sandworm's Java exporter was exercised against
Ghidra 12.1.3 with the bundled benign ELF. It exports up to 256 functions,
decompiled C, instruction locations, flow targets, unresolved/computed-flow flags
and p-code. This is Ghidra integration, not a new decompiler or complete symbolic
execution engine.

```bash
sandworm decompile samples/benign/greet --out decompiled.json
sandworm analyze samples/benign/greet --decompiler-report decompiled.json
```

The JSON is bound to the sample hash. Decoded ranges can participate in runtime
address correlation. A static profile with `options.decompile: "true"` also
enables Ghidra in queued workers. Ghidra is not downloaded automatically at runtime.

## Memory images

```bash
pip install -e '.[memory]'
sandworm memory-analyze sample.exe captured-memory.raw --platform windows \
  --symbols /path/to/offline-symbols --out memory-report.json
sandworm analyze sample.exe --memory-report memory-report.json
```

Use `--platform linux` for a Linux capture. The operator must associate the image
with the actual sample it came from. Sandworm records that association, invokes
bounded Volatility plugins offline, flattens nested rows, and reports partial
plugin failures. Supplying a sample hash does not independently prove how an
arbitrary memory image was acquired. Guest capture and kernel-symbol compatibility
must be validated on your deployment. To process QEMU dumps automatically, set
`capture_memory: true`, `options.memory_platform: "linux"`, and `options.symbols`
to a host directory with matching offline symbols.

## Runtime traces, canaries and differential behavior

`sandworm analyze sample --runtime-report runtime.json` accepts this schema:

```json
{
  "schema_version": 1,
  "target_sha256": "64-hex-character sample digest",
  "traces": [{"kind": "linux", "text": "42 openat(AT_FDCWD, \"/tmp/example\", O_RDONLY) = 3"}],
  "cpu_trace": [],
  "baseline_processes": [],
  "post_processes": [],
  "canaries": []
}
```

Trace kinds: `linux` for strace, `php` for JSONL function/argument events, `shell`
for shell xtrace. CPU trace rows require a `location` conforming to
`EvidenceLocation` plus optional PID/target. Supply module identity/load base when
available; foreign modules or undecoded gaps do not become function matches.
Raw Intel PT packet decoding is not implemented.

QEMU's canary profile injects fake credentials/history tokens into the disposable
guest and checks captured evidence for matching tokens. Token presence is an
indicator to investigate, not automatic proof of exfiltration. Baseline/post
process lists produce differential process evidence.

```bash
sandworm differential sample.sh --profiles linux-baseline,linux-canaries --out comparison.json
```

Profiles must exist in `SANDWORM_PROFILES`. A failed backend aborts comparison.
Differences can reflect noise/nondeterminism; validate them before attributing
environment-sensitive malware behavior.

## Offline intelligence

```json
{
  "schema_version": 1,
  "source": "internal-intelligence-snapshot",
  "created_at": "2026-09-17T00:00:00Z",
  "indicators": [{"kind": "domain", "value": "indicator.example", "confidence": 0.7, "labels": ["investigate"]}]
}
```

Use `sandworm analyze sample --intelligence snapshot.json`. Matching findings cite
the original evidence, snapshot source and age. Snapshots older than 90 days are
marked stale and discounted. There are no implicit external enrichment requests.

## Clustering and speculative hypotheses

```bash
sandworm cluster --distance 0.3 --out clusters.json
sandworm hypotheses RUN_ID
```

Clustering uses Weisfeiler–Lehman graph-neighborhood features with cosine DBSCAN.
It returns groups and outliers, not trained malware-family predictions. It is
bounded to 2,000 persisted CLI runs. A GNN training pipeline and validated labeled
family model are not included.

Hypotheses require a configured LLM provider capable of structured JSON. They are
kept separate from evidence/verdicts, labeled speculative, and must cite existing
evidence IDs. Invalid/uncited outputs are rejected. The offline mock does not
pretend to generate LLM hypotheses.

## Emulation and additional formats

Unicorn supports bounded models of VirtualAlloc/VirtualProtect (and Ex variants),
memory copy/set, Sleep and ExitProcess. Unknown imports stop execution; no host OS,
filesystem or network operations are forwarded. Modified executable memory ranges
are recovered separately, including allocated buffers. This is a limited model,
not complete Windows emulation or a guarantee of unpacking every packer.

JAR/APK analysis inventories bounded archive members and extracts Java constant
pool / DEX strings and selected API references. It does not validate signatures,
fully decode Android binary XML, decompile Java/Dalvik methods or run Android apps.
Mach-O analysis inventories thin/universal slices, segments, dependencies and
entry commands. UEFI analysis validates volume bounds/checksums and inventories
FFS files; it does not establish firmware authenticity, decompress every module,
emulate SMM or prove bootkit infection.
