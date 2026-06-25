<div align="center">

<img src="assets/banner.png" alt="SANDWORM — AI-Powered Malware Analysis & Reverse Engineering Platform" width="820"/>

<br/>

![tests](https://img.shields.io/badge/tests-76%20passing-2ea043)
![lint](https://img.shields.io/badge/ruff%20%2B%20mypy-clean-2ea043)
![python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![license](https://img.shields.io/badge/license-MIT-blue)
![offline](https://img.shields.io/badge/runs-fully%20offline-7ee787)

### Given a sample, reconstruct what happened, explain why, and emit detections.

</div>

SANDWORM is an isolated, multi-format malware reverse-engineering platform. It is
*not* "another sandbox": every subsystem exists to serve one promise — take a
sample, reconstruct its lifecycle from static, dynamic, and memory evidence, and
produce explainable attack narratives, behavioral graphs, and defender-ready
detections (YARA + Sigma).

It handles **PE/DLL, ELF (C/Rust/Go), PHP webshells, scripts
(PowerShell/JS/shell), and Office macros** through a pluggable analyzer
architecture — new formats are plugins, not core changes.

Every conclusion is **traceable to evidence**, labeled **observed vs inferred**,
explained through a **reasoning chain**, and turned into **actionable detections** —
which makes SANDWORM an explainable malware-reasoning platform rather than a
collection of parsers.

```bash
pip install -e ".[dev]"
sandworm analyze samples/synthetic/benign_webshell.php
# → recursively-deobfuscated payload, behavioral graph, ATT&CK mappings (each with
#   a confidence and a "why"), clean-tested YARA + Sigma, and a coverage score.
sandworm ask "what execution sinks were found?"      # graph-grounded copilot
sandworm plugins --dir plugins_example               # list analyzers + plugins

# Dynamic + memory lanes via offline replay of recorded reports (no live
# detonation — ingests prior evidence, so it runs without the isolation gate and
# upgrades the matching ATT&CK techniques from inferred → observed):
sandworm analyze samples/synthetic/benign_dropper.sh \
  --cape-report samples/synthetic/recorded_cape_report.json \
  --memory-report samples/synthetic/recorded_vol3_report.json
```

## The architectural spine: an Evidence Layer

Every engine emits **one** normalized schema — the `EvidenceItem` — instead of
talking to each other. Producers (analyzers) only *write* EvidenceItems; consumers
(behavioral graph, timeline, ATT&CK mapper, detection generators, LLM copilot)
only *read* from the store. This decoupling is what makes SANDWORM extensible and
explainable. `confidence` (0–1) is **required on every item**.

```
sample ─▶ triage ─▶ analyzers ─┐
                                ├─▶ EvidenceStore ─▶ graph / timeline / ATT&CK ─▶ report
   (static always; dynamic ────┘                 └─▶ YARA + Sigma + coverage
    only behind the isolation gate)              └─▶ copilot (graph-grounded)
```

## Isolation & safe handling (enforced in code, not docs)

* **Isolation gate** (`core/isolation.py`): dynamic analysis runs *only* inside a
  verified, network-isolated, ephemeral detonation environment with all egress
  routed to a simulated responder (INetSim/FakeNet). If isolation can't be
  verified, SANDWORM **refuses to detonate**, logs an `IsolationError`, and falls
  back to static-only. (See `tests/test_isolation_gate.py`.)
* **Defanged at rest** (`core/sample.py`): samples are stored only as
  password-protected archives, never written executable to a shared path; loading
  never auto-executes.
* **Benign synthetic samples by default** (`samples/synthetic/`): the whole
  pipeline demos end-to-end with zero real malware on disk.
* **Audit log** (`core/audit.py`): every analyzer action and every (refused)
  detonation is appended to a JSONL audit log.
* **No real-network C2, no persistence, no propagation.** SANDWORM observes and
  reports; it never reaches a real host and never acts on what it discovers.

Full detail: [`docs/threat-model.md`](docs/threat-model.md),
[`docs/handling-real-samples.md`](docs/handling-real-samples.md).

## The PHP lane (the differentiator)

`analyzers/static/php.py` statically *evaluates* (never executes) the classic
webshell stack — nested `eval`/`assert` around `base64_decode`, `gzinflate`,
`gzuncompress`, `str_rot13`, `strrev`, `hex2bin`/`pack`, and `chr()` chains —
peeling one layer at a time, emitting each as evidence, and flagging the dangerous
sink in the recovered payload (`system`/`exec`/`passthru`/`shell_exec`/`proc_open`,
`preg_replace /e`, variable-function calls).

## The plugin SDK

A new analyzer is one file implementing the `Analyzer` protocol
(`name`, `handles`, `requires_isolation`, `analyze(sample, ctx) -> [EvidenceItem]`):

```python
from sandworm.analyzers.base import BaseAnalyzer
class MyAnalyzer(BaseAnalyzer):
    name = "plugin.my"; handles = {"php"}; requires_isolation = False
    def run(self, sample, ctx): return [ctx.ev(source="plugin.my", artifact="string",
        operation="read", object={"hello": "world"}, confidence=0.5)]
ANALYZER = MyAnalyzer()
```

Drop it in a directory, `sandworm plugins --dir <dir>`. No core changes. See
[`docs/writing-an-analyzer.md`](docs/writing-an-analyzer.md) and
[`plugins_example/`](plugins_example/example_analyzer.py).

## Tech stack

Python 3.11+, pydantic v2, typer, jinja2. Optional, gracefully-degrading backends:
lief/pefile/pyelftools/capstone + capa (static), oletools (macros), CAPE/DRAKVUF
adapter (Windows dynamic), locked-down containers (Linux/script/PHP dynamic),
volatility3 (memory), neo4j (graph; in-memory fallback), and a provider-agnostic
LLM copilot (Anthropic / OpenAI-compatible / offline `mock` default).

## Status — what's deferred to v2 (honest list)

* Hypervisor-level instrumentation / Intel-PT tracing (we *integrate* CAPE/DRAKVUF,
  we don't build hypervisor instrumentation).
* Firmware / SMM / bootkit analysis.
* GNN graph embeddings & ML-based family clustering (today's graph is rule-built).
* OS coverage beyond Windows + Linux (Mach-O is recognized but routed to a "not yet
  supported" notice; full PS/JS dynamic interpreters need their container images).
* Strong sample-at-rest crypto (the stdlib ZIP store is a *defang*, not AES — swap
  in pyzipper/7z for engagements).
* Real `auto_prepend`/seccomp builtin interception images for the dynamic lanes
  (the adapters define the contract; the container images are an ops task).

## Development

```bash
pip install -e ".[dev]"
ruff check sandworm tests && mypy sandworm && pytest
```

CI (`.github/workflows/ci.yml`) runs ruff + mypy + pytest fully offline, no secrets.
