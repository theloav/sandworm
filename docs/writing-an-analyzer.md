# Writing an analyzer (the plugin SDK)

An analyzer is the only way to *produce* evidence in SANDWORM. The contract is
small and is the entire extensibility story — new formats and capabilities are
plugins, not core changes.

## The contract

```python
from typing import Protocol
from sandworm.core.evidence import EvidenceItem
from sandworm.core.sample import Sample
from sandworm.analyzers.base import Context

class Analyzer(Protocol):
    name: str                    # unique, e.g. "static.php" or "plugin.wallet"
    handles: set[str]            # format tags claimed, e.g. {"php"} or {"*"} for all
    requires_isolation: bool     # True => dynamic lane, only runs behind the gate
    def analyze(self, sample: Sample, ctx: Context) -> list[EvidenceItem]: ...
```

Rules:

* **Only write `EvidenceItem`s.** Never call another analyzer; never reach the
  network; never write the sample to an executable path.
* **`confidence` is required** on every item (0–1).
* Set `requires_isolation = True` if you execute/detonate the sample — the registry
  and the isolation gate will keep you out unless isolation is verified.

## Easiest path: subclass `BaseAnalyzer`

`BaseAnalyzer` handles audit logging and crash isolation; you implement `run`:

```python
from sandworm.analyzers.base import BaseAnalyzer

class WalletAnalyzer(BaseAnalyzer):
    name = "plugin.wallet"
    handles = {"*"}
    requires_isolation = False

    def run(self, sample, ctx):
        items = []
        if b"bc1" in sample.data:
            items.append(ctx.ev(
                source="plugin.wallet", artifact="string", operation="read",
                object={"kind": "btc_wallet"},
                details={"ioc": True, "false_positive_risk": "medium"},
                confidence=0.5,
            ))
        return items

ANALYZER = WalletAnalyzer()        # the registry auto-discovers this
```

`ctx.ev(**kwargs)` stamps the current `run_id` and returns a validated
`EvidenceItem`.

## Registering

* **Built-in**: add a `register(registry)` function in your module and wire it in
  `analyzers/registry.py::register_builtins`.
* **Plugin** (no core changes): expose a top-level `ANALYZER` instance *or* a
  `register(registry)` hook, drop the file in a directory, and run:

```bash
sandworm plugins --dir path/to/plugins
```

## Choosing fields (quick reference)

| Field | Use |
|-------|-----|
| `source` | `"<lane>.<format>"`, e.g. `static.elf`, `dynamic.php`, `memory.vol3` |
| `artifact` | `process` / `file` / `registry` / `network` / `api_call` / `string` / `module` / `macro` / `thread` / `callback` |
| `operation` | `create` / `write` / `read` / `connect` / `inject` / `spawn` / `decode` / `resolve` / `exec` |
| `subject` | who acted (process name/pid, or `{"analyzer": self.name}`) |
| `object` | what was acted on (path/key/host/sink/...) |
| `details` | free-form; put the **why** and `false_positive_risk` here |
| `confidence` | calibrated 0–1 (see `interpreting-confidence.md`) |
| `evidence_refs` | pointers to raw artifacts (`sample:<sha>`, `layer:N`, log offsets) |

The ATT&CK mapper, graph, detections and copilot all read these fields, so naming
your `object` keys conventionally (`sink`, `host`, `path`, `key`, `import`) makes
your evidence light up the rest of the pipeline for free.
