# Setup

## Requirements

* Python 3.11+
* (optional) access to a separately managed CAPE v2 deployment

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Optional backend extras (each degrades gracefully if absent):

```bash
pip install -e ".[static]"   # lief, pefile, pyelftools, capstone, oletools
pip install -e ".[graph]"    # neo4j driver
pip install -e ".[memory]"   # volatility3
pip install -e ".[llm]"      # anthropic / openai SDKs
pip install -e ".[secure]"   # AES-256 sample storage (--store)
pip install -e ".[emulate]"  # bounded CPU emulation for unpacking
```

## First run (no real malware needed)

```bash
sandworm analyze samples/synthetic/benign_webshell.php
open .sandworm/runs/<run_id>/report.html
```

## Configuration (env vars)

| Variable | Default | Meaning |
|----------|---------|---------|
| `SANDWORM_WORK_DIR` | `.sandworm` | runs, samples, audit log |
| `SANDWORM_CAPE_URL` | unset | CAPE v2 base URL ending in `/apiv2/` |
| `SANDWORM_CAPE_TOKEN` | unset | scoped CAPE API token |
| `SANDWORM_CAPE_IMAGE_ID` | unset | immutable analysis-image identifier |
| `SANDWORM_CAPE_ISOLATION_VERIFIED` | `false` | operator attestation after containment validation |
| `SANDWORM_CAPE_ALLOW_HTTP` | `false` | explicitly permit plaintext HTTP in a closed lab |
| `SANDWORM_CAPE_SIMULATED_ROUTE` | unset | CAPE route name for INetSim/FakeNet-style networking |
| `SANDWORM_SAMPLE_PASSWORD` | `infected` | encrypted-at-rest archive password |
| `SANDWORM_NEO4J_URI` | unset | enable Neo4j graph (else in-memory) |
| `SANDWORM_LLM_PROVIDER` | `mock` | `mock` / `anthropic` / `openai` |
| `SANDWORM_LLM_MODEL` | `claude-opus-4-8` | model id for the copilot |

See `.env.example`. The default is static-only; no backend means no sample
execution.

## Quality gate

```bash
ruff check sandworm tests plugins_example
mypy sandworm
pytest
```

## Build distributable packages

```bash
pip install build
python -m build
pip install dist/sandworm-0.2.0-py3-none-any.whl
sandworm --help
```

The wheel provides the CLI, browser workspace/API, HTML report renderer, and
guest provisioning code. `pip install '.[full]'` installs all Python extras;
QEMU, Ghidra, Java and a CAPE deployment remain external tools/infrastructure.
The source distribution also includes deployment assets, documentation and the
benign demonstration corpus. See `docs/platform.md` and `docs/sandbox-deployment.md`.
