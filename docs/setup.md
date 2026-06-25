# Setup

## Requirements

* Python 3.11+
* (optional) Docker, for the isolated detonation environments + FakeNet/INetSim

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
pip install -e ".[web]"      # fastapi + uvicorn (optional UI)
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
| `SANDWORM_ALLOW_DETONATION` | `false` | operator opt-in for the dynamic lane |
| `SANDWORM_ISOLATED` | unset | isolation marker set *inside* the detonation env |
| `SANDWORM_SIMNET_HOST` | `10.0.0.1` | simulated-network responder address |
| `SANDWORM_SAMPLE_PASSWORD` | `infected` | encrypted-at-rest archive password |
| `SANDWORM_NEO4J_URI` | unset | enable Neo4j graph (else in-memory) |
| `SANDWORM_LLM_PROVIDER` | `mock` | `mock` / `anthropic` / `openai` |
| `SANDWORM_LLM_MODEL` | `claude-opus-4-8` | model id for the copilot |

See `.env.example`. The defaults are **safe**: detonation is off and the simulated
network is assumed, so a fresh checkout cannot reach a real host.

## Quality gate

```bash
ruff check sandworm tests plugins_example
mypy sandworm
pytest
```
