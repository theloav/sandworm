# Threat model

SANDWORM handles live malware. This document states what we defend, what we assume,
and where the load-bearing controls live in code.

## Assets to protect

1. **The analyst host / network** — must never be reached by a sample.
2. **Other samples & the evidence store** — integrity and non-execution.
3. **The analyst LLM copilot** — must not be hijacked by sample-controlled text.

## Adversary capabilities (the sample)

* Arbitrary native/script execution *if detonated*.
* Network egress attempts (C2, exfil, propagation).
* Persistence attempts (registry, cron, services).
* Environment-aware dormancy / anti-analysis.
* **Prompt injection** via strings, file paths, or decoded payloads aimed at the
  copilot.

## Controls (enforced in code)

| Threat | Control | Where |
|--------|---------|-------|
| Sample reaches a real host | Controller never executes samples; live submission requires an explicitly attested external backend and network policy | `sandbox/base.py`, `sandbox/cape.py`, `tests/test_sandbox_backend.py` |
| Accidental execution from disk | AES-encrypted, non-executable archive entry; storage fails closed without AES support | `core/sample.py`, `tests/test_sample_store_aes.py` |
| Silent/unaudited actions | JSONL audit log of every analyzer action and (refused) detonation | `core/audit.py` |
| Propagation / persistence on host | Execution-capable analyzers are not registered in-process; backend jobs are released even after collection failure | `analyzers/registry.py`, `core/pipeline.py` |
| Prompt injection of the copilot | Sanitize + delimiter-defang all sample-controlled text; copilot answers only from retrieved subgraph and abstains otherwise | `copilot/sanitize.py`, `copilot/graphrag.py`, `tests/test_copilot_grounding.py` |
| Analyzer crash takes down a run | Analyzers are sandboxed in `BaseAnalyzer.analyze`; errors are audited, not fatal | `analyzers/base.py` |

## Trust boundaries

```
[ controller ] ── submit ──▶ [ external sandbox backend ] ──▶ [ disposable VM ]
      ▲                              │                              │
      └──── hashed artifact bundle ◀─┴──────────────────────────────┘
      │
      └── EvidenceStore / report (normalization and read-only consumption)
```

* Static producers write only `EvidenceItem`s and do not execute samples.
* Dynamic backends return content-hashed artifacts bound to the submitted hash.
* Consumers read only from the store — they never invoke analyzers or touch the
  sample bytes directly.

## Explicit non-goals (v1)

* We do not build hypervisor instrumentation; we integrate CAPE/DRAKVUF.
* `SANDWORM_CAPE_ISOLATION_VERIFIED` is deployment attestation supplied by the
  operator; SANDWORM cannot prove a remote hypervisor's containment from inside
  the controller.
* We do not guarantee detection of VM-aware malware that fully no-ops; the
  differential lane (`enrich/differential.py`) only *surfaces* such behavior.
