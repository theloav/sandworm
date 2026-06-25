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
| Sample reaches a real host | Isolation gate: verify detonation env is enabled, marked isolated, and has **no** real-network reachability; else refuse + degrade to static | `core/isolation.py`, `tests/test_isolation_gate.py` |
| Accidental execution from disk | Defang at rest: password-protected, non-executable inner name, explicit load | `core/sample.py`, `samples/README.md` |
| Silent/unaudited actions | JSONL audit log of every analyzer action and (refused) detonation | `core/audit.py` |
| Propagation / persistence on host | No detonation outside the ephemeral container/VM; dynamic analyzers gated by the registry **and** the gate | `analyzers/registry.py`, `core/pipeline.py` |
| Prompt injection of the copilot | Sanitize + delimiter-defang all sample-controlled text; copilot answers only from retrieved subgraph and abstains otherwise | `copilot/sanitize.py`, `copilot/graphrag.py`, `tests/test_copilot_grounding.py` |
| Analyzer crash takes down a run | Analyzers are sandboxed in `BaseAnalyzer.analyze`; errors are audited, not fatal | `analyzers/base.py` |

## Trust boundaries

```
[ host ] ── refuses ──▶ [ detonation env: container/VM, no real net ] ──▶ [ FakeNet/INetSim ]
   ▲                                                                       (simulated only)
   └── EvidenceStore / report (read-only consumption of normalized evidence)
```

* Producers (analyzers) write only `EvidenceItem`s.
* Consumers read only from the store — they never invoke analyzers or touch the
  sample bytes directly.

## Explicit non-goals (v1)

* We do not provide strong cryptographic at-rest protection (the ZIP store is a
  defang). Use AES (pyzipper/7z) for engagements.
* We do not build hypervisor instrumentation; we integrate CAPE/DRAKVUF.
* We do not guarantee detection of VM-aware malware that fully no-ops; the
  differential lane (`enrich/differential.py`) only *surfaces* such behavior.
