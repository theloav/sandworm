# Handling real samples — set up isolation BEFORE you touch live malware

> If you have not read [`threat-model.md`](threat-model.md), read it first.

SANDWORM ships safe-by-default: detonation is **off** and the dynamic lane will
**refuse to run** until isolation is verified in code. Do not disable these checks.

## 1. Build an isolated detonation environment

Use the provided compose stack as a starting point:

```bash
cd docker && docker compose up -d        # detonation containers + FakeNet responder
```

The detonation environment MUST:

* be **ephemeral** (destroyed and recreated per run);
* have **no route to any real network** — only to the simulated responder
  (`SANDWORM_SIMNET_HOST`, default `10.0.0.1`);
* set the **isolation marker** env var inside the image:
  `SANDWORM_ISOLATED=1` (this is what `verify_isolation()` checks);
* run as an unprivileged user with a read-only host mount of the sample only.

For Windows PE, point the CAPE/DRAKVUF adapter at your existing sandbox instance
(`analyzers/dynamic/windows_cape.py`) — SANDWORM integrates it, it does not rebuild
hypervisor instrumentation.

## 2. Verify the gate refuses on a non-isolated host

On your normal workstation (no marker, real network reachable):

```bash
sandworm analyze suspicious.exe        # detonation refused, IsolationError audited,
                                        # static-only analysis completes
grep detonation_refused .sandworm/audit.jsonl
```

This is the expected, safe behavior. Dynamic analysis only happens inside the
verified environment.

## 3. Store samples defanged at rest

```python
from sandworm.core.sample import Sample, SampleStore
SampleStore().store(Sample.from_path("suspicious.exe"))   # → .sandworm/samples/<sha256>.zip
```

* Stored as a password-protected archive (`SANDWORM_SAMPLE_PASSWORD`, default
  `infected`) with a non-executable `.bin` inner name.
* **For real engagements, replace the stdlib ZIP with AES** (`pyzipper`/7z): the
  stdlib store is a *defang*, not strong crypto.
* Never commit real samples to the repo. `samples/` holds only benign synthetics.

## 4. Operational rules

* One sample per ephemeral environment; tear down after each run.
* Treat all decoded payloads and extracted strings as hostile *data*, never as
  commands — the copilot already does (`copilot/sanitize.py`).
* Review `audit.jsonl` after every engagement.
