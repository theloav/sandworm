# `samples/` — handling policy

**No real malware is ever committed to this repository.** Only the benign
synthetic samples under `samples/synthetic/` live here in plaintext.

## Encrypted-at-rest policy (enforced in code)

Real samples handled by an operator are **defanged at rest**:

* Stored only as password-protected archives via `core/sample.py::SampleStore`
  (default password `infected`, configurable via `SANDWORM_SAMPLE_PASSWORD`).
* Written with a non-executable `.bin` inner name, never to a shared executable
  path.
* Loaded into the detonation environment **explicitly** — importing a sample
  never executes it.

> The stdlib ZIP store is a *defanging* measure, not strong crypto. For real
> engagements swap in AES (`pyzipper`/7z) — see `docs/handling-real-samples.md`.

## Before you touch a live sample

Read `docs/handling-real-samples.md` and `docs/threat-model.md`. Dynamic analysis
will **refuse to run** unless `core/isolation.py` can verify network isolation.
