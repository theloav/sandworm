# Handling real samples

> Read [`threat-model.md`](threat-model.md) first. Do not run live malware with
> the development Docker stack.

SANDWORM's controller never launches submitted bytes. Static analyzers run in
the controller today; live execution is available only through a configured
`SandboxBackend`. With no backend, `sandworm analyze` is static-only.

## Windows: configure a separate CAPE deployment

The CAPE deployment and its analysis VMs are external to this repository. Build,
isolate, snapshot, and validate them independently, then configure SANDWORM:

```bash
export SANDWORM_CAPE_URL=https://cape.internal/apiv2/
export SANDWORM_CAPE_TOKEN=replace-with-a-scoped-token
export SANDWORM_CAPE_IMAGE_ID=win11-clean@sha256:replace-with-image-digest
export SANDWORM_CAPE_ISOLATION_VERIFIED=true

# Optional: only when this CAPE route points to INetSim/FakeNet and has no
# forwarding path to production or the public internet.
export SANDWORM_CAPE_SIMULATED_ROUTE=inetsim

sandworm analyze suspicious.exe --backend cape --sandbox-network disabled
```

`SANDWORM_CAPE_ISOLATION_VERIFIED=true` is an operator attestation, not an
automatic security test. Before setting it, verify at minimum:

- the guest is reverted from a known snapshot for each task;
- the analysis network cannot route to the analyst host or production networks;
- `disabled` truly has no guest egress;
- the simulated route terminates only at the responder;
- the controller token cannot administer CAPE;
- the configured image identifier uniquely identifies the guest build;
- escape, host-write, persistence, and egress tests pass.

Plain HTTP is rejected by default. An isolated lab can opt in with
`SANDWORM_CAPE_ALLOW_HTTP=true`, but HTTPS is recommended even on internal
networks because samples and reports cross this connection.

## Offline replay

Previously captured reports can be normalized without contacting a sandbox or
executing the sample:

```bash
sandworm analyze suspicious.exe \
  --cape-report report.json \
  --memory-report volatility.json
```

Each report must identify the source sample with `target_sha256`; a native CAPE
report's `target.file.sha256` is also accepted. Mismatched or unbound reports are
refused.

For static-to-runtime function correlation, retain CAPE's native
`behavior.processes[].calls[]` records. Sandworm consumes the call's `caller`,
`thread_id`, and `id` together with the process `module_path` and load base
(`image_base`, `module_base`, or `environ.DllBase`). ASLR addresses are rebased to
RVAs and only linked when the module hash/name identifies the analyzed sample and
the RVA falls inside a statically decoded instruction range. Reports lacking
those address fields still ingest normally; they simply do not claim a function
correlation.

## Sample storage

Install the secure extra before using `--store`:

```bash
pip install -e ".[secure]"
sandworm analyze suspicious.exe --no-dynamic --store
```

The store fails closed if AES support is unavailable. It never falls back to a
plaintext ZIP. Never commit real samples or collected sandbox artifacts.

## Operational rules

- One sample per disposable guest lifecycle.
- Keep the controller and artifact store outside the detonation network.
- Treat reports, filenames, decoded payloads, PCAPs, and memory images as hostile.
- Retain the audit log and content hashes with the engagement record.
- Use harmless instrumented fixtures for containment tests; do not validate
  containment by intentionally releasing real malware.
