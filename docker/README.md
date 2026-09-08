# `docker/` — development support only

This Compose stack starts a simulated-network responder for harmless integration
fixtures. It is **not a malware containment boundary** and SANDWORM will not
execute samples in these containers.

Use a separately managed CAPE deployment for Windows dynamic analysis. A future
Linux backend should use disposable microVMs with an attested image, explicit
network policy, artifact collection, and guaranteed teardown.

```bash
docker compose up -d simnet
docker compose down -v
```

`rules.yar` is the bundled static-analysis ruleset used when the `yara` Python
module is installed.
