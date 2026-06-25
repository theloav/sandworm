# `docker/` — isolated detonation environments

`docker-compose.yml` brings up:

* **`simnet`** — a simulated-network responder (INetSim/FakeNet-style) at
  `10.0.0.1`. All sample egress is answered here; nothing reaches a real host.
* **`php_runner` / `linux_runner`** — locked-down, **internal-network-only**
  detonation containers carrying the `SANDWORM_ISOLATED=1` marker that
  `core/isolation.py` verifies before allowing any detonation.

```bash
docker compose up -d        # start the isolated lab
docker compose down -v      # tear down (do this per run — environments are ephemeral)
```

The `internal: true` network is the load-bearing control: it removes any route to
a real network. Replace the placeholder runner images with hardened images
(read-only rootfs, dropped capabilities, seccomp) for production use, and point the
Windows lane at your existing CAPE/DRAKVUF instance.

`rules.yar` is the bundled YARA ruleset used by the common static analyzer when the
`yara` Python module is installed.

> Read `../docs/handling-real-samples.md` before detonating anything real.
