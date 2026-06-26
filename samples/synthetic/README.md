# Synthetic benign samples

These ship with SANDWORM so **every pipeline path demos end-to-end with zero real
malware on disk**. Each is harmless and self-contained; none contacts a real host
(any "beacon" targets the simulated-network address `10.0.0.1`).

| File | Format lane | Demonstrates |
|------|-------------|--------------|
| `benign_webshell.php` | `static.php` | 3-layer `eval(base64_decode(gzinflate(base64_decode(...))))` unwrap → `system($_REQUEST['cmd'])` sink → web-shell verdict (T1027/T1140/T1059/T1505.003). |
| `benign_dropper.sh`   | `static.script` (+ gated `dynamic.script`) | `curl \| sh` download-exec, marker-file drop, sim-net beacon. |
| `benign_macro.doc`    | `static.office` | AutoOpen/Document_Open VBA, `Shell` sink, marker write. Synthetic OLE stand-in (see note in file). |
| `benign_elf.c`        | `static.elf` (+ gated `dynamic.linux`) | Source + build note: opens a marker file and `connect()`s to the sim network. |
| `loader_demo.exe` + `recorded_cape_report.json` + `recorded_vol3_report.json` | `dynamic.windows.cape` / `memory.vol3` (offline replay) | Bound demo of the dynamic + memory lanes: an injection-loader's recorded CAPE/vol3 run upgrading techniques inferred → observed. |

Run the flagship demo:

```bash
sandworm analyze samples/synthetic/benign_webshell.php
```

Demo the dynamic + memory lanes via offline replay (ingests prior evidence — not a
live detonation):

```bash
sandworm analyze samples/synthetic/loader_demo.exe \
  --cape-report   samples/synthetic/recorded_cape_report.json \
  --memory-report samples/synthetic/recorded_vol3_report.json
```

The recorded reports are **bound by `target_sha256`** to `loader_demo.exe` — the
binary they were captured from. SANDWORM refuses to fold them into any other
sample (even another PE): a recorded run is only a file's behaviour if it was
captured *from that file*, so pointing these at, say, a real WannaCry sample is
refused and that sample is analysed static-only rather than absorbing the loader's
process tree / injection / C2.

All four are intentionally crude/obvious — they exercise the engine, they are not
realistic adversary tradecraft. The marker string `SANDWORM-MARKER` makes it easy
to confirm a payload was reached.
