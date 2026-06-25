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

Run the flagship demo:

```bash
sandworm analyze samples/synthetic/benign_webshell.php
```

All four are intentionally crude/obvious — they exercise the engine, they are not
realistic adversary tradecraft. The marker string `SANDWORM-MARKER` makes it easy
to confirm a payload was reached.
