# Benign sample set (false-positive tests)

Real, harmless programs used to verify SANDWORM does **not** flag legitimate
software. A good analyzer must keep false positives low — these should all come
back **Low risk / no clear malicious capability**.

| Sample | Format | What it is |
|---|---|---|
| `greet` (+ `greet.c`) | ELF | Real compiled executable: prints a greeting + the time. No network/exec/persistence. |
| `wordcount` (+ `wordcount.c`) | ELF | Real compiled executable: counts lines/words/chars from stdin (a tiny `wc`). |
| `contact_form.php` | PHP | Legitimate contact-form page: validates input, escapes output, **no** command/code-exec sinks or obfuscation. |

The two ELF binaries are committed with their C source so they are fully
transparent and reproducible (`gcc -O2 -o greet greet.c`).

```bash
sandworm analyze samples/benign/greet            # → risk Low, score 0/100
sandworm analyze samples/benign/contact_form.php # → risk Low (legit PHP, not a web shell)
```

> Note on Windows PE: a real benign `.exe` isn't committed here because building
> one needs a Windows cross-compiler (not assumed offline) and shipping a
> third-party vendor binary is poor practice. SANDWORM handles real PEs fine —
> e.g. analyzing a stock `notepad.exe`/`calc.exe` returns **Low risk** — the
> committed ELF + PHP samples cover the same false-positive check reproducibly.
