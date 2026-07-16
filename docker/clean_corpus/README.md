# Clean corpus (goodware)

Drop **real benign binaries** here — system DLLs/EXEs, popular open-source tools,
common documents/scripts. Every YARA rule SANDWORM generates is tested against
every file in this directory (recursively) and any rule that matches goodware is
**pruned or dropped** before it ships. This is what makes generated rules
deployable rather than merely "clean-looking" against the seven bundled snippets.

## How it is used

- `sandworm analyze <sample>` loads this directory automatically and folds it
  into the YARA clean-test (`load_clean_corpus()` → `generate_yara(..., clean_corpus=...)`).
- `sandworm optimize-rules <malicious_dir> --clean <extra_dir>` also honours it.

## Guidance

- More and more *representative* goodware = stronger false-positive suppression.
- Files are read up to an 8 MB cap each, up to 500 files, so a large corpus stays
  memory-bounded. Candidate rule strings cluster in headers/resources, which fall
  well inside that cap.
- Organise however you like; subdirectories are scanned recursively.

## Not in git

Real goodware is large and often redistribution-restricted, so the contents of
this directory are `.gitignore`d — only this README is tracked. Populate it in
your own environment (e.g. copy from `C:\Windows\System32\*.dll`, `/usr/bin/*`,
or a curated goodware set).
"""
