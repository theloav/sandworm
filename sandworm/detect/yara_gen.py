"""Generate YARA rules from static + behavioral evidence — clean-tested.

Every generated rule is auto-tested against a bundled clean corpus; any rule that
matches a benign document is DROPPED (it would false-positive). We keep a tiny
internal rule representation so the clean test runs offline without the `yara`
binary, and also serialize to real YARA text for operators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore
from ..core.sample import Sample

# A small bundled clean corpus — representative benign content the rules must NOT
# hit. Extend with real goodware in docker/clean_corpus/ for production tuning.
CLEAN_CORPUS: list[bytes] = [
    b"<?php echo 'Hello, world'; phpinfo(); ?>",
    b"#!/bin/bash\necho 'backup complete'\nrsync -a /src /dst\n",
    b"function add(a, b){ return a + b; } console.log(add(1,2));",
    b"Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
    b"The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet.",
    b"import os\nprint(os.getcwd())\n",
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
]

# Strings too generic to ever anchor a rule (would match goodware).
_STOPWORDS = {
    "eval", "system", "exec", "echo", "print", "function", "http", "https",
    "true", "false", "null", "get", "post", "open", "read", "write", "shell",
}


@dataclass
class YaraRule:
    name: str
    strings: list[bytes]
    condition_min: int  # "N of them"
    meta: dict = field(default_factory=dict)

    def matches(self, data: bytes) -> bool:
        hits = sum(1 for s in self.strings if s and s in data)
        return hits >= self.condition_min

    def to_yara(self) -> str:
        lines = [f"rule {self.name}", "{", "    meta:"]
        for k, v in self.meta.items():
            lines.append(f'        {k} = "{str(v)[:120]}"')
        lines.append("    strings:")
        for i, s in enumerate(self.strings):
            try:
                printable = s.decode("ascii")
                if printable.isprintable():
                    esc = printable.replace("\\", "\\\\").replace('"', '\\"')
                    lines.append(f'        $s{i} = "{esc}"')
                    continue
            except Exception:
                pass
            hexs = " ".join(f"{b:02x}" for b in s)
            lines.append(f"        $s{i} = {{ {hexs} }}")
        lines.append("    condition:")
        lines.append(f"        {self.condition_min} of them")
        lines.append("}")
        return "\n".join(lines)


def _candidate_strings(store: EvidenceStore, sample: Sample) -> list[bytes]:
    cands: set[bytes] = set()
    for it in store:
        # decoded payload fragments are high-signal anchors
        prev = it.details.get("decoded_preview") or it.details.get("final_payload_preview")
        if prev:
            for tok in re.findall(r"[A-Za-z0-9_./\\$()=:-]{8,40}", prev):
                if tok.lower() not in _STOPWORDS and not tok.isdigit():
                    cands.add(tok.encode())
        # sink+context combos
        sink = it.object.get("sink")
        if sink and isinstance(sink, str) and len(sink) >= 6 and sink.lower() not in _STOPWORDS:
            cands.add(sink.encode())
        # IOC values
        val = it.object.get("value")
        if val and isinstance(val, str) and len(val) >= 8:
            cands.add(val.encode())
        yr = it.object.get("yara_rule")
        if yr:
            cands.add(str(yr).encode())
    # Distinctive raw-sample tokens as a last resort.
    if len(cands) < 2:
        for tok in re.findall(rb"[A-Za-z0-9_]{12,40}", sample.data)[:10]:
            cands.add(tok)
    # prefer longer, more specific strings
    ordered = sorted(cands, key=lambda b: (-len(b), b))
    return ordered[:12]


def generate_yara(store: EvidenceStore, sample: Sample, *, clean_corpus: list[bytes] | None = None) -> list[YaraRule]:
    corpus = (clean_corpus or []) + CLEAN_CORPUS
    candidates = _candidate_strings(store, sample)
    if not candidates:
        return []

    rule = YaraRule(
        name=f"SANDWORM_{sample.sha256[:12]}",
        strings=candidates,
        condition_min=min(2, len(candidates)),
        meta={
            "author": "SANDWORM",
            "sample_sha256": sample.sha256,
            "description": "auto-generated from static+behavioral evidence",
        },
    )

    # Self-tighten: if the rule hits the clean corpus, prune the offending strings
    # and raise the threshold until it is clean or we give up.
    cleaned = _make_clean(rule, corpus)
    if cleaned is None:
        return []
    return [cleaned]


def _make_clean(rule: YaraRule, corpus: list[bytes]) -> YaraRule | None:
    # Drop any individual string that appears in clean corpus (too generic).
    kept = [s for s in rule.strings if not any(s in doc for doc in corpus)]
    if len(kept) < 1:
        return None
    rule.strings = kept
    rule.condition_min = min(rule.condition_min, len(kept))
    # Verify the whole rule no longer matches any clean doc; raise threshold if needed.
    while any(rule.matches(doc) for doc in corpus) and rule.condition_min < len(kept):
        rule.condition_min += 1
    if any(rule.matches(doc) for doc in corpus):
        return None
    return rule


def passes_clean_corpus(rules: list[YaraRule], corpus: list[bytes] | None = None) -> bool:
    corpus = (corpus or []) + CLEAN_CORPUS
    return all(not r.matches(doc) for r in rules for doc in corpus)
