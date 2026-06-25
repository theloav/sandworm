"""Format-agnostic static evidence: strings, entropy, IOC extraction, YARA scan.

Runs on EVERY sample (including unknown/generic ones) so nothing yields zero
evidence. Each IOC carries a confidence and a false-positive-risk note, because a
URL in a config file is not the same signal as a URL in a decoded payload.
"""

from __future__ import annotations

import math
import re

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")

# IOC patterns. fp_risk is a qualitative false-positive risk for the IOC type.
_IOC_PATTERNS = {
    "url": (re.compile(r"\bhttps?://[^\s'\"<>)]+", re.IGNORECASE), 0.7, "low"),
    "domain": (
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE),
        0.45,
        "high",  # bare domains match many benign strings (e.g. example.com, *.dll-ish)
    ),
    "ipv4": (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        0.6,
        "medium",
    ),
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.6, "medium"),
    "md5": (re.compile(r"\b[a-fA-F0-9]{32}\b"), 0.4, "high"),
    "sha256": (re.compile(r"\b[a-fA-F0-9]{64}\b"), 0.5, "medium"),
}

# Domains we never want to surface as malicious IOCs.
_DOMAIN_ALLOWLIST = {"example.com", "example.org", "localhost", "schemas.microsoft.com", "w3.org"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    return [m.group().decode("ascii", "replace") for m in _ASCII_RE.finditer(data) if len(m.group()) >= min_len]


def extract_iocs(text: str) -> list[tuple[str, str, float, str]]:
    """Return (kind, value, confidence, fp_risk)."""
    out: list[tuple[str, str, float, str]] = []
    seen: set[tuple[str, str]] = set()
    # collect URLs/domains first to suppress domain duplicates of URL hosts
    url_hosts: set[str] = set()
    for m in _IOC_PATTERNS["url"][0].finditer(text):
        try:
            host = re.sub(r"^https?://", "", m.group(), flags=re.I).split("/")[0].split(":")[0]
            url_hosts.add(host.lower())
        except Exception:
            pass
    for kind, (pat, conf, fp) in _IOC_PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group()
            if kind == "domain":
                if val.lower() in _DOMAIN_ALLOWLIST or val.lower() in url_hosts:
                    continue
                # require a plausible TLD shape, skip things like file.dll
                if val.lower().endswith((".dll", ".exe", ".php", ".js", ".sys", ".so")):
                    continue
            key = (kind, val)
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, val, conf, fp))
    return out


# Minimal bundled YARA-style heuristics used when the real `yara` module is
# absent. Each is (rule_name, [substrings], confidence).
_BUNDLED_HEURISTICS = [
    ("webshell_eval_base64", [b"eval(", b"base64_decode"], 0.7),
    ("powershell_encoded", [b"-enc", b"FromBase64String"], 0.65),
    ("reverse_shell_sh", [b"/dev/tcp/"], 0.75),
    ("download_exec", [b"curl", b"| sh"], 0.5),
]


def yara_scan(data: bytes) -> list[tuple[str, float]]:
    """Try real YARA with bundled rules; fall back to substring heuristics."""
    hits: list[tuple[str, float]] = []
    try:  # pragma: no cover - optional dependency
        from importlib.resources import files

        import yara  # type: ignore

        rules_path = files("sandworm").joinpath("..", "docker", "rules.yar")
        if rules_path.is_file():
            rules = yara.compile(filepath=str(rules_path))
            for m in rules.match(data=data):
                hits.append((m.rule, 0.7))
            return hits
    except Exception:
        pass
    low = data.lower()
    for name, subs, conf in _BUNDLED_HEURISTICS:
        if all(s.lower() in low for s in subs):
            hits.append((name, conf))
    return hits


class CommonAnalyzer(BaseAnalyzer):
    name = "static.common"
    handles = {"*"}  # runs on everything
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []
        data = sample.data

        ent = shannon_entropy(data)
        items.append(
            ctx.ev(
                source="static.common",
                artifact="file",
                operation="read",
                subject={"analyzer": self.name},
                object={"name": sample.name, "sha256": sample.sha256},
                details={
                    "size": sample.size,
                    "entropy": round(ent, 3),
                    "high_entropy": ent > 7.2,
                    "note": "high overall entropy suggests packing/encryption" if ent > 7.2 else "",
                },
                confidence=0.6 if ent > 7.2 else 0.4,
                evidence_refs=[ref],
            )
        )

        strings = extract_strings(data)
        text_for_ioc = sample.text if sample.size < 5_000_000 else "\n".join(strings)
        for kind, val, conf, fp in extract_iocs(text_for_ioc):
            items.append(
                ctx.ev(
                    source="static.common",
                    artifact="network" if kind in {"url", "domain", "ipv4"} else "string",
                    operation="resolve",
                    subject={"analyzer": self.name},
                    object={"kind": kind, "value": val},
                    details={"ioc": True, "false_positive_risk": fp},
                    confidence=conf,
                    evidence_refs=[ref],
                )
            )

        for rule, conf in yara_scan(data):
            items.append(
                ctx.ev(
                    source="static.common",
                    artifact="string",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"yara_rule": rule},
                    details={"engine": "yara-or-heuristic"},
                    confidence=conf,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(CommonAnalyzer())
