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
# UTF-16LE ("wide") strings — how Windows binaries store most of their text
# (URLs, registry keys, commands, ransom notes). ASCII-only extraction misses
# all of them, which blinds IOC extraction and the ransomware heuristics on PEs.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

# IOC patterns. fp_risk is a qualitative false-positive risk for the IOC type.
_IOC_PATTERNS = {
    # URL: restrict to URL-valid characters so a match in a binary stops at the
    # first non-URL byte (NUL / 0xFFFD replacement char) instead of swallowing
    # trailing garbage (e.g. the WannaCry killswitch URL grabbing mojibake).
    "url": (re.compile(r"\bhttps?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"), 0.7, "low"),
    "domain": (
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE),
        0.45,
        "high",  # bare domains match many benign strings (e.g. example.com, *.dll-ish)
    ),
    "ipv4": (
        # Lookarounds reject ASN.1 OID fragments (`1.3.6.1`, `2.5.4.102`) and the
        # middles of longer dotted-number runs — those are NOT IP addresses.
        re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
        0.6,
        "medium",
    ),
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.6, "medium"),
    # Hashes: real ones from tooling are lowercase hex AND contain at least one
    # a-f letter. This rejects 32/64-digit decimal numbers and uppercase table
    # data (`28421709...`, `B10B11B12...`) that are not hashes.
    "md5": (re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{32}\b"), 0.4, "high"),
    "sha256": (re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{64}\b"), 0.5, "medium"),
}

# Domains we never want to surface as malicious IOCs.
_DOMAIN_ALLOWLIST = {"example.com", "example.org", "localhost", "schemas.microsoft.com", "w3.org"}

# Benign toolchain / SDK / hosting domains that legitimately appear compiled into
# binaries (Go modules, package registries). These are real domains but are
# *library artifacts*, not C2 — surfaced separately, never as network IOCs.
_LIBRARY_DOMAINS = frozenset(
    """
    golang.org go.dev pkg.go.dev gopkg.in google.com googleapis.com gstatic.com
    github.com githubusercontent.com gitlab.com bitbucket.org sourceforge.net
    microsoft.com windows.com live.com office.com msftncsi.com
    cloudflare.com amazonaws.com azure.com digicert.com verisign.com sectigo.com
    letsencrypt.org mozilla.org apache.org python.org rust-lang.org crates.io
    npmjs.com nodejs.org openssl.org curl.se zlib.net intel.com
    """.split()
)

# Go standard-library / runtime package names. Go binaries embed thousands of
# `package.Symbol` / `package.Type.Method` strings whose tail matches a real TLD
# (`runtime.name`, `reflect.name`, `idna.info`, `hash.net`). If the leading label
# is one of these, the "domain" is a Go symbol, not a host.
_STDLIB_PKGS = frozenset(
    """
    runtime reflect reflectlite unicode sync atomic hash rand asn1 pkix big idna
    service syscall math time sort bytes strings strconv errors fmt os io bufio
    net http tls x509 json xml base64 hex gzip zlib flate tar zip regexp bits
    cpu poll unix windows itab go type internal context crypto cipher elliptic
    sha256 sha512 md5 hmac rsa ecdsa ed25519 pem utf8 utf16 url cookiejar textproto
    """.split()
)


def _registrable(domain: str) -> str:
    """Best-effort registrable domain (last two labels)."""
    labels = domain.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def classify_domain(val: str) -> str:
    """Classify a candidate domain: 'drop' (noise), 'library' (benign toolchain),
    or 'ioc' (treat as a real network indicator)."""
    labels = val.split(".")
    # Canonical hostnames are case-insensitive but effectively lowercase; an
    # uppercase letter signals a code symbol (pkix.Name, reflect.Value.Int).
    if any(c.isupper() for c in val):
        return "drop"
    if labels[-1].lower() not in _COMMON_TLDS:
        return "drop"
    # Leading label is a Go stdlib/runtime package -> it's a symbol, not a host.
    if labels[0] in _STDLIB_PKGS or (len(labels) >= 2 and labels[-2] in _STDLIB_PKGS):
        return "drop"
    # Second-level label must be >=3 chars (kills `<stray>.<ccTLD>` fragments).
    if len(labels[-2]) < 3:
        return "drop"
    if val.lower() in _DOMAIN_ALLOWLIST:
        return "drop"
    if _registrable(val) in _LIBRARY_DOMAINS or val.lower() in _LIBRARY_DOMAINS:
        return "library"
    return "ioc"


def _valid_url(url: str) -> bool:
    """A URL is only an IOC if its host is a real hostname (has a dot + known TLD)
    or an IP. Rejects binary garbage like `https://L)` / `https://H`."""
    host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split("?")[0].split(":")[0]
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return True
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1].lower()
    return tld in _COMMON_TLDS and classify_domain(host) != "drop"

# Real public TLDs. The bare-domain regex otherwise matches JavaScript member
# access (`document.getElementById`, `a.onclick`), object paths (`d.msg`), and
# filenames (`payload.jpg`) — all of which flood the IOC list with garbage and
# poison the generated C2 detections. Requiring a known TLD removes that noise
# while keeping real domains (`evil.id`, `c2.example.ru`). Extend as needed.
_COMMON_TLDS = frozenset(
    """
    com net org info biz xyz top site online club shop store app dev page link live
    icu rest pro mobi asia name ws cc tv me io co gg sh ai dev cloud space website tech
    us uk ca au de fr nl ru cn jp kr in br id my sg ph th vn tw hk it es se no fi pl
    ua tr ir ng za mx ar cl pe pt gr cz ro hu be at ch dk ie il sa ae kz by md
    tk ml ga cf gq su pw cyou
    gov edu mil int
    """.split()
)


def shannon_entropy(data: bytes) -> float:
    """Entropy is the hottest loop in the pipeline (whole file + every 4KB
    unpack block + every PE section), so byte counting uses numpy when it is
    installed (~20x on multi-MB samples) and Counter's C helper otherwise."""
    if not data:
        return 0.0
    n = len(data)
    try:  # pragma: no cover - optional dependency
        import numpy as np

        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        p = counts[counts > 0] / n
        return float(-(p * np.log2(p)).sum())
    except ImportError:
        pass
    from collections import Counter

    ent = 0.0
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    return [m.group().decode("ascii", "replace") for m in _ASCII_RE.finditer(data) if len(m.group()) >= min_len]


def extract_wide_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable UTF-16LE strings (Windows wide strings)."""
    out: list[str] = []
    for m in _WIDE_RE.finditer(data):
        s = m.group().decode("utf-16-le", "replace")
        if len(s) >= min_len:
            out.append(s)
    return out


def extract_all_strings(data: bytes, min_len: int = 4) -> list[str]:
    """ASCII + UTF-16LE strings, ASCII first. This is what IOC extraction and
    YARA candidate mining should consume for binary formats."""
    return extract_strings(data, min_len) + extract_wide_strings(data, min_len)


def _is_routable_ipv4(val: str) -> bool:
    """Reject version-number / bogon / reserved IPv4 that masquerade as IOCs
    (e.g. ``6.0.0.0`` is a version string, not a C2). Only public-looking
    addresses survive."""
    try:
        octets = [int(x) for x in val.split(".")]
    except ValueError:
        return False
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return False
    a, b, c, d = octets
    # x.0.0.0 / x.255.255.255 look like version strings or broadcast, not hosts
    if (b, c, d) in {(0, 0, 0), (255, 255, 255)}:
        return False
    # Standard ASN.1 OID root arcs (`1.2.*`, `1.3.*`, `2.5.*`, `2.16.*`, `0.*`)
    # are pervasive in crypto/x509 code and are NOT IP addresses.
    if (a, b) in {(1, 2), (1, 3), (2, 5), (2, 16)} or a == 0:
        return False
    if a in (0, 10, 127) or a >= 224:  # this-net, RFC1918-10, loopback, multicast/reserved
        return False
    if a == 169 and b == 254:  # link-local
        return False
    if a == 172 and 16 <= b <= 31:  # RFC1918-172
        return False
    if a == 192 and b == 168:  # RFC1918-192
        return False
    return True


def extract_iocs(text: str) -> list[tuple[str, str, float, str]]:
    """Return (kind, value, confidence, fp_risk) — network/host IOCs only.

    Library/toolchain artifacts (golang.org, github.com, …) and noise (Go symbol
    paths, ASN.1 OIDs, non-hashes) are filtered out here; use
    :func:`extract_iocs_classified` if you also want the library artifacts.
    """
    return [(k, v, c, f) for k, v, c, f, cat in extract_iocs_classified(text) if cat == "ioc"]


def extract_iocs_classified(text: str) -> list[tuple[str, str, float, str, str]]:
    """Like :func:`extract_iocs` but each item carries a category:
    'ioc' (real network indicator) or 'library' (benign toolchain artifact)."""
    out: list[tuple[str, str, float, str, str]] = []
    seen: set[tuple[str, str]] = set()
    # collect URLs/domains first to suppress domain duplicates of URL hosts
    url_hosts: set[str] = set()
    for m in _IOC_PATTERNS["url"][0].finditer(text):
        if _valid_url(m.group()):
            host = re.sub(r"^https?://", "", m.group(), flags=re.I).split("/")[0].split(":")[0]
            url_hosts.add(host.lower())
    for kind, (pat, conf, fp) in _IOC_PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group()
            category = "ioc"
            if kind == "url" and not _valid_url(val):
                continue
            if kind == "domain":
                if val.lower() in url_hosts:
                    continue  # already covered by the URL
                category = classify_domain(val)
                if category == "drop":
                    continue
            if kind == "ipv4" and not _is_routable_ipv4(val):
                continue
            key = (kind, val)
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, val, conf, fp, category))
    return out


# Minimal bundled YARA-style heuristics used when the real `yara` module is
# absent. Each is (rule_name, [substrings], confidence).
_BUNDLED_HEURISTICS = [
    ("webshell_eval_base64", [b"eval(", b"base64_decode"], 0.7),
    ("powershell_encoded", [b"-enc", b"FromBase64String"], 0.65),
    ("reverse_shell_sh", [b"/dev/tcp/"], 0.75),
    ("download_exec", [b"curl", b"| sh"], 0.5),
]


# Ransomware tells. Shadow-copy / recovery deletion is extremely high-signal
# (almost never in goodware) → Inhibit System Recovery. Ransom-note + crypto
# tooling language → Data Encrypted for Impact. Format-agnostic: works on a PE
# even when the import table is dynamically resolved (as WannaCry's is).
_RECOVERY_INHIBIT = [b"vssadmin", b"wbadmin", b"bcdedit", b"shadowcopy", b"wmic shadow"]

# Ransomware tells, grouped into INDEPENDENT categories. T1486 is only inferred
# when several distinct categories co-occur — a single category (e.g. a `.crypt`
# extension, or a `CryptEncrypt` import) is common in benign software and must
# NOT imply ransomware on its own. Note: the generic word "decrypt" is
# deliberately excluded — every crypto library contains it.
_RANSOM_CATEGORIES: dict[str, list[bytes]] = {
    # near-unique family / ransom-extension / ransom-note markers (one is enough)
    "family": [b".wnry", b".wncry", b"wanacry", b"wncry", b"wanadecryptor", b"@wanadecryptor", b".locky", b".cryptolocker"],
    "note": [
        b"files have been encrypted", b"your files are encrypted", b"your important files",
        b"all your files", b"how to decrypt your", b"how to recover your", b"recover your files",
        b"your documents photos databases",
    ],
    "extension": [b".crypt", b".encrypted", b".crypto", b".locked", b".crypz", b".enc"],
    "payment": [b"bitcoin", b"btc wallet", b"monero", b"ransom", b".onion"],
    "crypto_api": [b"cryptencrypt", b"cryptgenkey", b"cryptderivekey", b"cryptimportkey"],
}


# Reverse map every ransom/recovery needle to its category, then compile ONE
# alternation regex for ASCII and ONE for UTF-16LE. Scanning becomes two
# IGNORECASE passes over the raw bytes — no per-needle loop and no full-file
# `.lower()` copy (which allocated a second 20MB buffer on large samples).
_NEEDLE_CATEGORY: dict[bytes, str] = {}
for _n in _RECOVERY_INHIBIT:
    _NEEDLE_CATEGORY[_n] = "recovery_inhibit"
for _cat, _needles in _RANSOM_CATEGORIES.items():
    for _n in _needles:
        _NEEDLE_CATEGORY[_n] = _cat

# Longest-first alternation so overlapping needles prefer the more specific one.
# All needles are already lowercase, so we scan a single lowercased copy of the
# data WITHOUT re.IGNORECASE — benchmarked ~10x faster than IGNORECASE and faster
# than per-needle substring scans (the `.lower()` copy is a cheap C memcpy).
_ORDERED_NEEDLES = sorted(_NEEDLE_CATEGORY, key=len, reverse=True)
_RANSOM_ASCII_RE = re.compile(b"|".join(re.escape(n) for n in _ORDERED_NEEDLES))
_RANSOM_WIDE_RE = re.compile(b"|".join(re.escape(n.decode().encode("utf-16-le")) for n in _ORDERED_NEEDLES))


def ransomware_scan(data: bytes) -> tuple[list[str], dict[str, list[str]]]:
    """Return (recovery_inhibit_hits, {category: [hits]}) — the recovery hits feed
    T1490 and also count as a ransomware category. Needles are matched in both
    ASCII and UTF-16LE in a single pass each."""
    low = data.lower()
    found: dict[str, set[str]] = {}
    for regex, decode in ((_RANSOM_ASCII_RE, "latin-1"), (_RANSOM_WIDE_RE, "utf-16-le")):
        for m in regex.finditer(low):
            needle = m.group().decode(decode, "replace")
            cat = _NEEDLE_CATEGORY.get(needle.encode())
            if cat:
                found.setdefault(cat, set()).add(needle)
    recovery = sorted(found.get("recovery_inhibit", set()))
    cats: dict[str, list[str]] = {c: sorted(v) for c, v in found.items() if c != "recovery_inhibit"}
    if recovery:
        cats["recovery_inhibit"] = recovery
    if recovery:
        cats["recovery_inhibit"] = recovery
    return recovery, cats


def is_ransomware(cats: dict[str, list[str]]) -> bool:
    """Infer ransomware only when (a) a family/ransom-specific marker is present,
    or (b) at least two INDEPENDENT categories co-occur and at least one is a
    ransomware-defining behaviour (note language, shadow-copy deletion, or an
    extension paired with payment). This rejects a backdoor that merely contains
    crypto routines and a `.crypt`/`.encrypted` string."""
    if cats.get("family"):
        return True
    present = {c for c in cats if cats[c]}
    behavioural = present & {"note", "recovery_inhibit"}
    ext_and_payment = {"extension", "payment"} <= present
    return len(present) >= 2 and (bool(behavioural) or ext_and_payment)


def ransom_indicators(cats: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    for hits in cats.values():
        out.extend(hits)
    return out


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

        # For binary formats, run IOC extraction over the EXTRACTED STRINGS, not a
        # lossy whole-file decode. Strings are split on non-printable bytes, so a
        # URL/domain never bleeds into adjacent binary noise (which is what tacked
        # mojibake onto the WannaCry killswitch URL). Wide (UTF-16LE) strings are
        # included — that is where Windows binaries keep their URLs/registry keys.
        binary_like = (sample.format_hint or "") in {"pe", "dll", "elf", "macho", "office", "generic"}
        if binary_like or sample.size >= 5_000_000:
            text_for_ioc = "\n".join(extract_all_strings(data))
        else:
            text_for_ioc = sample.text
        for kind, val, conf, fp, category in extract_iocs_classified(text_for_ioc):
            if category == "library":
                # Benign toolchain/SDK domain (e.g. golang.org, github.com). Record
                # it as a library artifact, NOT a network IOC — so it never feeds
                # the C2/T1071 mapping or inflates the indicator count.
                items.append(
                    ctx.ev(
                        source="static.common",
                        artifact="string",
                        operation="read",
                        subject={"analyzer": self.name},
                        object={"library_artifact": val, "kind": kind},
                        details={"library_artifact": True, "note": "benign toolchain/SDK reference, not C2"},
                        confidence=0.25,
                        evidence_refs=[ref],
                    )
                )
                continue
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

        # Ransomware heuristics (format-agnostic, intent-level).
        recovery, ransom_cats = ransomware_scan(data)
        if recovery:
            items.append(
                ctx.ev(
                    source="static.common",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"capability": "inhibit_recovery", "indicators": recovery},
                    details={"why": "shadow-copy / backup deletion tooling present (ransomware tell)"},
                    confidence=0.8,
                    evidence_refs=[ref],
                )
            )
        # Infer ransomware only when independent categories co-occur (family marker,
        # or note/recovery + another category). A lone crypto routine or `.crypt`
        # string is NOT enough — that misclassified benign backdoors.
        if is_ransomware(ransom_cats):
            cat_names = sorted(c for c in ransom_cats if ransom_cats[c])
            indicators = ransom_indicators(ransom_cats)
            # confidence scales with the number of independent categories.
            conf = min(0.95, 0.45 + 0.16 * len(cat_names)) if "family" not in ransom_cats else min(0.95, 0.78 + 0.05 * len(cat_names))
            items.append(
                ctx.ev(
                    source="static.common",
                    artifact="file",
                    operation="write",
                    subject={"analyzer": self.name},
                    object={"capability": "ransomware", "indicators": indicators},
                    details={
                        "why": f"independent ransomware categories present: {', '.join(cat_names)}",
                        "categories": cat_names,
                    },
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
