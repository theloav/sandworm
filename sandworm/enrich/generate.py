"""Synthetic adversarial sample generation (benign, semantics-preserving).

Produces byte-different *variants* of a benign sample for detection engineering:
feed 10/100/1000 variants to the current YARA/Sigma and see which slip through,
or feed them to the rule optimiser (#9) as a malicious-shaped corpus. The point is
to stress-test detection robustness without handling real malware.

Hard safety rule: this **never adds capability**. It only perturbs the *surface*
of an already-benign artifact — whitespace/comment noise, consistent identifier
renaming, and rotation of embedded indicators to reserved, non-routable values
(`.test`/`.invalid` domains, `198.51.100.0/24` TEST-NET IPs). The tokens that
drive detection (execution sinks, the SANDWORM marker) are preserved, so a variant
still reaches the *same* ATT&CK techniques — that is how we verify the label held.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass

from ..core.sample import Sample

_RESERVED_TLDS = (".test", ".invalid", ".example")
# Tokens we must never rename/mangle — they are what the detection keys on.
_PRESERVE = re.compile(r"\$_(?:GET|POST|REQUEST|SERVER|FILES|COOKIE|SESSION|ENV)")
_DOMAIN = re.compile(rb"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|top|info|biz|xyz|id)\b", re.I)
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Variant:
    name: str
    data: bytes
    mutations: list[str]


def _dga(seed: str, rng: random.Random) -> str:
    label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(8, 14)))
    return label + rng.choice(_RESERVED_TLDS)


def _rotate_iocs(data: bytes, rng: random.Random) -> tuple[bytes, int]:
    n = 0

    def _dom(m: re.Match) -> bytes:
        nonlocal n
        n += 1
        return _dga(m.group(0).decode("latin-1"), rng).encode()

    def _ip(m: re.Match) -> bytes:
        nonlocal n
        n += 1
        return f"198.51.100.{rng.randint(1, 254)}".encode()  # TEST-NET-2, non-routable

    data = _DOMAIN.sub(_dom, data)
    data = _IPV4.sub(_ip, data)
    return data, n


def _rename_identifiers(text: str, rng: random.Random) -> tuple[str, int]:
    # Rename PHP locals ($x), never superglobals or sink names.
    names = {m.group(0) for m in re.finditer(r"\$[a-zA-Z_]\w*", text) if not _PRESERVE.match(m.group(0))}
    n = 0
    for name in sorted(names, key=len, reverse=True):
        alias = "$v" + hashlib.sha1(f"{name}{rng.random()}".encode()).hexdigest()[:6]
        text, c = re.subn(re.escape(name) + r"\b", alias, text)
        n += 1 if c else 0
    return text, n


def _inject_noise(text: str, rng: random.Random) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    n = 0
    for ln in lines:
        out.append(ln)
        if rng.random() < 0.15 and not ln.strip().startswith(("#", "//", "<?")):
            out.append("  \n" if rng.random() < 0.5 else f"// {_token(rng)}\n")
            n += 1
    return "".join(out), n


def _token(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(4, 10)))


def _is_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return b"\x00" not in data[:512]
    except UnicodeDecodeError:
        return False


_COMMENT = {"sh": "#", "py": "#", "rb": "#", "pl": "#", "php": "//", "js": "//", "ts": "//", "go": "//"}


def generate_variants(sample: Sample, count: int = 10, *, seed: int = 0) -> list[Variant]:
    """Return ``count`` benign, semantics-preserving variants of ``sample``.

    Every variant is guaranteed distinct (a unique inert tail is always appended)
    and label-preserving (the tokens detection keys on are never touched)."""
    base = sample.data
    stem, _, ext = sample.name.rpartition(".")
    ext = (ext or "bin").lower()
    variants: list[Variant] = []
    for i in range(count):
        rng = random.Random(f"{seed}-{i}")
        muts: list[str] = []
        data = base
        if _is_text(data):
            text = data.decode("utf-8")
            text, rn = _rename_identifiers(text, rng)
            if rn:
                muts.append(f"renamed {rn} identifier(s)")
            text, nn = _inject_noise(text, rng)
            if nn:
                muts.append(f"injected {nn} noise line(s)")
            data = text.encode()
        data, ion = _rotate_iocs(data, rng)
        if ion:
            muts.append(f"rotated {ion} indicator(s) to reserved ranges")
        # Always append a unique inert tail so no two variants collide. For text we
        # use the language's comment syntax; for binaries, an inert overlay.
        tag = f"SANDWORM-VARIANT-{i:03d}-{_token(rng)}"
        if _is_text(data):
            data = data + f"\n{_COMMENT.get(ext, '#')} {tag}\n".encode()
            muts.append("appended inert comment tail")
        else:
            data = data + b"\x00" + tag.encode()
            muts.append("appended inert overlay")
        variants.append(Variant(name=f"{stem or sample.name}.var{i:03d}.{ext}", data=data, mutations=muts))
    return variants


def label_preserved(sample: Sample, variant: Sample) -> bool:
    """True if the variant still reaches at least the base sample's techniques —
    the check that a surface mutation did not change what the sample *is*."""
    from ..core.pipeline import analyze_sample

    base_tids = {m.technique_id for m in analyze_sample(sample, enable_dynamic=False).mappings}
    var_tids = {m.technique_id for m in analyze_sample(variant, enable_dynamic=False).mappings}
    return base_tids.issubset(var_tids)
