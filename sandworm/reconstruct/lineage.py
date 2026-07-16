"""Cross-sample behavioural diffing & lineage (offline corpus).

Each sample is analysed in isolation today; SANDWORM keeps no memory of prior
samples. This adds that memory — entirely offline, over the runs already persisted
to the work dir. A sample's behaviour is reduced to a token set (its techniques,
capabilities, execution sinks, family, IOC kinds); we MinHash that set so the
corpus can be queried by approximate Jaccard similarity (LSH-style) without a
database. The result answers the questions a hunter actually asks:

  • "show me samples sharing >80% of this one's behaviour"  (nearest neighbours)
  • "what diverged between these two variants"               (technique/IOC diff)
  • "which sample first introduced this C2 / capability"     (earliest-seen)

The corpus index is a plain JSON file; Neo4j is not required (the graph backend
already degrades to in-memory, and lineage is a consumer of persisted evidence).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..core.evidence import EvidenceStore
from ..core.simhash import minhash_similarity
from ..reconstruct.attack_map import map_evidence

_NUM_PERM = 64
_MAXH = (1 << 32) - 1


def _h(i: int, token: str) -> int:
    return int(hashlib.sha1(f"{i}:{token}".encode()).hexdigest()[:8], 16)


def _minhash(tokens: frozenset[str]) -> tuple[int, ...]:
    if not tokens:
        return tuple([_MAXH] * _NUM_PERM)
    return tuple(min(_h(i, t) for t in tokens) for i in range(_NUM_PERM))


def jaccard(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    """Estimated Jaccard similarity from two MinHash signatures."""
    if not a or not b:
        return 0.0
    return sum(1 for x, y in zip(a, b, strict=True) if x == y) / len(a)


@dataclass
class Signature:
    sha256: str
    name: str
    tokens: frozenset[str]
    minhash: tuple[int, ...]
    techniques: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    created: str = ""
    imphash: str = ""                          # PE import-profile hash (structural pivot)
    file_minhash: tuple[int, ...] = ()         # fuzzy byte-similarity digest

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256, "name": self.name, "tokens": sorted(self.tokens),
            "minhash": list(self.minhash), "techniques": self.techniques,
            "iocs": self.iocs, "created": self.created,
            "imphash": self.imphash, "file_minhash": list(self.file_minhash),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Signature:
        return cls(
            sha256=d["sha256"], name=d.get("name", ""), tokens=frozenset(d.get("tokens", [])),
            minhash=tuple(d.get("minhash", [])), techniques=d.get("techniques", []),
            iocs=d.get("iocs", []), created=d.get("created", ""),
            imphash=d.get("imphash", ""), file_minhash=tuple(d.get("file_minhash", [])),
        )


def behavioral_tokens(store: EvidenceStore, mappings) -> tuple[frozenset[str], list[str], list[str]]:
    """The behaviour-defining token set + the technique and IOC lists used for diffs."""
    techniques = sorted({m.technique_id for m in mappings})
    tokens: set[str] = {f"T:{t}" for t in techniques}
    iocs: list[str] = []
    for it in store:
        o = it.object
        if o.get("capability"):
            tokens.add(f"cap:{o['capability']}")
        if o.get("sink"):
            tokens.add(f"sink:{o['sink']}")
        if o.get("verdict"):
            tokens.add(f"verdict:{o['verdict']}")
        if o.get("imphash"):
            tokens.add(f"imphash:{o['imphash']}")
        if it.details.get("ioc") and (val := o.get("value") or o.get("host")):
            tokens.add(f"ioc:{o.get('kind', 'host')}")
            iocs.append(str(val))
    return frozenset(tokens), techniques, sorted(set(iocs))


def _structural_fingerprints(store: EvidenceStore) -> tuple[str, tuple[int, ...]]:
    """Pull the imphash and file MinHash out of the evidence (emitted by the PE
    and fingerprint analyzers)."""
    imph = ""
    fmh: tuple[int, ...] = ()
    for it in store:
        if it.object.get("imphash"):
            imph = str(it.object["imphash"])
        if it.details.get("file_minhash"):
            fmh = tuple(it.details["file_minhash"])
    return imph, fmh


def signature_of(sha256: str, name: str, store: EvidenceStore, mappings=None, created: str = "") -> Signature:
    mappings = mappings if mappings is not None else map_evidence(store)
    tokens, techniques, iocs = behavioral_tokens(store, mappings)
    imph, fmh = _structural_fingerprints(store)
    return Signature(sha256=sha256, name=name, tokens=tokens, minhash=_minhash(tokens),
                     techniques=techniques, iocs=iocs, created=created,
                     imphash=imph, file_minhash=fmh)


@dataclass
class Neighbour:
    signature: Signature
    similarity: float                 # behavioural (technique/capability/IOC) Jaccard
    byte_similarity: float = 0.0      # fuzzy file-content Jaccard
    same_imphash: bool = False        # identical PE import profile

    @property
    def relation(self) -> str:
        """One-word summary of how this neighbour relates to the target."""
        if self.same_imphash:
            return "same-import-profile"
        if self.byte_similarity >= 0.8:
            return "near-duplicate"
        if self.byte_similarity >= 0.4:
            return "byte-similar"
        return "behaviour-similar"


@dataclass
class LineageDiff:
    shared: list[str]
    only_in_a: list[str]      # techniques in A not B
    only_in_b: list[str]      # techniques in B not A
    ioc_evolution: list[str]  # human notes on IOC/infrastructure change

    def evolution_note(self, a: Signature, b: Signature) -> str:
        parts = []
        if self.only_in_b:
            parts.append(f"{b.name} added {', '.join(self.only_in_b)}")
        if self.only_in_a:
            parts.append(f"{b.name} dropped {', '.join(self.only_in_a)}")
        parts += self.ioc_evolution
        return "; ".join(parts) or "no behavioural divergence"


def _tld(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host and not host.replace(".", "").isdigit() else ""


def diff(a: Signature, b: Signature) -> LineageDiff:
    ta, tb = set(a.techniques), set(b.techniques)
    ioc_notes: list[str] = []
    tlds_a = {_tld(h) for h in a.iocs if _tld(h)}
    tlds_b = {_tld(h) for h in b.iocs if _tld(h)}
    rotated_in = tlds_b - tlds_a
    rotated_out = tlds_a - tlds_b
    if rotated_in or rotated_out:
        ioc_notes.append(f"C2 TLD rotated {sorted(tlds_a) or '∅'} → {sorted(tlds_b) or '∅'}")
    new_iocs = set(b.iocs) - set(a.iocs)
    if new_iocs:
        ioc_notes.append(f"{len(new_iocs)} new indicator(s)")
    return LineageDiff(
        shared=sorted(ta & tb), only_in_a=sorted(ta - tb), only_in_b=sorted(tb - ta),
        ioc_evolution=ioc_notes,
    )


class LineageIndex:
    """A JSON-backed corpus of behavioural signatures."""

    def __init__(self, path: Path):
        self.path = path
        self.sigs: dict[str, Signature] = {}
        if path.exists():
            for d in json.loads(path.read_text() or "[]"):
                sig = Signature.from_dict(d)
                self.sigs[sig.sha256] = sig

    def add(self, sig: Signature) -> None:
        self.sigs[sig.sha256] = sig

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([s.to_dict() for s in self.sigs.values()], indent=2))

    def neighbours(self, sig: Signature, *, threshold: float = 0.5, top: int = 10) -> list[Neighbour]:
        out: list[Neighbour] = []
        for sha, other in self.sigs.items():
            if sha == sig.sha256:
                continue
            behav = round(jaccard(sig.minhash, other.minhash), 3)
            byte = round(minhash_similarity(sig.file_minhash, other.file_minhash), 3)
            same_imp = bool(sig.imphash) and sig.imphash == other.imphash
            out.append(Neighbour(other, behav, byte_similarity=byte, same_imphash=same_imp))
        # Keep a neighbour if it is related on ANY axis: behaviour, bytes, or a
        # shared import profile. A recompiled variant can diverge behaviourally
        # yet remain a near-duplicate on bytes / imphash — that is exactly the
        # link a hunter wants surfaced.
        out = [
            n for n in out
            if n.similarity >= threshold or n.byte_similarity >= threshold or n.same_imphash
        ]
        # Rank by the strongest available signal.
        out.sort(key=lambda n: (n.same_imphash, max(n.similarity, n.byte_similarity)), reverse=True)
        return out[:top]

    def first_seen(self, token: str) -> Signature | None:
        """Earliest sample (by created time) whose behaviour contains a token —
        answers 'which sample first introduced this C2/capability'."""
        owners = [s for s in self.sigs.values() if token in s.tokens or token in s.iocs or token in s.techniques]
        return min(owners, key=lambda s: s.created or "~") if owners else None
