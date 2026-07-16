"""Similarity fingerprints — dependency-free, offline.

Two kinds, both used to turn per-sample analysis into corpus analysis:

* **imphash** — the industry-standard MD5 over a PE's ordered, normalized import
  list. Two samples built from the same source/toolchain share an imphash even
  when their bytes differ, so it answers "same import profile as sample X".

* **file MinHash** — a fuzzy byte-similarity digest. We hash overlapping byte
  n-grams and keep the per-permutation minima (MinHash), so two files can be
  compared by estimated Jaccard similarity without ssdeep/TLSH native libs. This
  survives small edits (recompiles, IOC rotation) that break a sha256.
"""

from __future__ import annotations

import hashlib

_NUM_PERM = 48
_NGRAM = 8
_MAXH = (1 << 32) - 1


def imphash(imports: list[str]) -> str:
    """Standard imphash: lowercase ``dll.function`` (dll extension stripped),
    joined in import order, MD5-hashed. Empty when there are no imports."""
    parts: list[str] = []
    for imp in imports:
        name = imp.strip().lower()
        if not name:
            continue
        # pefile normalizes "kernel32.dll" library prefixes off the function name;
        # our import list is already just function names, so hash them directly.
        parts.append(name)
    if not parts:
        return ""
    return hashlib.md5(",".join(parts).encode()).hexdigest()  # noqa: S324 - imphash is defined as MD5


def _ngram_hash(gram: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(gram, digest_size=4).digest(), "big")


def file_minhash(data: bytes, *, num_perm: int = _NUM_PERM, ngram: int = _NGRAM) -> tuple[int, ...]:
    """MinHash over overlapping byte n-grams. Deterministic; comparable across
    samples via :func:`minhash_similarity`. Large files are strided so the cost
    stays bounded (similarity is preserved under uniform sampling)."""
    n = len(data)
    if n < ngram:
        return tuple([_MAXH] * num_perm)
    # Bound the number of n-grams we hash so multi-MB files stay fast; a stride
    # keeps the sample uniform across the whole file.
    max_grams = 200_000
    total = n - ngram + 1
    stride = max(1, total // max_grams)

    mins = [_MAXH] * num_perm
    for i in range(0, total, stride):
        h = _ngram_hash(data[i:i + ngram])
        # Derive num_perm permutations from the single base hash cheaply.
        for p in range(num_perm):
            v = (h ^ (0x9E3779B1 * (p + 1))) & _MAXH
            if v < mins[p]:
                mins[p] = v
    return tuple(mins)


def minhash_similarity(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    """Estimated Jaccard similarity between two MinHash digests of equal length."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(1 for x, y in zip(a, b, strict=True) if x == y) / len(a)
