"""Tests for imphash, fuzzy file MinHash, and their use in lineage."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceStore
from sandworm.core.simhash import file_minhash, imphash, minhash_similarity
from sandworm.reconstruct.lineage import LineageIndex, signature_of


def test_imphash_stable_and_order_sensitive():
    a = imphash(["LoadLibraryA", "GetProcAddress", "VirtualAlloc"])
    b = imphash(["loadlibrarya", "getprocaddress", "virtualalloc"])
    assert a == b and a  # case-insensitive, non-empty
    # Different import order ⇒ different imphash (matches the standard definition).
    assert imphash(["GetProcAddress", "LoadLibraryA"]) != imphash(["LoadLibraryA", "GetProcAddress"])
    assert imphash([]) == ""


def test_file_minhash_similarity_scale():
    base = bytes(range(256)) * 400  # ~100KB structured content
    assert minhash_similarity(file_minhash(base), file_minhash(base)) == 1.0
    # A small edit keeps most n-grams ⇒ high (but < 1.0) similarity.
    edited = base[:50_000] + b"INJECTED PAYLOAD" + base[50_000:]
    sim = minhash_similarity(file_minhash(base), file_minhash(edited))
    assert 0.7 < sim < 1.0
    # Unrelated content ⇒ low similarity.
    import os

    assert minhash_similarity(file_minhash(base), file_minhash(os.urandom(100_000))) < 0.2


def _store_with(imph=None, fmh=None):
    store = EvidenceStore()
    if imph:
        store.append(_ev(object={"imphash": imph}))
    if fmh is not None:
        store.append(_ev(details={"file_minhash": list(fmh)}))
    return store


def _ev(object=None, details=None):
    from sandworm.core.evidence import EvidenceItem

    return EvidenceItem(
        run_id="r", source="static.pe", artifact="module", operation="read",
        object=object or {}, details=details or {}, confidence=0.5,
    )


def test_lineage_links_by_imphash_despite_behaviour_divergence(tmp_path):
    # Two samples with the SAME imphash but no shared behaviour still link.
    shared_imp = imphash(["LoadLibraryA", "GetProcAddress", "WSAStartup"])
    a = signature_of("aa", "a.exe", _store_with(imph=shared_imp, fmh=file_minhash(b"AAAA" * 5000)))
    b = signature_of("bb", "b.exe", _store_with(imph=shared_imp, fmh=file_minhash(b"ZZZZ" * 5000)))
    idx = LineageIndex(tmp_path / "l.json")
    idx.add(a)
    idx.add(b)
    neigh = idx.neighbours(a, threshold=0.99)  # behaviour threshold impossible to meet
    assert neigh and neigh[0].same_imphash
    assert neigh[0].relation == "same-import-profile"


def test_lineage_links_by_byte_similarity(tmp_path):
    content = bytes(range(256)) * 500
    variant = content[:60_000] + b"rotated-c2.example.top" + content[60_000:]
    a = signature_of("aa", "a.bin", _store_with(fmh=file_minhash(content)))
    b = signature_of("bb", "b.bin", _store_with(fmh=file_minhash(variant)))
    idx = LineageIndex(tmp_path / "l.json")
    idx.add(a)
    idx.add(b)
    neigh = idx.neighbours(a, threshold=0.5)
    assert neigh and neigh[0].byte_similarity > 0.5


def test_signature_roundtrip_preserves_fingerprints(tmp_path):
    imph = imphash(["CreateProcessA", "WriteProcessMemory"])
    fmh = file_minhash(b"payload" * 2000)
    sig = signature_of("cc", "c.exe", _store_with(imph=imph, fmh=fmh))
    idx = LineageIndex(tmp_path / "l.json")
    idx.add(sig)
    idx.save()
    reloaded = LineageIndex(tmp_path / "l.json")
    got = reloaded.sigs["cc"]
    assert got.imphash == imph
    assert tuple(got.file_minhash) == fmh
