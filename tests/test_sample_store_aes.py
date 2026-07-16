"""Tests for the encrypted-at-rest SampleStore (AES-256 when pyzipper present)."""

from __future__ import annotations

import zipfile

import pytest

from sandworm.core.config import Config
from sandworm.core.sample import Sample, SampleStore, _pyzipper

MAL = b"MZ\x90\x00 this represents malicious sample bytes"


@pytest.fixture
def store(tmp_path):
    return SampleStore(Config(work_dir=tmp_path / "wd"))


def test_roundtrip_preserves_bytes(store):
    s = Sample.from_bytes("evil.exe", MAL)
    store.store(s)
    loaded = store.load(s.sha256, "evil.exe")
    assert loaded.data == MAL
    assert loaded.sha256 == s.sha256


def test_inner_entry_is_non_executable(store):
    # The archived entry must never carry an executable extension.
    s = Sample.from_bytes("evil.exe", MAL)
    path = store.store(s)
    opener = _pyzipper() or zipfile
    with opener.ZipFile(str(path)) as zf:  # type: ignore[attr-defined]
        names = zf.namelist()
    assert names == [f"{s.sha256}.bin"]


def test_missing_sample_raises(store):
    with pytest.raises(FileNotFoundError):
        store.load("0" * 64)


@pytest.mark.skipif(_pyzipper() is None, reason="pyzipper not installed")
def test_aes_encryption_enforced(store):
    assert store.encryption == "aes-256"
    s = Sample.from_bytes("evil.exe", MAL)
    path = store.store(s)
    # Reading the AES entry with the stdlib (no AES support / no password) must fail.
    with zipfile.ZipFile(str(path)) as zf, pytest.raises((RuntimeError, NotImplementedError)):
        zf.read(zf.namelist()[0])


@pytest.mark.skipif(_pyzipper() is None, reason="pyzipper not installed")
def test_wrong_password_fails(tmp_path):
    good = SampleStore(Config(work_dir=tmp_path / "wd", sample_store_password="correct"))
    s = Sample.from_bytes("evil.exe", MAL)
    good.store(s)
    bad = SampleStore(Config(work_dir=tmp_path / "wd", sample_store_password="wrong"))
    # pyzipper raises RuntimeError ("Bad password") when the AES MAC check fails.
    with pytest.raises(RuntimeError):
        bad.load(s.sha256)
