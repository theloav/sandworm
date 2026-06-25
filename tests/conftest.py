"""Shared test fixtures. Every test runs against an isolated temp work dir with
detonation disabled, so the suite is fully offline and side-effect free."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandworm.core.config import Config, set_config


@pytest.fixture(autouse=True)
def temp_config(tmp_path, monkeypatch) -> Config:
    # Ensure no ambient env leaks detonation permission into tests.
    for var in ("SANDWORM_ALLOW_DETONATION", "SANDWORM_ISOLATED", "SANDWORM_NEO4J_URI"):
        monkeypatch.delenv(var, raising=False)
    cfg = Config(work_dir=tmp_path / "work", allow_detonation=False, llm_provider="mock")
    set_config(cfg)
    return cfg


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "samples" / "synthetic"
