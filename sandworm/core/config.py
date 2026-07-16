"""Runtime configuration. Environment-driven with safe defaults.

Defaults are chosen so SANDWORM is *safe by default*: detonation is disabled and
the simulated-network responder is assumed, so a fresh checkout cannot
accidentally let a sample reach a real host.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """Global SANDWORM configuration."""

    # Where runs, samples and audit logs live.
    work_dir: Path = field(default_factory=lambda: Path(os.environ.get("SANDWORM_WORK_DIR", ".sandworm")))

    # --- Isolation / safety (load-bearing) ---
    # Detonation is OFF unless explicitly enabled AND the isolation gate passes.
    allow_detonation: bool = field(default_factory=lambda: _env_bool("SANDWORM_ALLOW_DETONATION", False))
    # The only host egress is permitted to: the simulated-network responder.
    simulated_network_host: str = field(default_factory=lambda: os.environ.get("SANDWORM_SIMNET_HOST", "10.0.0.1"))
    # Marker env var set inside the detonation container/VM to prove isolation.
    isolation_marker_env: str = field(default_factory=lambda: os.environ.get("SANDWORM_ISOLATION_MARKER", "SANDWORM_ISOLATED"))

    # --- Encryption-at-rest for the sample store ---
    sample_store_password: str = field(default_factory=lambda: os.environ.get("SANDWORM_SAMPLE_PASSWORD", "infected"))

    # Hard cap on how many bytes a single sample may be. Guards against an
    # accidental multi-GB memory dump being loaded whole into RAM and scanned.
    # 0 disables the cap. Default 512 MiB comfortably covers real malware.
    max_sample_bytes: int = field(default_factory=lambda: int(os.environ.get("SANDWORM_MAX_SAMPLE_BYTES", 512 * 1024 * 1024)))

    # --- Graph backend ---
    neo4j_uri: str | None = field(default_factory=lambda: os.environ.get("SANDWORM_NEO4J_URI"))
    neo4j_user: str = field(default_factory=lambda: os.environ.get("SANDWORM_NEO4J_USER", "neo4j"))
    neo4j_password: str = field(default_factory=lambda: os.environ.get("SANDWORM_NEO4J_PASSWORD", ""))

    # --- LLM copilot ---
    llm_provider: str = field(default_factory=lambda: os.environ.get("SANDWORM_LLM_PROVIDER", "mock"))
    llm_model: str = field(default_factory=lambda: os.environ.get("SANDWORM_LLM_MODEL", "claude-opus-4-8"))
    llm_api_key: str | None = field(default_factory=lambda: os.environ.get("SANDWORM_LLM_API_KEY"))

    def run_dir(self, run_id: str) -> Path:
        d = self.work_dir / "runs" / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def audit_path(self) -> Path:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        return self.work_dir / "audit.jsonl"

    @property
    def sample_dir(self) -> Path:
        d = self.work_dir / "samples"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def cache_dir(self) -> Path:
        d = self.work_dir / "cache"
        d.mkdir(parents=True, exist_ok=True)
        return d


_DEFAULT: Config | None = None


def get_config() -> Config:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Config()
    return _DEFAULT


def set_config(cfg: Config) -> None:
    global _DEFAULT
    _DEFAULT = cfg
