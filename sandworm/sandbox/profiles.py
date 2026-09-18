"""Operator-controlled profiles. API clients select names, never commands/paths."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..core.config import Config
from .base import AnalysisPolicy, SandboxBackend


def available_profiles() -> dict:
    profiles = {"static": {"backend": "static"}}
    path = os.environ.get("SANDWORM_PROFILES")
    if path:
        document = json.loads(Path(path).read_text())
        if not isinstance(document, dict):
            raise ValueError("profiles must be a JSON object")
        profiles.update(document)
    return profiles


def resolve_profile(name: str, cfg: Config) -> tuple[SandboxBackend | None, AnalysisPolicy]:
    row = available_profiles().get(name)
    if row is None:
        raise ValueError(f"unknown sandbox profile: {name}")
    policy = AnalysisPolicy(timeout_seconds=int(row.get("timeout", 120)),
                            network=row.get("network", "disabled"),
                            capture_memory=bool(row.get("capture_memory", False)),
                            options={str(k): str(v) for k, v in row.get("options", {}).items()})
    if row["backend"] == "static":
        return None, policy
    if row["backend"] == "qemu":
        from .qemu import QemuBackend
        return QemuBackend(image=Path(row["image"]), image_sha256=row["sha256"],
                           artifact_dir=cfg.sandbox_artifact_dir), policy
    if row["backend"] == "cape":
        from .cape import CAPEBackend
        return CAPEBackend(base_url=cfg.cape_url or "", token=cfg.cape_token,
                           artifact_dir=cfg.sandbox_artifact_dir, image_id=cfg.cape_image_id,
                           isolation_verified=cfg.cape_isolation_verified,
                           simulated_route=cfg.cape_simulated_route,
                           allow_insecure_http=cfg.cape_allow_insecure_http), policy
    raise ValueError("unsupported sandbox backend")
