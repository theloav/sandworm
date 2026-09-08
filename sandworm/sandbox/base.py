"""Typed boundary between the controller and disposable sandbox workers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from ..core.sample import Sample

NetworkMode = Literal["disabled", "simulated"]
ExecutionMode = Literal["replay", "sandbox"]
ArtifactKind = Literal[
    "cape_report",
    "memory_report",
    "pcap",
    "memory_dump",
    "dropped_file",
    "trace",
    "log",
    "other",
]


class BackendError(RuntimeError):
    """A sandbox job could not be safely submitted, collected, or destroyed."""


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DESTROYED = "destroyed"


@dataclass(frozen=True)
class AnalysisPolicy:
    """Execution controls sent to a backend with every submitted sample."""

    timeout_seconds: int = 120
    network: NetworkMode = "disabled"
    capture_memory: bool = True
    platform: str | None = None
    options: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.network not in {"disabled", "simulated"}:
            raise ValueError("network must be 'disabled' or 'simulated'")


@dataclass(frozen=True)
class JobHandle:
    id: str
    backend: str
    sample_sha256: str
    submitted_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class JobStatus:
    state: JobState
    message: str = ""

    @property
    def terminal(self) -> bool:
        return self.state in {JobState.COMPLETED, JobState.FAILED, JobState.DESTROYED}


@dataclass(frozen=True)
class Artifact:
    """A content-addressed artifact produced by a sandbox job."""

    kind: ArtifactKind
    path: Path
    sha256: str
    size: int
    media_type: str = "application/octet-stream"

    @classmethod
    def from_path(
        cls, kind: ArtifactKind, path: str | Path, *, media_type: str = "application/octet-stream"
    ) -> Artifact:
        artifact_path = Path(path)
        if not artifact_path.is_file():
            raise BackendError(f"sandbox artifact does not exist or is not a file: {artifact_path}")
        digest = hashlib.sha256()
        size = 0
        with artifact_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        return cls(
            kind=kind,
            path=artifact_path,
            sha256=digest.hexdigest(),
            size=size,
            media_type=media_type,
        )


@dataclass(frozen=True)
class ArtifactBundle:
    """Immutable manifest returned by a backend after analysis completes."""

    job: JobHandle
    target_sha256: str
    backend_version: str
    execution_mode: ExecutionMode
    artifacts: tuple[Artifact, ...]
    policy: AnalysisPolicy
    image_id: str | None = None
    isolation_verified: bool = False
    started_at: str | None = None
    completed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        if self.target_sha256.lower() != self.job.sample_sha256.lower():
            raise BackendError("artifact bundle target does not match the submitted sample")
        if self.execution_mode == "sandbox" and not self.isolation_verified:
            raise BackendError("a live sandbox bundle must carry verified isolation attestation")

    def by_kind(self, kind: ArtifactKind) -> tuple[Artifact, ...]:
        return tuple(artifact for artifact in self.artifacts if artifact.kind == kind)

    def manifest(self) -> dict[str, object]:
        """Return a JSON-serializable provenance and integrity manifest."""
        return {
            "schema_version": 1,
            "job": {
                "id": self.job.id,
                "backend": self.job.backend,
                "sample_sha256": self.job.sample_sha256,
                "submitted_at": self.job.submitted_at,
            },
            "target_sha256": self.target_sha256,
            "backend_version": self.backend_version,
            "execution_mode": self.execution_mode,
            "image_id": self.image_id,
            "isolation_verified": self.isolation_verified,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "policy": {
                "timeout_seconds": self.policy.timeout_seconds,
                "network": self.policy.network,
                "capture_memory": self.policy.capture_memory,
                "platform": self.policy.platform,
                "options": dict(self.policy.options),
            },
            "artifacts": [
                {
                    "kind": artifact.kind,
                    "path": str(artifact.path),
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                    "media_type": artifact.media_type,
                }
                for artifact in self.artifacts
            ],
        }


@runtime_checkable
class SandboxBackend(Protocol):
    """Synchronous backend contract used by the analysis pipeline.

    ``collect`` may wait up to the timeout in the submitted policy. ``destroy``
    must be idempotent and is always called by the controller in a ``finally``
    block, including when collection fails.
    """

    name: str

    def submit(self, sample: Sample, policy: AnalysisPolicy) -> JobHandle: ...

    def status(self, job: JobHandle) -> JobStatus: ...

    def collect(self, job: JobHandle) -> ArtifactBundle: ...

    def destroy(self, job: JobHandle) -> None: ...
