"""Offline backend for replaying previously captured sandbox artifacts."""

from __future__ import annotations

import uuid
from pathlib import Path

from ..core.sample import Sample
from .base import (
    AnalysisPolicy,
    Artifact,
    ArtifactBundle,
    BackendError,
    JobHandle,
    JobState,
    JobStatus,
)


class ReplayBackend:
    """Expose recorded CAPE/Volatility JSON through the sandbox contract.

    Replay never executes sample bytes and never claims current-run isolation.
    Report-to-sample provenance is verified by the pipeline normalizers.
    """

    name = "replay"

    def __init__(
        self,
        *,
        cape_report: str | Path | None = None,
        memory_report: str | Path | None = None,
        runtime_report: str | Path | None = None,
    ) -> None:
        if cape_report is None and memory_report is None and runtime_report is None:
            raise ValueError("ReplayBackend requires at least one recorded report")
        self._paths = {
            "cape_report": Path(cape_report) if cape_report is not None else None,
            "memory_report": Path(memory_report) if memory_report is not None else None,
            "trace": Path(runtime_report) if runtime_report is not None else None,
        }
        self._jobs: dict[str, tuple[JobHandle, AnalysisPolicy, bool]] = {}

    def submit(self, sample: Sample, policy: AnalysisPolicy) -> JobHandle:
        for path in self._paths.values():
            if path is not None and not path.is_file():
                raise BackendError(f"recorded report does not exist: {path}")
        job = JobHandle(
            id=f"replay-{uuid.uuid4().hex[:12]}",
            backend=self.name,
            sample_sha256=sample.sha256,
        )
        self._jobs[job.id] = (job, policy, False)
        return job

    def status(self, job: JobHandle) -> JobStatus:
        record = self._jobs.get(job.id)
        if record is None or record[2]:
            return JobStatus(JobState.DESTROYED, "replay job has been released")
        return JobStatus(JobState.COMPLETED, "recorded artifacts ready")

    def collect(self, job: JobHandle) -> ArtifactBundle:
        record = self._jobs.get(job.id)
        if record is None or record[2]:
            raise BackendError(f"unknown or destroyed replay job: {job.id}")
        _, policy, _ = record
        artifacts: list[Artifact] = []
        for kind, path in self._paths.items():
            if path is not None:
                artifacts.append(
                    Artifact.from_path(kind, path, media_type="application/json")  # type: ignore[arg-type]
                )
        return ArtifactBundle(
            job=job,
            target_sha256=job.sample_sha256,
            backend_version="1",
            execution_mode="replay",
            artifacts=tuple(artifacts),
            policy=policy,
            isolation_verified=False,
        )

    def destroy(self, job: JobHandle) -> None:
        record = self._jobs.get(job.id)
        if record is not None:
            self._jobs[job.id] = (record[0], record[1], True)
