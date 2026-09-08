"""CAPE v2 REST backend for Windows sandbox analysis."""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin, urlparse

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


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes
    content_type: str = "application/octet-stream"


class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
    ) -> HTTPResponse: ...


class UrllibTransport:
    """Small bounded HTTP transport; CAPE remains an optional dependency."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
    ) -> HTTPResponse:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(max_bytes + 1)
                status = response.status
                content_type = response.headers.get_content_type()
        except urllib.error.HTTPError as exc:
            payload = exc.read(max_bytes + 1)
            status = exc.code
            content_type = exc.headers.get_content_type()
        except urllib.error.URLError as exc:
            raise BackendError(f"CAPE request failed: {exc.reason}") from exc
        if len(payload) > max_bytes:
            raise BackendError(f"CAPE response exceeded the {max_bytes:,}-byte limit")
        return HTTPResponse(status=status, body=payload, content_type=content_type)


@dataclass
class _CAPEJob:
    handle: JobHandle
    policy: AnalysisPolicy
    destroyed: bool = False


class CAPEBackend:
    """Submit samples to a separately managed, attested CAPE deployment.

    Construction alone does not establish trust. ``isolation_verified`` and a
    concrete ``image_id`` must be supplied by deployment configuration before
    ``submit`` will send sample bytes over the network.
    """

    name = "cape"

    def __init__(
        self,
        *,
        base_url: str,
        token: str | None,
        artifact_dir: str | Path,
        image_id: str,
        isolation_verified: bool,
        simulated_route: str | None = None,
        allow_insecure_http: bool = False,
        poll_interval_seconds: float = 2.0,
        request_timeout_seconds: float = 30.0,
        max_report_bytes: int = 128 * 1024 * 1024,
        transport: HTTPTransport | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("CAPE base_url must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_insecure_http:
            raise ValueError("CAPE HTTP transport requires explicit allow_insecure_http=True")
        if not image_id.strip():
            raise ValueError("CAPE image_id is required for artifact provenance")
        if poll_interval_seconds < 0:
            raise ValueError("poll_interval_seconds cannot be negative")
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.artifact_dir = Path(artifact_dir)
        self.image_id = image_id
        self.isolation_verified = isolation_verified
        self.simulated_route = simulated_route
        self.poll_interval_seconds = poll_interval_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.max_report_bytes = max_report_bytes
        self.transport = transport or UrllibTransport()
        self._jobs: dict[str, _CAPEJob] = {}

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Token {self.token}"
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        response = self.transport.request(
            method,
            self._url(path),
            headers={**self._headers(), **(headers or {})},
            body=body,
            timeout=self.request_timeout_seconds,
            max_bytes=self.max_report_bytes,
        )
        if not 200 <= response.status < 300:
            raise BackendError(f"CAPE returned HTTP {response.status} for {path}")
        try:
            decoded = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackendError(f"CAPE returned invalid JSON for {path}") from exc
        if not isinstance(decoded, dict):
            raise BackendError(f"CAPE returned a non-object JSON response for {path}")
        if decoded.get("error") is True:
            message = decoded.get("error_value") or decoded.get("errors") or "unknown error"
            raise BackendError(f"CAPE rejected the request: {message}")
        return decoded

    @staticmethod
    def _multipart(sample: Sample, policy: AnalysisPolicy, route: str) -> tuple[bytes, str]:
        boundary = f"sandworm-{secrets.token_hex(16)}"
        chunks: list[bytes] = []

        def field(name: str, value: str) -> None:
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                    value.encode(),
                    b"\r\n",
                ]
            )

        field("timeout", str(policy.timeout_seconds))
        field("memory", "1" if policy.capture_memory else "0")
        field("route", route)
        requested_platform = policy.platform or sample.format_hint
        platform = "windows" if requested_platform in {"pe", "dll"} else requested_platform
        if platform:
            field("platform", platform)
        if policy.options:
            field("options", ",".join(f"{key}={value}" for key, value in policy.options.items()))

        filename = Path(sample.name).name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
                b"Content-Type: application/octet-stream\r\n\r\n",
                sample.data,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        return b"".join(chunks), boundary

    def submit(self, sample: Sample, policy: AnalysisPolicy) -> JobHandle:
        if not self.isolation_verified:
            raise BackendError("CAPE submission refused: deployment isolation is not attested")
        if policy.network == "simulated" and not self.simulated_route:
            raise BackendError("simulated networking requires a configured CAPE route")
        route = self.simulated_route if policy.network == "simulated" else "none"
        assert route is not None
        body, boundary = self._multipart(sample, policy, route)
        response = self._request_json(
            "POST",
            "tasks/create/file/",
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        response_data = response.get("data")
        data: dict = response_data if isinstance(response_data, dict) else response
        task_ids = data.get("task_ids")
        task_id = task_ids[0] if isinstance(task_ids, list) and task_ids else data.get("task_id")
        if not isinstance(task_id, int) and not (isinstance(task_id, str) and task_id.isdigit()):
            raise BackendError("CAPE submission did not return a task id")
        handle = JobHandle(id=str(task_id), backend=self.name, sample_sha256=sample.sha256)
        self._jobs[handle.id] = _CAPEJob(handle=handle, policy=policy)
        return handle

    def _job(self, job: JobHandle) -> _CAPEJob:
        record = self._jobs.get(job.id)
        if record is None or record.destroyed:
            raise BackendError(f"unknown or released CAPE job: {job.id}")
        if record.handle != job:
            raise BackendError("CAPE job handle does not match the submitted job")
        return record

    def status(self, job: JobHandle) -> JobStatus:
        self._job(job)
        response = self._request_json("GET", f"tasks/view/{job.id}/")
        data = response.get("data") or response.get("task") or response
        raw = str(data.get("status", "unknown")).lower() if isinstance(data, dict) else "unknown"
        if raw in {"reported", "completed"}:
            return JobStatus(JobState.COMPLETED, raw)
        if raw in {"failed_analysis", "failed_processing", "failed_reporting", "failed"}:
            return JobStatus(JobState.FAILED, raw)
        if raw in {"running", "processing"}:
            return JobStatus(JobState.RUNNING, raw)
        return JobStatus(JobState.QUEUED, raw)

    @staticmethod
    def _report_sha256(report: dict) -> str | None:
        target = report.get("target")
        if not isinstance(target, dict):
            return None
        file_info = target.get("file")
        if isinstance(file_info, dict) and file_info.get("sha256"):
            return str(file_info["sha256"]).lower()
        if target.get("sha256"):
            return str(target["sha256"]).lower()
        return None

    def collect(self, job: JobHandle) -> ArtifactBundle:
        record = self._job(job)
        deadline = time.monotonic() + record.policy.timeout_seconds + 60
        while True:
            status = self.status(job)
            if status.state == JobState.COMPLETED:
                break
            if status.state == JobState.FAILED:
                raise BackendError(f"CAPE analysis failed: {status.message}")
            if time.monotonic() >= deadline:
                raise BackendError(f"CAPE job {job.id} exceeded its collection deadline")
            time.sleep(self.poll_interval_seconds)

        report = self._request_json("GET", f"tasks/get/report/{job.id}/")
        reported_hash = self._report_sha256(report)
        if reported_hash is not None and reported_hash != job.sample_sha256.lower():
            raise BackendError("CAPE report target hash does not match the submitted sample")
        if reported_hash is None:
            raise BackendError("CAPE report does not identify its target SHA-256")
        report["target_sha256"] = reported_hash

        job_dir = self.artifact_dir / f"cape-{job.id}"
        job_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        job_dir.chmod(0o700)
        report_path = job_dir / "report.json"
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        report_path.chmod(0o600)
        artifact = Artifact.from_path("cape_report", report_path, media_type="application/json")
        report_info = report.get("info")
        info: dict = report_info if isinstance(report_info, dict) else {}
        return ArtifactBundle(
            job=job,
            target_sha256=reported_hash,
            backend_version=str(info.get("version", "unknown")),
            execution_mode="sandbox",
            artifacts=(artifact,),
            policy=record.policy,
            image_id=self.image_id,
            isolation_verified=self.isolation_verified,
            started_at=str(info.get("started")) if info.get("started") else None,
        )

    def destroy(self, job: JobHandle) -> None:
        # CAPE restores the analysis VM as part of its task lifecycle. Releasing
        # this handle deliberately does not delete the remote report; retention
        # is an operator policy, separate from worker teardown.
        record = self._jobs.get(job.id)
        if record is not None:
            record.destroyed = True
