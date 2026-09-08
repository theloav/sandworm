"""The controller/backend boundary is fail-closed and replay is non-executing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sandworm.core.pipeline import analyze_sample, persist_run
from sandworm.core.sample import Sample
from sandworm.sandbox import AnalysisPolicy, BackendError, CAPEBackend, ReplayBackend
from sandworm.sandbox.cape import HTTPResponse


def _pe() -> Sample:
    return Sample.from_bytes("sample.exe", b"MZ" + b"\x00" * 510)


def test_replay_backend_hashes_artifacts_and_is_not_isolation(tmp_path):
    sample = _pe()
    report = tmp_path / "cape.json"
    report.write_text(json.dumps({"target_sha256": sample.sha256, "behavior": {}}))
    backend = ReplayBackend(cape_report=report)

    job = backend.submit(sample, AnalysisPolicy())
    bundle = backend.collect(job)

    assert bundle.execution_mode == "replay"
    assert not bundle.isolation_verified
    assert bundle.target_sha256 == sample.sha256
    assert bundle.artifacts[0].sha256
    assert bundle.artifacts[0].size == report.stat().st_size

    backend.destroy(job)
    with pytest.raises(BackendError):
        backend.collect(job)


def test_pipeline_replay_uses_backend_and_releases_job(temp_config, tmp_path):
    sample = _pe()
    report = tmp_path / "cape.json"
    report.write_text(
        json.dumps(
            {
                "target_sha256": sample.sha256,
                "behavior": {"api_calls": [{"api": "VirtualAllocEx", "t": 0.1}]},
            }
        )
    )

    result = analyze_sample(
        sample,
        config=temp_config,
        enable_dynamic=False,
        cape_report=str(report),
    )

    assert result.execution_mode == "replay"
    assert result.sandbox_backend == "replay"
    assert not result.isolated
    assert "dynamic.windows.cape(replay)" in result.analyzers_run

    from sandworm.core.audit import AuditLogger

    audit_actions = [record["action"] for record in AuditLogger(temp_config).read_all()]
    assert "sandbox_submit" in audit_actions
    assert "sandbox_collect" in audit_actions
    assert "sandbox_destroy" in audit_actions

    run_dir = persist_run(result, temp_config)
    manifest = json.loads((run_dir / "artifacts.json").read_text())
    assert manifest["schema_version"] == 1
    assert manifest["target_sha256"] == sample.sha256
    assert manifest["execution_mode"] == "replay"
    assert manifest["artifacts"][0]["sha256"]


def test_pipeline_never_invokes_backend_when_dynamic_disabled(temp_config):
    class ExplodingBackend:
        name = "must-not-run"

        def submit(self, sample, policy):
            raise AssertionError("backend was invoked")

        def status(self, job):
            raise AssertionError("backend was invoked")

        def collect(self, job):
            raise AssertionError("backend was invoked")

        def destroy(self, job):
            raise AssertionError("backend was invoked")

    result = analyze_sample(
        Sample.from_bytes("sample.php", b"<?php echo 1; ?>"),
        config=temp_config,
        enable_dynamic=False,
        sandbox_backend=ExplodingBackend(),
    )
    assert result.execution_mode == "static"
    assert result.sandbox_backend is None


class FakeCAPETransport:
    def __init__(self, sample_sha256: str) -> None:
        self.sample_sha256 = sample_sha256
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def request(self, method, url, *, headers, body, timeout, max_bytes):
        self.calls.append((method, url, headers, body))
        if url.endswith("tasks/create/file/"):
            return HTTPResponse(200, b'{"error": false, "data": {"task_ids": [42]}}')
        if url.endswith("tasks/view/42/"):
            return HTTPResponse(200, b'{"error": false, "data": {"status": "reported"}}')
        if url.endswith("tasks/get/report/42/"):
            report = {
                "info": {"version": "2.5", "started": "2026-01-01T00:00:00Z"},
                "target": {"file": {"sha256": self.sample_sha256}},
                "behavior": {"api_calls": [{"api": "CreateProcessW"}]},
            }
            return HTTPResponse(200, json.dumps(report).encode())
        raise AssertionError(f"unexpected request: {method} {url}")


def _cape(tmp_path: Path, sample: Sample, transport: FakeCAPETransport, **kwargs):
    return CAPEBackend(
        base_url="https://cape.test/apiv2/",
        token="secret-token",
        artifact_dir=tmp_path / "artifacts",
        image_id="win11-clean@sha256:abc",
        isolation_verified=True,
        poll_interval_seconds=0,
        transport=transport,
        **kwargs,
    )


def test_cape_backend_submits_polls_binds_and_collects(tmp_path):
    sample = _pe()
    transport = FakeCAPETransport(sample.sha256)
    backend = _cape(tmp_path, sample, transport)

    job = backend.submit(sample, AnalysisPolicy(network="disabled", timeout_seconds=30))
    bundle = backend.collect(job)

    assert job.id == "42"
    assert bundle.execution_mode == "sandbox"
    assert bundle.isolation_verified
    assert bundle.image_id == "win11-clean@sha256:abc"
    assert bundle.target_sha256 == sample.sha256
    assert bundle.artifacts[0].path.is_file()
    assert json.loads(bundle.artifacts[0].path.read_text())["target_sha256"] == sample.sha256
    assert [call[0] for call in transport.calls] == ["POST", "GET", "GET"]
    assert transport.calls[0][2]["Authorization"] == "Token secret-token"
    assert sample.data in (transport.calls[0][3] or b"")


def test_cape_refuses_unattested_deployment_before_network(tmp_path):
    sample = _pe()
    transport = FakeCAPETransport(sample.sha256)
    backend = CAPEBackend(
        base_url="https://cape.test/apiv2/",
        token=None,
        artifact_dir=tmp_path,
        image_id="win11-clean@sha256:abc",
        isolation_verified=False,
        transport=transport,
    )

    with pytest.raises(BackendError, match="not attested"):
        backend.submit(sample, AnalysisPolicy())
    assert transport.calls == []


def test_cape_simulated_network_requires_named_route(tmp_path):
    sample = _pe()
    transport = FakeCAPETransport(sample.sha256)
    backend = _cape(tmp_path, sample, transport)

    with pytest.raises(BackendError, match="configured CAPE route"):
        backend.submit(sample, AnalysisPolicy(network="simulated"))
    assert transport.calls == []


def test_pipeline_destroys_failed_backend_job(temp_config):
    class FailingBackend:
        name = "failing"
        destroyed = False

        def submit(self, sample, policy):
            from sandworm.sandbox import JobHandle

            return JobHandle("job-1", self.name, sample.sha256)

        def status(self, job):
            from sandworm.sandbox import JobState, JobStatus

            return JobStatus(JobState.RUNNING)

        def collect(self, job):
            raise BackendError("collection failed")

        def destroy(self, job):
            self.destroyed = True

    backend = FailingBackend()
    result = analyze_sample(
        _pe(), config=temp_config, enable_dynamic=True, sandbox_backend=backend
    )

    assert backend.destroyed
    assert result.execution_mode == "static"
    assert any("failed safely" in note for note in result.notes)
