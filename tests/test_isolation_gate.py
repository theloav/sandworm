"""The isolation gate MUST refuse detonation when isolation is unverifiable, and
nothing may execute the sample in that case."""

from __future__ import annotations

import pytest

from sandworm.core.audit import AuditLogger
from sandworm.core.isolation import (
    IsolationError,
    guard_detonation,
    require_isolation,
    verify_isolation,
)
from sandworm.core.sample import Sample


def test_refuses_without_isolation(temp_config):
    status = verify_isolation(temp_config)
    assert not status.isolated
    assert "detonation not enabled" in " ".join(status.reasons)

    with pytest.raises(IsolationError):
        require_isolation("run1", config=temp_config)


def test_refusal_is_audited(temp_config):
    audit = AuditLogger(temp_config)
    assert guard_detonation("run2", config=temp_config, audit=audit) is False
    records = audit.read_all()
    assert any(r["action"] == "detonation_refused" for r in records)


def test_dynamic_analyzers_are_never_registered_in_process(temp_config):
    """The controller registry contains only inert/static analyzers."""
    from sandworm.analyzers.registry import register_builtins

    reg = register_builtins()
    selected = reg.for_format("php", include_dynamic=True, isolated=False)
    assert all(not a.requires_isolation for a in selected)
    # An environment-controlled boolean must not change that decision.
    selected_iso = reg.for_format("php", include_dynamic=True, isolated=True)
    assert all(not a.requires_isolation for a in selected_iso)


def test_legacy_marker_cannot_authorize_execution(temp_config, monkeypatch):
    """An attacker-controlled environment marker is not an isolation proof."""
    monkeypatch.setenv(temp_config.isolation_marker_env, "1")
    temp_config.allow_detonation = True
    with pytest.raises(IsolationError, match="SandboxBackend"):
        require_isolation("run3", config=temp_config)


def test_no_execution_on_refusal(temp_config, monkeypatch):
    """Sanity: even if a dynamic analyzer object is invoked directly, it should
    only run inside isolation. Here we confirm the pipeline keeps it out."""
    from sandworm.core.pipeline import analyze_sample

    sample = Sample.from_bytes("x.php", b"<?php echo 1; ?>")
    result = analyze_sample(sample, config=temp_config)
    assert result.isolated is False
    assert all("dynamic" not in name for name in result.analyzers_run)
