"""Deprecated in-process isolation gate.

An environment marker and failed public socket probes cannot establish a safe
malware boundary. Live execution now belongs exclusively to ``SandboxBackend``.
These functions remain as a fail-closed compatibility API for callers that used
the earlier gate; they can no longer authorize sample execution.
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLogger
from .config import Config, get_config


class IsolationError(RuntimeError):
    """Raised when the detonation environment cannot be verified isolated."""


@dataclass
class IsolationStatus:
    isolated: bool
    reasons: list[str]
    checks: dict[str, bool]

    def __bool__(self) -> bool:
        return self.isolated


def verify_isolation(config: Config | None = None) -> IsolationStatus:
    """Return a fail-closed result directing callers to ``SandboxBackend``."""
    config = config or get_config()
    checks: dict[str, bool] = {"backend_boundary": False}
    reasons: list[str] = []

    checks["detonation_enabled"] = bool(config.allow_detonation)
    if not config.allow_detonation:
        reasons.append("detonation not enabled (SANDWORM_ALLOW_DETONATION is off)")
    reasons.append(
        "in-process isolation markers are not a security boundary; configure a SandboxBackend"
    )
    return IsolationStatus(isolated=False, reasons=reasons, checks=checks)


def require_isolation(run_id: str, config: Config | None = None, audit: AuditLogger | None = None) -> IsolationStatus:
    """Raise :class:`IsolationError` (and audit it) if isolation is unverifiable.

    Callers that would execute a sample MUST call this first. On failure nothing
    is executed; the caller degrades to static-only analysis.
    """
    config = config or get_config()
    audit = audit or AuditLogger(config)
    status = verify_isolation(config)
    if not status.isolated:
        audit.log(
            run_id=run_id,
            action="detonation_refused",
            analyzer="core.isolation",
            reasons=status.reasons,
            checks=status.checks,
        )
        raise IsolationError(
            "Detonation refused — isolation could not be verified: " + "; ".join(status.reasons)
        )
    audit.log(
        run_id=run_id,
        action="isolation_verified",
        analyzer="core.isolation",
        checks=status.checks,
    )
    return status


def guard_detonation(run_id: str, config: Config | None = None, audit: AuditLogger | None = None) -> bool:
    """Non-raising variant: returns True iff detonation is permitted.

    Logs the decision either way. Useful for analyzers that want to skip the
    dynamic lane silently and continue with static evidence.
    """
    try:
        require_isolation(run_id, config=config, audit=audit)
        return True
    except IsolationError:
        return False
