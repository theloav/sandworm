"""THE ISOLATION GATE — the safety gate (build second, test second).

SANDWORM handles live malware. Dynamic analysis may run ONLY inside an isolated
detonation environment (container/VM) with no real network: all egress must be
routed to a simulated-network responder (INetSim / FakeNet-style). If isolation
cannot be *verified in code*, we refuse to detonate and fall back to static-only.

This is enforced programmatically, not in docs. Every ``detonate``-style caller
must pass through :func:`require_isolation` / :func:`guard_detonation`.
"""

from __future__ import annotations

import socket
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


def _real_network_reachable(timeout: float = 0.4) -> bool:
    """Best-effort probe: can we reach a real, public host? In a properly
    isolated env this must FAIL. We try a couple of well-known anycast IPs on
    DNS/HTTPS ports. A successful connection means we are NOT isolated."""
    targets = [("8.8.8.8", 53), ("1.1.1.1", 443)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def verify_isolation(config: Config | None = None) -> IsolationStatus:
    """Verify the detonation environment is network-isolated and ephemeral.

    Checks (all must pass):

    * ``allow_detonation`` is explicitly enabled (operator opt-in).
    * The isolation marker env var is present (set by the container/VM image),
      proving we are inside the dedicated detonation environment and not the host.
    * No real/public network is reachable — egress is confined to the simulated
      responder.
    """
    config = config or get_config()
    checks: dict[str, bool] = {}
    reasons: list[str] = []

    import os

    checks["detonation_enabled"] = bool(config.allow_detonation)
    if not config.allow_detonation:
        reasons.append("detonation not enabled (SANDWORM_ALLOW_DETONATION is off)")

    marker_present = os.environ.get(config.isolation_marker_env) is not None
    checks["isolation_marker"] = marker_present
    if not marker_present:
        reasons.append(
            f"isolation marker env '{config.isolation_marker_env}' not set — "
            "not running inside a verified detonation environment"
        )

    real_net = _real_network_reachable()
    checks["no_real_network"] = not real_net
    if real_net:
        reasons.append("real/public network is reachable — egress is NOT confined to simulated network")

    isolated = all(checks.values())
    return IsolationStatus(isolated=isolated, reasons=reasons, checks=checks)


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
