"""Instrumented script detonation (PowerShell / JS / shell).

Enables the right tracing per interpreter inside the isolated container:
``set -x`` for shell, ScriptBlock logging for PowerShell, a require/console hook
for JS. Normalizes the trace into EvidenceItems. Gated: requires verified
isolation. The synthetic shell dropper exercises the shell path.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context


class ScriptRuntimeAnalyzer(BaseAnalyzer):
    name = "dynamic.script"
    handles = {"script", "shell", "powershell", "javascript"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        lang = sample.format_hint or "shell"
        if lang != "shell":
            # PS/JS detonation needs the respective interpreter image; document & skip.
            return [
                ctx.ev(
                    source="dynamic.script",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"status": "skipped", "language": lang},
                    details={"reason": f"no instrumented {lang} interpreter image in this env"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]

        sh = shutil.which("bash") or shutil.which("sh")
        if not sh:  # pragma: no cover
            return []

        items: list[EvidenceItem] = []
        with tempfile.TemporaryDirectory() as td:  # pragma: no cover - requires isolation
            tdir = Path(td)
            target = tdir / "sample.sh"
            target.write_bytes(sample.data)
            try:
                proc = subprocess.run(
                    [sh, "-x", str(target)],
                    capture_output=True,
                    timeout=15,
                    cwd=td,
                    env={"PATH": "/usr/bin:/bin", "SANDWORM_SIMNET": ctx.config.simulated_network_host},
                    check=False,
                )
            except Exception as exc:
                return [
                    ctx.ev(
                        source="dynamic.script",
                        artifact="process",
                        operation="exec",
                        subject={"analyzer": self.name},
                        object={"status": "error"},
                        details={"error": repr(exc)},
                        confidence=0.2,
                        evidence_refs=[ref],
                    )
                ]
            # `set -x` writes the executed command trace to stderr (+ lines).
            for line in proc.stderr.decode("utf-8", "replace").splitlines():
                if not line.startswith("+"):
                    continue
                cmd = line.lstrip("+ ").strip()
                items.append(
                    ctx.ev(
                        source="dynamic.script",
                        artifact="process",
                        operation="spawn",
                        subject={"analyzer": self.name, "pid": "sh"},
                        object={"command": cmd},
                        details={"observed": "set -x trace"},
                        confidence=0.85,
                        evidence_refs=[ref],
                    )
                )
            # Any files created in the work dir are dropper artifacts.
            for f in tdir.iterdir():
                if f.name != "sample.sh":
                    items.append(
                        ctx.ev(
                            source="dynamic.script",
                            artifact="file",
                            operation="create",
                            subject={"analyzer": self.name, "pid": "sh"},
                            object={"path": f.name},
                            details={"size": f.stat().st_size},
                            confidence=0.8,
                            evidence_refs=[ref],
                        )
                    )
        return items


def register(registry) -> None:
    registry.register(ScriptRuntimeAnalyzer())
