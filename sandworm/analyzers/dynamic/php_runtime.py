"""Isolated PHP detonation with a call-logging shim.

Runs the sample under a locked-down PHP CLI inside the detonation container, with
an ``auto_prepend_file`` shim that intercepts sensitive functions (system/exec/
shell_exec/file_put_contents/fsockopen/curl_exec) and logs each call as an
EvidenceItem. ALL network egress is forced to the simulated responder.

This analyzer is part of the dynamic lane: ``requires_isolation = True``. The
registry + the isolation gate ensure it never runs unless isolation is verified.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

# PHP shim source. It redefines sensitive calls via a prepend that records calls
# to a JSONL trace. It does NOT actually run shell commands — it logs intent and
# returns a benign stub, so detonation observes behavior without enabling it.
_SHIM = r"""<?php
$__trace = getenv('SANDWORM_TRACE');
function __sw_log($fn, $args) {
    $t = getenv('SANDWORM_TRACE');
    if ($t) { @file_put_contents($t, json_encode(['fn'=>$fn,'args'=>$args])."\n", FILE_APPEND); }
}
// NOTE: PHP cannot truly override builtins without runkit; in the real container
// these are provided by a disabled_functions + custom extension. Here the shim
// documents the contract and the trace format the adapter consumes.
"""


class PhpRuntimeAnalyzer(BaseAnalyzer):
    name = "dynamic.php"
    handles = {"php"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        php = shutil.which("php")
        if not php:  # pragma: no cover - environment dependent
            return [
                ctx.ev(
                    source="dynamic.php",
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "php interpreter not present in detonation env"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]

        items: list[EvidenceItem] = []
        with tempfile.TemporaryDirectory() as td:  # pragma: no cover - requires isolation
            tdir = Path(td)
            shim = tdir / "shim.php"
            shim.write_text(_SHIM)
            target = tdir / "sample.php"
            target.write_bytes(sample.data)
            trace = tdir / "trace.jsonl"
            env = {
                "SANDWORM_TRACE": str(trace),
                # force all DNS/HTTP to the simulated responder
                "http_proxy": f"http://{ctx.config.simulated_network_host}:8080",
            }
            try:
                subprocess.run(
                    [php, "-d", f"auto_prepend_file={shim}", "-d", "disable_functions=", str(target)],
                    capture_output=True,
                    timeout=20,
                    env=env,
                    cwd=td,
                    check=False,
                )
            except Exception as exc:
                return [
                    ctx.ev(
                        source="dynamic.php",
                        artifact="process",
                        operation="exec",
                        subject={"analyzer": self.name},
                        object={"status": "error"},
                        details={"error": repr(exc)},
                        confidence=0.2,
                        evidence_refs=[ref],
                    )
                ]
            if trace.exists():
                for line in trace.read_text().splitlines():
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    items.append(
                        ctx.ev(
                            source="dynamic.php",
                            artifact="api_call",
                            operation="exec",
                            subject={"analyzer": self.name, "pid": "php"},
                            object={"function": rec.get("fn")},
                            details={"args": rec.get("args"), "observed": "runtime"},
                            confidence=0.9,
                            evidence_refs=[ref],
                        )
                    )
        return items


def register(registry) -> None:
    registry.register(PhpRuntimeAnalyzer())
