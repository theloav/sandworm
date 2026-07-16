"""Integration tests for the `batch` CLI command (JSON/SARIF + exit gating)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from sandworm.cli import app
from sandworm.core.config import Config, set_config

runner = CliRunner()

WEBSHELL = b"<?php system($_GET['c']); ?>"
BENIGN = b"The quick brown fox.\n"


def _setup(tmp_path):
    set_config(Config(work_dir=tmp_path / "wd"))
    d = tmp_path / "samples"
    d.mkdir()
    (d / "shell.php").write_bytes(WEBSHELL)
    (d / "note.txt").write_bytes(BENIGN)
    return d


def test_batch_json_output(tmp_path):
    d = _setup(tmp_path)
    out = tmp_path / "out.json"
    result = runner.invoke(app, ["batch", str(d), "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    names = {s["sample"]["name"] for s in payload["samples"]}
    assert names == {"shell.php", "note.txt"}
    shell = next(s for s in payload["samples"] if s["sample"]["name"] == "shell.php")
    assert any(t["id"] == "T1059" for t in shell["techniques"])
    set_config(Config())


def test_batch_sarif_output(tmp_path):
    d = _setup(tmp_path)
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, ["batch", str(d), "--format", "sarif", "--out", str(out)])
    assert result.exit_code == 0, result.output
    log = json.loads(out.read_text())
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"]
    set_config(Config())


def test_batch_fail_on_gate(tmp_path):
    d = _setup(tmp_path)
    # The webshell is High risk, so --fail-on High must exit non-zero.
    result = runner.invoke(app, ["batch", str(d), "--fail-on", "High", "--out", str(tmp_path / "o.json")])
    assert result.exit_code == 1
    set_config(Config())


def test_batch_fail_on_not_triggered_when_clean(tmp_path):
    set_config(Config(work_dir=tmp_path / "wd"))
    d = tmp_path / "s"
    d.mkdir()
    (d / "note.txt").write_bytes(BENIGN)
    result = runner.invoke(app, ["batch", str(d), "--fail-on", "Critical", "--out", str(tmp_path / "o.json")])
    assert result.exit_code == 0, result.output
    set_config(Config())
