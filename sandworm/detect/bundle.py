"""Review-ready detection artifacts; never deploys rules or opens a remote PR."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import uuid
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from ..analyzers.external import run_parser
from ..core.pipeline import RunResult


def suricata_candidates(store, *, sid_start: int = 9000000) -> tuple[list[str], list[dict]]:
    if not 1000000 <= sid_start <= 4294966000:
        raise ValueError("SID start must reserve a local range of at least 1000 IDs")
    indicators: dict[tuple[str, str], list[str]] = {}
    for item in store:
        if item.artifact != "network" or item.confidence < 0.6 or item.details.get("false_positive_risk") == "high":
            continue
        value = item.object.get("host") or item.object.get("value")
        if not isinstance(value, str) or len(value) > 2048:
            continue
        try:
            host = urlsplit(value).hostname if "://" in value else value
            host = (host or "").lower().rstrip(".")
            try:
                address = ipaddress.ip_address(host)
                if not address.is_global:
                    continue
                kind, normalized = "ip", str(address)
            except ValueError:
                if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
                    continue
                kind, normalized = "dns", host
        except ValueError:
            continue
        indicators.setdefault((kind, normalized), []).append(item.id)
    rules, rows = [], []
    for index, ((kind, value), refs) in enumerate(sorted(indicators.items())[:1000]):
        sid = sid_start + index
        if kind == "dns":
            rule = f'alert dns any any -> any any (msg:"SANDWORM review DNS indicator"; dns.query; content:"{value}"; nocase; startswith; endswith; sid:{sid}; rev:1;)'
        else:
            rule = f'alert ip any any -> {value} any (msg:"SANDWORM review destination indicator"; sid:{sid}; rev:1;)'
        rules.append(rule)
        rows.append({"sid": sid, "kind": kind, "value": value, "evidence_ids": refs,
                     "status": "experimental IOC candidate; not proof of C2"})
    return rules, rows


def write_bundle(result: RunResult, out: Path, *, target: str = "", pipeline: str = "", product: str = "") -> dict:
    if out.exists():
        raise ValueError("bundle output must be a new directory")
    if target and (target not in {"splunk", "kusto"} or not pipeline or product not in {"windows", "linux", "macos"}):
        raise ValueError("conversion needs target splunk/kusto, an explicit pipeline and telemetry product")
    out.mkdir(parents=True, mode=0o700)
    sigma_dir = out / "sigma"
    sigma_dir.mkdir()
    (out / "rules.yar").write_text("\n\n".join(rule.to_yara() for rule in result.yara) + "\n")
    examples, conversions = [], []
    for index, original in enumerate(result.sigma):
        rule = replace(original, logsource=original.logsource | ({"product": product} if product else {}))
        source = rule.to_yaml()
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL, source))
        path = sigma_dir / f"{index:03d}-{identity}.yml"
        path.write_text(f'id: "{identity}"\n' + source + "\n")
        examples.append({"rule": str(path.relative_to(out)), "selection_fields": rule.detection,
                         "note": "Review required: these selectors are not validated SIEM telemetry fixtures."})
        if target:
            executable = shutil.which("sigma")
            query = out / f"{index:03d}.{target}.txt"
            log = out / f"{index:03d}.conversion.log"
            try:
                if not executable:
                    raise RuntimeError("install sigma-cli and the selected backend/pipeline")
                run_parser([executable, "convert", "-t", target, "-p", pipeline, "-o", str(query), str(path)], log, timeout=60)
                if not query.is_file() or not query.stat().st_size:
                    raise RuntimeError("converter returned no query")
                conversions.append({"rule": path.name, "status": "converted", "query": query.name})
            except (RuntimeError, OSError) as exc:
                conversions.append({"rule": path.name, "status": "failed", "error": str(exc)})
    network_rules, network = suricata_candidates(result.store)
    (out / "suricata.rules").write_text("\n".join(network_rules) + "\n")
    (out / "network-evidence.json").write_text(json.dumps(network, indent=2) + "\n")
    (out / "sigma-review.json").write_text(json.dumps(examples, indent=2) + "\n")
    tests = [{"rule": rule.name, "positive_hex": b"\x00".join(rule.strings).hex(), "negative_hex": ""} for rule in result.yara]
    (out / "yara-cases.json").write_text(json.dumps(tests, indent=2) + "\n")
    (out / "test_yara.py").write_text('''"""Synthetic rule-semantics checks, not a goodware FP benchmark."""
import json
from pathlib import Path
import yara_x
import pytest

def test_generated_yara():
    root = Path(__file__).parent
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)
    compiler.add_source((root / "rules.yar").read_text())
    rules = compiler.build()
    cases = json.loads((root / "yara-cases.json").read_text())
    if not cases:
        pytest.skip("No YARA candidates generated")
    for case in cases:
        assert case["rule"] in {r.identifier for r in rules.scan(bytes.fromhex(case["positive_hex"])).matching_rules}
        assert case["rule"] not in {r.identifier for r in rules.scan(bytes.fromhex(case["negative_hex"])).matching_rules}
''')
    (out / "README.md").write_text("# Detection review bundle\n\nExperimental candidates, not deployed detections.\n\n"
        "Run `python -m pytest test_yara.py` with yara-x installed. These synthetic anchor tests measure rule semantics, not recall or false positives. "
        "Run a separate hash-pinned goodware audit before use.\n\n"
        "Review Sigma log sources, product assumptions, field mappings and converted queries against your actual telemetry. "
        "Suricata output uses exact DNS names/public destination IPs; validate with `suricata -T` and representative PCAPs, reserve local SIDs, and tune shared infrastructure. "
        "No rules, queries, or test samples are automatically executed or deployed.\n")
    manifest = {"schema_version": 1, "sample_sha256": result.sample.sha256, "status": "requires analyst review",
                "sigma_target": target or None, "sigma_pipeline": pipeline or None, "telemetry_product": product or None,
                "conversions": conversions, "suricata_engine_validated": False,
                "files": {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
