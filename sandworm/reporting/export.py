"""Machine-readable exports for defender tooling.

All built from the same evidence + mappings a run already produced — the export
engine is simply another *consumer* of the EvidenceStore, never a new pipeline:

* **ATT&CK Navigator layer** — per-technique confidence as a heat score.
* **STIX 2.1 bundle** — IOCs + techniques as STIX SDOs (indicator / attack-pattern
  / relationship), ingestible by TIPs.
* **MISP event** — IOCs as MISP attributes + Galaxy-style ATT&CK tags.
* **OpenIOC** — Mandiant OpenIOC 1.1 XML indicator tree.
* **CSV** — a flat indicator dump for spreadsheets / quick grep.
* **SARIF 2.1** — results for code-scanning dashboards / CI.
* **Findings JSON** — a compact, stable machine summary for batch/CI use.

Nothing here re-analyses; exporters are pure consumers of the RunResult, matching
the evidence-layer architecture.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import UTC, datetime
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

# ATT&CK Navigator colour ramp: low → high confidence.
_NAV_GRADIENT = {"colors": ["#ffe6e6", "#ff9999", "#cc0000"], "minValue": 0.0, "maxValue": 1.0}


def navigator_layer(mappings: list[Any], *, name: str, sha256: str) -> dict:
    """Build an ATT&CK Navigator layer (spec v4.5) scored by technique confidence.

    ``mappings`` are ``AttackMapping``-shaped (technique_id, confidence, status,
    tactic, why). Sub-technique ids (``Txxxx.yyy``) are preserved — Navigator
    understands them natively."""
    techniques = []
    for m in mappings:
        techniques.append(
            {
                "techniqueID": m.technique_id,
                "score": round(float(m.confidence), 3),
                "color": "",
                "comment": f"[{m.status}] {m.why}"[:500],
                "enabled": True,
                "metadata": [
                    {"name": "status", "value": m.status},
                    {"name": "tactic", "value": m.tactic},
                ],
                "showSubtechniques": True,
            }
        )
    return {
        "name": f"SANDWORM · {name}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"SANDWORM analysis of {name} (sha256 {sha256}). "
                       "Score = per-technique confidence; comment = evidence.",
        "sorting": 3,
        "gradient": dict(_NAV_GRADIENT),
        "techniques": techniques,
        "metadata": [{"name": "sha256", "value": sha256}],
    }


def _stix_id(kind: str, seed: str) -> str:
    """Deterministic STIX id so re-exports of the same run are stable/deduplicable."""
    digest = hashlib.sha256(f"{kind}:{seed}".encode()).hexdigest()
    return f"{kind}--{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _stix_pattern(kind: str, value: str) -> str | None:
    v = value.replace("'", "\\'")
    if kind == "url":
        return f"[url:value = '{v}']"
    if kind == "domain":
        return f"[domain-name:value = '{v}']"
    if kind == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if kind in ("md5", "sha256"):
        return f"[file:hashes.'{kind.upper()}' = '{v}']"
    return None


def stix_bundle(store, mappings: list[Any], *, sha256: str, name: str) -> dict:
    """Assemble a STIX 2.1 bundle: one attack-pattern per technique, one indicator
    per IOC, and relationships from the sample's malware SDO."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict] = []

    malware_id = _stix_id("malware", sha256)
    objects.append({
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": now, "modified": now, "name": name, "is_family": False,
        "sample_refs": [], "description": f"SANDWORM-analysed sample sha256 {sha256}",
    })

    for m in mappings:
        ap_id = _stix_id("attack-pattern", m.technique_id)
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": now, "modified": now, "name": m.technique_name,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": m.technique_id}
            ],
        })
        rel = _stix_id("relationship", f"{sha256}:{m.technique_id}")
        objects.append({
            "type": "relationship", "spec_version": "2.1", "id": rel,
            "created": now, "modified": now, "relationship_type": "uses",
            "source_ref": malware_id, "target_ref": ap_id,
            "confidence": int(round(float(m.confidence) * 100)),
        })

    seen: set[tuple[str, str]] = set()
    for it in store:
        if not it.details.get("ioc"):
            continue
        kind, value = it.object.get("kind"), it.object.get("value")
        if not kind or not value or (kind, value) in seen:
            continue
        seen.add((kind, value))
        pattern = _stix_pattern(str(kind), str(value))
        if pattern is None:
            continue
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": _stix_id("indicator", f"{kind}:{value}"),
            "created": now, "modified": now,
            "name": f"{kind} observed in {name}",
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(round(float(it.confidence) * 100)),
            "labels": ["malicious-activity"],
        })

    return {"type": "bundle", "id": _stix_id("bundle", f"{sha256}:{now}"), "objects": objects}


def findings_json(result, summary) -> dict:
    """Compact, stable machine summary of a run for batch/CI consumers."""
    return {
        "run_id": result.run_id,
        "sample": {"name": result.sample.name, "sha256": result.sample.sha256, "size": result.sample.size},
        "format": result.triage.fmt,
        "isolated": result.isolated,
        "verdict": {
            "risk": summary.risk,
            "maliciousness": summary.maliciousness_score,
            "family_hint": summary.family_hint,
        },
        "techniques": [
            {
                "id": m.technique_id, "name": m.technique_name, "tactic": m.tactic,
                "confidence": round(float(m.confidence), 3), "status": m.status,
            }
            for m in result.mappings
        ],
        "iocs": [
            {"kind": it.object.get("kind"), "value": it.object.get("value"),
             "confidence": round(float(it.confidence), 3)}
            for it in result.store if it.details.get("ioc")
        ],
        "detections": {"yara": len(result.yara), "sigma": len(result.sigma),
                       "detectable": result.coverage.detectable},
        "evidence_count": len(result.store),
    }


def _iter_iocs(store) -> list[tuple[str, str, float]]:
    """Deduplicated (kind, value, confidence) IOCs from the store — the single
    source every IOC exporter draws from. Highest confidence wins on duplicates."""
    best: dict[tuple[str, str], float] = {}
    for it in store:
        if not it.details.get("ioc"):
            continue
        kind, value = it.object.get("kind"), it.object.get("value")
        if not kind or not value:
            continue
        key = (str(kind), str(value))
        conf = float(it.confidence)
        if conf > best.get(key, -1.0):
            best[key] = conf
    return [(k, v, c) for (k, v), c in best.items()]


# IOC kind → (MISP type, MISP category). MISP has precise types per indicator.
_MISP_TYPE = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
}

# IOC kind → OpenIOC search term (Mandiant IOC terms).
_OPENIOC_TERM = {
    "url": "Network/URI",
    "domain": "Network/DNS",
    "ipv4": "Network/Connection/IP",
    "email": "Email/From",
    "md5": "FileItem/Md5sum",
    "sha256": "FileItem/Sha256sum",
}


def misp_event(store, mappings: list[Any], *, sha256: str, name: str) -> dict:
    """A MISP event (core-format JSON) with IOC attributes and ATT&CK Galaxy tags.
    POST straight to a MISP instance's ``/events/add`` or import via the UI."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    attributes: list[dict] = [{
        "type": "sha256", "category": "Payload delivery", "to_ids": True,
        "value": sha256, "comment": f"analysed sample: {name}",
    }]
    for kind, value, conf in _iter_iocs(store):
        mapping = _MISP_TYPE.get(kind)
        if not mapping:
            continue
        misp_type, category = mapping
        attributes.append({
            "type": misp_type, "category": category,
            "to_ids": conf >= 0.5,  # only high-confidence indicators drive detection
            "value": value, "comment": f"SANDWORM confidence {conf:.2f}",
        })
    tags = [{"name": f'misp-galaxy:mitre-attack-pattern="{m.technique_name} - {m.technique_id}"'}
            for m in mappings]
    tags.append({"name": "tlp:amber"})
    return {"Event": {
        "info": f"SANDWORM · {name}",
        "date": now[:10], "threat_level_id": "2", "analysis": "2", "distribution": "0",
        "Attribute": attributes,
        "Tag": tags,
    }}


def openioc_xml(store, *, sha256: str, name: str) -> str:
    """Mandiant OpenIOC 1.1 XML. IOCs become IndicatorItems OR'd under one
    top-level Indicator (any match ⇒ hit), the standard OpenIOC shape."""
    ioc_id = hashlib.sha256(f"openioc:{sha256}".encode()).hexdigest()
    items = []
    for kind, value, _conf in _iter_iocs(store):
        term = _OPENIOC_TERM.get(kind)
        if not term:
            continue
        context, doc = term.split("/", 1)[0], term
        items.append(
            f'      <IndicatorItem condition="contains">\n'
            f'        <Context document="{context}" search="{doc}" type="mir"/>\n'
            f'        <Content type="string">{_xml_escape(value)}</Content>\n'
            f'      </IndicatorItem>'
        )
    items_xml = "\n".join(items) if items else "      <!-- no network/file IOCs recovered -->"
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="{ioc_id[:8]}-'
        f'{ioc_id[8:12]}-{ioc_id[12:16]}-{ioc_id[16:20]}-{ioc_id[20:32]}">\n'
        f'  <short_description>SANDWORM · {_xml_escape(name)}</short_description>\n'
        f'  <authored_by>SANDWORM</authored_by>\n'
        '  <links/>\n'
        '  <definition>\n'
        '    <Indicator operator="OR" id="' + ioc_id[:8] + '-0000-0000-0000-000000000000">\n'
        f'{items_xml}\n'
        '    </Indicator>\n'
        '  </definition>\n'
        '</ioc>\n'
    )


def ioc_csv(store, *, sha256: str, name: str) -> str:
    """Flat CSV indicator dump: kind,value,confidence,sample,sha256."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["kind", "value", "confidence", "sample", "sha256"])
    for kind, value, conf in sorted(_iter_iocs(store)):
        w.writerow([kind, value, f"{conf:.3f}", name, sha256])
    return buf.getvalue()


_RISK_TO_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Clean": "none"}


def sarif_log(entries: list[tuple[Any, Any]]) -> dict:
    """A SARIF 2.1.0 log for a batch of samples so results drop into code-scanning
    dashboards / CI. ``entries`` is a list of ``(RunResult, summary)`` pairs. Each
    mapped technique becomes a SARIF rule; each (sample, technique) a result whose
    level follows the sample's risk."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for result, summary in entries:
        level = _RISK_TO_SARIF_LEVEL.get(summary.risk, "warning")
        for m in result.mappings:
            if m.technique_id not in rules:
                rules[m.technique_id] = {
                    "id": m.technique_id,
                    "name": m.technique_name,
                    "shortDescription": {"text": f"{m.technique_id} {m.technique_name}"},
                    "helpUri": f"https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}/",
                    "properties": {"tactic": m.tactic},
                }
            results.append({
                "ruleId": m.technique_id,
                "level": level,
                "message": {"text": f"[{m.status}] {m.why}"[:1000]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": result.sample.name},
                    }
                }],
                "properties": {
                    "confidence": round(float(m.confidence), 3),
                    "sha256": result.sample.sha256,
                    "risk": summary.risk,
                },
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SANDWORM",
                "informationUri": "https://github.com/theloav/sandworm",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def dumps(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=False)
