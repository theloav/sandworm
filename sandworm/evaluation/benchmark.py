"""Hash-pinned static ATT&CK benchmark with explicit positive/negative judgments."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import replace
from pathlib import Path

from .. import __version__
from ..core.config import Config
from ..core.pipeline import analyze_sample
from ..core.sample import Sample
from .metrics import calibration, classification, reliability_svg


def evaluate(manifest_path: Path, *, threshold: float = 0.5, split: str | None = None) -> dict:
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be in [0, 1]")
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if manifest.get("schema_version") != 1 or not manifest.get("cases"):
        raise ValueError("nonempty schema_version=1 benchmark required")
    root = manifest_path.parent.resolve()
    selected_cases = manifest["cases"]
    if split is not None:
        from .corpus_review import audit_corpus
        if split not in {"train", "validation", "test"}:
            raise ValueError("split must be train, validation or test")
        review = audit_corpus(manifest_path)
        if not review["ready_for_scoped_evaluation"]:
            raise ValueError("corpus review failed: " + "; ".join(review["issues"][:5]))
        selected_cases = [case for case in selected_cases if case["split"] == split]
    counts: dict[str, list[int]] = {}
    decisions, emitted, cases = [], [], []
    seen = set()
    with tempfile.TemporaryDirectory(prefix="sw-eval-") as temporary:
        cfg = replace(Config(work_dir=Path(temporary)), llm_provider="mock", neo4j_uri=None)
        for case in selected_cases:
            if case["id"] in seen:
                raise ValueError("duplicate case id")
            seen.add(case["id"])
            path = (root / case["path"]).resolve()
            if not path.is_relative_to(root):
                raise ValueError("benchmark paths must remain inside the corpus")
            sample = Sample.from_path(path, cfg)
            if sample.sha256 != case["sha256"]:
                raise ValueError(f"benchmark identity mismatch: {case['id']}")
            positive, negative = set(case["positive"]), set(case["negative"])
            if positive & negative or not positive | negative or not case.get("rationale"):
                raise ValueError("disjoint explicit judgments and rationale required")
            if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", t) for t in positive | negative):
                raise ValueError("invalid technique identifier")
            result = analyze_sample(sample, config=cfg, enable_dynamic=False, use_cache=False)
            scores = {m.technique_id: m.confidence for m in result.mappings}
            predictions = {t for t, p in scores.items() if p >= threshold}
            for technique in sorted(positive | negative):
                label = int(technique in positive)
                probability = scores.get(technique, 0.0)
                decisions.append((probability, label))
                if technique in scores:
                    emitted.append((probability, label))
                # Order TP, FP, FN, TN. Unknown labels are never assumed negative.
                bucket = 0 if technique in predictions and label else 1 if technique in predictions else 2 if label else 3
                counts.setdefault(technique, [0, 0, 0, 0])[bucket] += 1
            cases.append({"id": case["id"], "sha256": sample.sha256, "scores": scores,
                          "false_positives": sorted(predictions & negative),
                          "false_negatives": sorted(positive - predictions),
                          "unjudged_predictions": sorted(predictions - positive - negative)})
    totals = [sum(row[i] for row in counts.values()) for i in range(4)]
    return {"schema_version": 1, "sandworm_version": __version__, "corpus": manifest.get("name"),
            "corpus_kind": manifest.get("kind", "unspecified"), "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "threshold": threshold, "micro": classification(*totals),
            "split": split, "label_policy": manifest.get("label_policy", "legacy broad static-presence fixtures; provisional"),
            "measurement_status": "measurement infrastructure; not calibrated-model validation",
            "per_technique": {t: classification(*row) for t, row in sorted(counts.items())},
            "calibration_emitted": calibration(emitted), "calibration_decisions": calibration(decisions),
            "calibration_note": "Emitted: judged claims only. Decisions: all judged pairs, absent mappings scored 0 (not a Bayesian posterior). Neither implies deployment calibration.",
            "cases": cases}


def write_results(report: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "metrics.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "reliability.svg").write_text(reliability_svg(report["calibration_emitted"]))
    rows = ["# ATT&CK benchmark", "", f"Corpus: {report['corpus']} ({report['corpus_kind']})", "",
            "| Technique | TP | FP | FN | Precision | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for technique, row in report["per_technique"].items():
        def number(value):
            return "N/A" if value is None else f"{value:.3f}"
        rows.append(f"| {technique} | {row['tp']} | {row['fp']} | {row['fn']} | {number(row['precision'])} | {number(row['recall'])} |")
    rows.extend(["", report["calibration_note"], "", "![Reliability](reliability.svg)"])
    (output / "summary.md").write_text("\n".join(rows) + "\n")
