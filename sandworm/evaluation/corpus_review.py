"""Audit declared annotation/split provenance before scoped held-out evaluation.

Checks metadata consistency, not annotator independence or label correctness.
Does not download samples, assign labels, or repair disagreements automatically.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path


def audit_corpus(path: Path, *, min_test_cases: int = 100) -> dict:
    document = json.loads(path.read_text())
    issues = []
    if document.get("label_policy") != "static-behavior-capability-v1":
        issues.append("explicit static-behavior-capability-v1 label policy required")
    rows = document.get("cases", [])
    splits: dict[str, list[date]] = {"train": [], "validation": [], "test": []}
    families: dict[str, set[str]] = {name: set() for name in splits}
    hashes, ids, annotators = set(), set(), set()
    root = path.parent.resolve()
    for row in rows:
        identity = str(row.get("id", ""))
        if not identity or identity in ids:
            issues.append(f"{identity}: missing/duplicate case ID")
        ids.add(identity)
        digest = row.get("sha256", "")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest in hashes:
            issues.append(f"{identity}: invalid/duplicate sample digest")
        hashes.add(str(digest))
        sample = (root / row.get("path", "")).resolve()
        try:
            if not sample.is_relative_to(root):
                raise ValueError("path outside corpus")
            with sample.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    raise ValueError("sample identity mismatch")
        except (OSError, ValueError):
            issues.append(f"{identity}: sample unavailable, changed or outside corpus")
        split = row.get("split")
        family = row.get("family")
        if split not in splits or not isinstance(family, str) or not family.strip():
            issues.append(f"{identity}: family/project group and train/validation/test split required")
        else:
            families[split].add(family.casefold())
            try:
                observed = date.fromisoformat(row.get("first_seen", ""))
                splits[split].append(observed)
            except (ValueError, TypeError):
                issues.append(f"{identity}: invalid first_seen date")
        if not row.get("provenance") or not row.get("rationale"):
            issues.append(f"{identity}: source provenance and label rationale required")
        positive, negative = set(row.get("positive", [])), set(row.get("negative", []))
        if positive & negative or not positive | negative or any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", label) for label in positive | negative):
            issues.append(f"{identity}: invalid or overlapping technique judgments")
        reviews = row.get("reviews", [])
        reviewers = {review.get("annotator") for review in reviews if isinstance(review.get("annotator"), str) and review["annotator"].strip()}
        annotators.update(reviewers)
        if len(reviewers) < 2 or len(reviewers) != len(reviews):
            issues.append(f"{identity}: at least two distinct identified reviews required")
        disagreement = any(set(review.get("positive", [])) != positive or set(review.get("negative", [])) != negative for review in reviews)
        if disagreement:
            resolution = row.get("adjudication", {})
            if not resolution.get("rationale") or not resolution.get("annotator") or resolution["annotator"] in reviewers:
                issues.append(f"{identity}: disagreement needs a separate identified adjudicator and rationale")
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        shared = families[left] & families[right]
        if shared:
            issues.append(f"family/project leakage between {left} and {right}: {','.join(sorted(shared))}")
        if splits[left] and splits[right] and max(splits[left]) >= min(splits[right]):
            issues.append(f"time leakage between {left} and {right}")
    if any(not values for values in splits.values()):
        issues.append("nonempty dated train, validation and test splits required")
    if len(splits["test"]) < min_test_cases:
        issues.append(f"test split has fewer than {min_test_cases} dated cases")
    return {"schema_version": 1, "ready_for_scoped_evaluation": not issues,
            "sample_count": len(rows), "split_counts": {name: len(values) for name, values in splits.items()},
            "declared_annotators": sorted(annotators), "minimum_test_cases": min_test_cases,
            "issues": issues, "scope": "Checks declared metadata and sample identity only; cannot verify reviewer independence, family attribution, dates, label correctness or population representativeness."}
