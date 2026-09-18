"""Dependency-free binary classification and probability calibration metrics."""
from __future__ import annotations

import math


def wilson(hits: int, count: int) -> list[float] | None:
    if count == 0:
        return None
    z = 1.959963984540054
    p = hits / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    radius = z * math.sqrt(p * (1 - p) / count + z * z / (4 * count**2)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def classification(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def calibration(rows: list[tuple[float, int]], bins: int = 10) -> dict:
    if not 1 <= bins <= 100:
        raise ValueError("bins must be in [1, 100]")
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for probability, label in rows:
        if not math.isfinite(probability) or not 0 <= probability <= 1 or label not in (0, 1):
            raise ValueError("calibration requires finite probabilities and binary labels")
        buckets[min(int(probability * bins), bins - 1)].append((probability, label))
    points = []
    ece = 0.0
    for index, bucket in enumerate(buckets):
        count = len(bucket)
        mean = sum(p for p, _ in bucket) / count if count else None
        accuracy = sum(y for _, y in bucket) / count if count else None
        if count:
            assert mean is not None and accuracy is not None
            ece += count * abs(mean - accuracy)
        points.append({"lower": index / bins, "upper": (index + 1) / bins, "count": count,
                       "mean_confidence": mean, "accuracy": accuracy,
                       "accuracy_wilson95": wilson(sum(y for _, y in bucket), count)})
    return {"n": len(rows), "brier": sum((p - y)**2 for p, y in rows) / len(rows) if rows else None,
            "ece": ece / len(rows) if rows else None, "bins": points}


def reliability_svg(result: dict) -> str:
    # Numeric values only: no corpus/sample text enters SVG markup.
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 480" role="img" aria-label="Reliability diagram">',
             '<rect width="500" height="480" fill="white"/>',
             '<path d="M60 40 V400 H460 M60 400 L420 40" fill="none" stroke="#888"/>',
             '<text x="150" y="450">Mean reported confidence</text>',
             '<text x="65" y="22">Observed correctness (95% Wilson intervals)</text>',
             '<text x="45" y="420">0</text><text x="415" y="420">1</text><text x="35" y="45">1</text>']
    for point in result["bins"]:
        if not point["count"]:
            continue
        x = 60 + 360 * point["mean_confidence"]
        y = 400 - 360 * point["accuracy"]
        low, high = point["accuracy_wilson95"]
        parts.append(f'<path d="M{x:.2f} {400 - 360 * high:.2f} V{400 - 360 * low:.2f}" stroke="#1260aa"/>')
        parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="5" fill="#1260aa"><title>n={point["count"]}</title></circle>')
    return "\n".join(parts + ["</svg>"])
