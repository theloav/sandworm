"""Repeatable matcher microbenchmark, including normalization and copying costs."""
from __future__ import annotations

import hashlib
import platform
import random
import statistics
import time

from ..analyzers.static.common import ransomware_scan


def matcher_benchmark(megabytes: int = 8, repeats: int = 5) -> dict:
    if not 1 <= megabytes <= 128 or not 1 <= repeats <= 20:
        raise ValueError("size/repeats outside benchmark bounds")
    data = random.Random(1729).randbytes(megabytes * 1024**2)
    data += b"Files have been encrypted .wncry VSSADMIN bitcoin" + "Your files are encrypted".encode("utf-16-le")
    expected = ransomware_scan(data, engine="regex")
    durations: dict[str, list[float]] = {"regex": [], "aho": []}
    for engine in durations:
        assert ransomware_scan(data, engine=engine) == expected  # warmup + semantic check
    # Alternate order to reduce systematic warm-cache/order bias.
    for iteration in range(repeats):
        for engine in ("regex", "aho") if iteration % 2 == 0 else ("aho", "regex"):
            start = time.perf_counter()
            result = ransomware_scan(data, engine=engine)
            durations[engine].append(time.perf_counter() - start)
            if result != expected:
                raise RuntimeError("matcher semantics differ")
    medians = {name: statistics.median(values) for name, values in durations.items()}
    return {"python": platform.python_version(), "platform": platform.platform(), "bytes": len(data),
            "data_sha256": hashlib.sha256(data).hexdigest(), "repeats": repeats,
            "seconds": durations, "median_seconds": medians, "regex_over_aho": medians["regex"] / medians["aho"],
            "scope": "Synthetic fixed-seed ransomware literal sweep only; not whole-pipeline throughput or peak RSS."}
