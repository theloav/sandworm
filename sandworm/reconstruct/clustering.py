"""Unsupervised graph-feature clustering; clusters are not malware-family labels."""

from __future__ import annotations

import hashlib
from collections import Counter

from ..core.evidence import EvidenceStore
from ..graphdb.client import InMemoryGraph
from .graph import build_graph


def graph_features(store: EvidenceStore, rounds: int = 2) -> dict[str, int]:
    graph = build_graph(store, graph=InMemoryGraph())
    labels = {n.id: f"{n.label}:{n.props.get('operation', '')}:{n.props.get('source', '')}" for n in graph.nodes.values()}
    features = Counter(labels.values())
    # Weisfeiler–Lehman neighborhood labels encode graph structure without raw
    # process IDs, filenames or IOC strings dominating the distance.
    for _ in range(rounds):
        updated = {}
        for nid in labels:
            neighbors = sorted(f"{e.rel}:{labels.get(n.id, '')}" for e, n in graph.neighbors(nid))
            updated[nid] = hashlib.sha256((labels[nid] + "|" + "|".join(neighbors)).encode()).hexdigest()[:24]
        labels = updated
        features.update(labels.values())
    return dict(features)


def cluster_runs(stores: dict[str, EvidenceStore], *, distance: float = 0.3, min_samples: int = 2) -> dict:
    if not 0 < distance < 1 or min_samples < 2:
        raise ValueError("distance must be between 0 and 1; min_samples must be >=2")
    if len(stores) > 2000:
        raise ValueError("clustering is bounded to 2000 runs")
    try:
        from sklearn.cluster import DBSCAN
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.preprocessing import normalize
    except ImportError as exc:
        raise RuntimeError("install the ml extra for clustering") from exc
    if not stores:
        return {"clusters": {}, "outliers": [], "method": "WL graph features + cosine DBSCAN"}
    names = list(stores)
    vectors = DictVectorizer().fit_transform([graph_features(stores[n]) or {"empty": 1} for n in names])
    labels = DBSCAN(eps=distance, min_samples=min_samples, metric="cosine").fit_predict(normalize(vectors))
    groups: dict[str, list[str]] = {}
    outliers = []
    for name, label in zip(names, labels, strict=True):
        if label == -1:
            outliers.append(name)
        else:
            groups.setdefault(str(label), []).append(name)
    return {"clusters": groups, "outliers": outliers, "method": "WL graph features + cosine DBSCAN",
            "distance": distance, "warning": "similarity clusters require analyst validation; not family attribution"}
