"""NL -> Cypher translation with a "show raw query" affordance.

Produces a Cypher query string from a natural-language question using intent
heuristics. The raw Cypher is always returned alongside the answer so an analyst
can inspect/adjust it. Against the in-memory backend the same intent drives a
keyword/label retrieval (the Cypher is shown for transparency and Neo4j use).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..graphdb.schema import (
    NODE_FILE,
    NODE_HOST,
    NODE_PROCESS,
    NODE_REGISTRY,
    NODE_TECHNIQUE,
)

_INTENTS = [
    (re.compile(r"\b(att&ck|attack|technique|mitre|t\d{4})\b", re.I), [NODE_TECHNIQUE]),
    (re.compile(r"\b(network|c2|host|connect|domain|ip|exfil)\b", re.I), [NODE_HOST]),
    (re.compile(r"\b(file|drop|write|payload|wrote)\b", re.I), [NODE_FILE]),
    (re.compile(r"\b(registry|persist|run key|autorun)\b", re.I), [NODE_REGISTRY]),
    (re.compile(r"\b(process|spawn|inject|exec|command)\b", re.I), [NODE_PROCESS]),
]


@dataclass
class CypherPlan:
    cypher: str
    labels: list[str]
    keywords: list[str]


def _keywords(question: str) -> list[str]:
    toks = re.findall(r"[A-Za-z0-9_.$/-]{3,}", question.lower())
    stop = {"the", "what", "which", "did", "does", "was", "were", "are", "this", "that", "sample", "show", "list", "find", "and", "for"}
    return [t for t in toks if t not in stop][:8]


def to_cypher(question: str) -> CypherPlan:
    labels: list[str] = []
    for pat, labs in _INTENTS:
        if pat.search(question):
            labels.extend(labs)
    if not labels:
        labels = []  # no label filter -> search all
    kws = _keywords(question)

    label_filter = "|".join(labels) if labels else ""
    node_pat = f"(n:{label_filter})" if label_filter else "(n)"
    where = ""
    if kws:
        conds = " OR ".join(f"toLower(toString(n)) CONTAINS '{k}'" for k in kws)
        where = f"WHERE {conds}\n"
    cypher = (
        f"MATCH {node_pat}\n"
        f"{where}"
        "OPTIONAL MATCH (e:Evidence)-[:ABOUT]->(n)\n"
        "RETURN n, collect(e) AS evidence\n"
        "LIMIT 50"
    )
    return CypherPlan(cypher=cypher, labels=labels, keywords=kws)
