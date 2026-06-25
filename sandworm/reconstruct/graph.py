"""Build the behavioral graph from the EvidenceStore.

Nodes: processes / files / registry keys / hosts / modules / macros / strings /
api-calls / techniques. Edges: an actor (subject) ACTED-ON an object, plus
EVIDENCE links to the raw item and MAPS-TO links to ATT&CK techniques. The graph
is the queryable substrate for the copilot and the report. Neo4j if available,
in-memory otherwise — same code path.
"""

from __future__ import annotations

from ..core.evidence import EvidenceStore
from ..graphdb.client import InMemoryGraph, get_graph
from ..graphdb.schema import (
    NODE_API,
    NODE_EVIDENCE,
    NODE_FILE,
    NODE_HOST,
    NODE_MACRO,
    NODE_MODULE,
    NODE_PROCESS,
    NODE_REGISTRY,
    NODE_STRING,
    NODE_TECHNIQUE,
    Edge,
    Node,
)
from .attack_map import AttackMapping, map_evidence

_ARTIFACT_LABEL = {
    "process": NODE_PROCESS,
    "file": NODE_FILE,
    "registry": NODE_REGISTRY,
    "network": NODE_HOST,
    "module": NODE_MODULE,
    "macro": NODE_MACRO,
    "string": NODE_STRING,
    "api_call": NODE_API,
    "thread": NODE_PROCESS,
    "callback": NODE_API,
}


def _node_key(label: str, ident: str) -> str:
    return f"{label}:{ident}"


def _object_identity(it) -> tuple[str, dict]:
    """Derive a stable identity + display props for the object of an evidence item."""
    obj = it.object
    for key in ("path", "name", "host", "value", "key", "sink", "api", "function", "yara_rule", "verdict", "command", "import", "symbol", "capability"):
        if key in obj and obj[key] not in (None, ""):
            return str(obj[key]), {"kind": key, **{k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool))}}
    return it.artifact + ":" + it.operation, {k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool))}


def _subject_identity(it) -> tuple[str, dict] | None:
    subj = it.subject
    for key in ("name", "pid", "analyzer"):
        if key in subj and subj[key] not in (None, ""):
            return str(subj[key]), {"kind": key, **{k: v for k, v in subj.items() if isinstance(v, (str, int, float, bool))}}
    return None


def build_graph(store: EvidenceStore, mappings: list[AttackMapping] | None = None, graph=None):
    """Construct (or extend) a behavioral graph. Returns the graph backend."""
    graph = graph or get_graph()
    if mappings is None:
        mappings = map_evidence(store)

    for it in store:
        label = _ARTIFACT_LABEL.get(it.artifact, NODE_STRING)
        obj_id, obj_props = _object_identity(it)
        obj_node_id = _node_key(label, obj_id)
        graph.add_node(Node(obj_node_id, label, {"display": obj_id, **obj_props}))

        # Evidence node (so the report/copilot can cite the raw item).
        ev_id = _node_key(NODE_EVIDENCE, it.id)
        graph.add_node(
            Node(
                ev_id,
                NODE_EVIDENCE,
                {
                    "source": it.source,
                    "operation": it.operation,
                    "artifact": it.artifact,
                    "confidence": it.confidence,
                    "ts": it.ts,
                    "summary": f"{it.source} {it.operation} {obj_id}",
                },
            )
        )
        graph.add_edge(Edge(ev_id, obj_node_id, "ABOUT", {}))

        subj = _subject_identity(it)
        if subj:
            subj_id, subj_props = subj
            # Only make a distinct actor node for process-like subjects.
            if subj_props.get("kind") in {"name", "pid"}:
                subj_node_id = _node_key(NODE_PROCESS, subj_id)
                graph.add_node(Node(subj_node_id, NODE_PROCESS, {"display": subj_id, **subj_props}))
                graph.add_edge(
                    Edge(subj_node_id, obj_node_id, it.operation.upper(), {"confidence": it.confidence, "evidence": it.id, "ts": it.ts})
                )

    # ATT&CK technique nodes + links to their backing evidence.
    for m in mappings:
        tech_id = _node_key(NODE_TECHNIQUE, m.technique_id)
        graph.add_node(
            Node(
                tech_id,
                NODE_TECHNIQUE,
                {"display": f"{m.technique_id} {m.technique_name}", "tactic": m.tactic, "confidence": m.confidence, "why": m.why},
            )
        )
        for eid in m.evidence_ids:
            graph.add_edge(Edge(_node_key(NODE_EVIDENCE, eid), tech_id, "MAPS_TO", {"confidence": m.confidence}))

    return graph


def graph_summary(graph) -> dict:
    stats = graph.stats()
    techniques = [n.props.get("display") for n in graph.find_nodes(label=NODE_TECHNIQUE)]
    return {"backend": getattr(graph, "backend", "memory"), **stats, "techniques": techniques}


def in_memory() -> InMemoryGraph:
    return InMemoryGraph()
