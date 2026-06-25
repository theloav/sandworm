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
    NODE_CAPABILITY,
    NODE_DETECTION,
    NODE_EVIDENCE,
    NODE_FILE,
    NODE_HOST,
    NODE_MACRO,
    NODE_MODULE,
    NODE_PROCESS,
    NODE_REGISTRY,
    NODE_SAMPLE,
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


def build_graph(store: EvidenceStore, mappings: list[AttackMapping] | None = None, graph=None, sample_name: str = "sample"):
    """Construct a *reasoning* graph: Sample → entity/capability → Technique →
    Detection, with typed edges so each step has meaning (and the Evidence nodes
    backing every claim retained for citations/drill-down)."""
    graph = graph or get_graph()
    if mappings is None:
        mappings = map_evidence(store)

    sample_node = _node_key(NODE_SAMPLE, sample_name)
    graph.add_node(Node(sample_node, NODE_SAMPLE, {"display": sample_name}))

    # evidence id -> the entity node it is about (so we can wire entity→technique)
    ev_to_obj: dict[str, str] = {}

    for it in store:
        # Benign library/toolchain artifacts must not participate in reasoning —
        # they are kept in the evidence store for context but never become graph
        # nodes (no analyst wants golang.org in the ATT&CK chain).
        if it.details.get("library_artifact"):
            continue
        # Capability findings get their own node type so the chain reads
        # "Sample → Capability(ransomware) → Technique(T1486)".
        if it.object.get("capability"):
            label = NODE_CAPABILITY
        else:
            label = _ARTIFACT_LABEL.get(it.artifact, NODE_STRING)
        obj_id, obj_props = _object_identity(it)
        obj_node_id = _node_key(label, obj_id)
        graph.add_node(Node(obj_node_id, label, {"display": obj_id, **obj_props}))
        ev_to_obj[it.id] = obj_node_id
        # The sample contains/exhibits this entity.
        graph.add_edge(Edge(sample_node, obj_node_id, "CONTAINS", {}))

        # Evidence node (retained for citations + drill-down).
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
            if subj_props.get("kind") in {"name", "pid"}:
                subj_node_id = _node_key(NODE_PROCESS, subj_id)
                graph.add_node(Node(subj_node_id, NODE_PROCESS, {"display": subj_id, **subj_props}))
                graph.add_edge(
                    Edge(subj_node_id, obj_node_id, it.operation.upper(), {"confidence": it.confidence, "evidence": it.id, "ts": it.ts})
                )

    # ATT&CK technique nodes. Wire BOTH evidence→technique (citations) and the
    # backing entity→technique (the visible reasoning chain).
    for m in mappings:
        tech_id = _node_key(NODE_TECHNIQUE, m.technique_id)
        graph.add_node(
            Node(
                tech_id,
                NODE_TECHNIQUE,
                {"display": f"{m.technique_id} {m.technique_name}", "tactic": m.tactic, "confidence": m.confidence, "why": m.why, "status": m.status},
            )
        )
        for eid in m.evidence_ids:
            graph.add_edge(Edge(_node_key(NODE_EVIDENCE, eid), tech_id, "MAPS_TO", {"confidence": m.confidence}))
            obj_node = ev_to_obj.get(eid)
            if obj_node:
                graph.add_edge(Edge(obj_node, tech_id, "INDICATES", {"confidence": m.confidence}))

    return graph


def add_detections_to_graph(graph, mappings: list[AttackMapping], yara=None, sigma=None) -> None:
    """Attach generated detections to the techniques they cover, completing the
    chain Technique → Detection (the defender-facing tail of the reasoning graph)."""
    tech_nodes = {n.props.get("display", "").split(" ", 1)[0]: n.id for n in graph.find_nodes(label=NODE_TECHNIQUE)}
    for rule in yara or []:
        rid = _node_key(NODE_DETECTION, f"yara:{rule.name}")
        graph.add_node(Node(rid, NODE_DETECTION, {"display": f"YARA {rule.name}", "kind": "yara"}))
        # YARA is a static signature for the whole sample; link to all techniques.
        for tid in tech_nodes.values():
            graph.add_edge(Edge(tid, rid, "DETECTED_BY", {}))
    for rule in sigma or []:
        rid = _node_key(NODE_DETECTION, f"sigma:{rule.title[:24]}")
        graph.add_node(Node(rid, NODE_DETECTION, {"display": f"Sigma ({rule.kind})", "kind": "sigma"}))
        for tag in rule.tags:
            t = tag.replace("attack.", "").upper()
            if t in tech_nodes:
                graph.add_edge(Edge(tech_nodes[t], rid, "DETECTED_BY", {}))


def graph_summary(graph) -> dict:
    stats = graph.stats()
    techniques = [n.props.get("display") for n in graph.find_nodes(label=NODE_TECHNIQUE)]
    return {"backend": getattr(graph, "backend", "memory"), **stats, "techniques": techniques}


def in_memory() -> InMemoryGraph:
    return InMemoryGraph()
