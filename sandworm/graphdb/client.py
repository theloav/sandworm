"""Graph client: Neo4j when configured, in-memory fallback otherwise.

The in-memory graph is a first-class backend — the whole pipeline (build, query,
copilot) works without a database, which keeps CI and the synthetic demo offline.
Both backends expose the same minimal surface: ``add_node``, ``add_edge``,
``neighbors``, ``find_nodes``, and a tiny ``query`` used by the copilot.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..core.config import Config, get_config
from .schema import Edge, Node


class InMemoryGraph:
    backend = "memory"

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = defaultdict(list)
        self._radj: dict[str, list[Edge]] = defaultdict(list)

    def add_node(self, node: Node) -> None:
        if node.id in self.nodes:
            self.nodes[node.id].props.update(node.props)
        else:
            self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adj[edge.src].append(edge)
        self._radj[edge.dst].append(edge)

    def neighbors(self, node_id: str) -> list[tuple[Edge, Node]]:
        out = []
        for e in self._adj.get(node_id, []):
            if e.dst in self.nodes:
                out.append((e, self.nodes[e.dst]))
        for e in self._radj.get(node_id, []):
            if e.src in self.nodes:
                out.append((e, self.nodes[e.src]))
        return out

    def find_nodes(self, *, label: str | None = None, prop: tuple[str, Any] | None = None) -> list[Node]:
        out = []
        for n in self.nodes.values():
            if label and n.label != label:
                continue
            if prop and n.props.get(prop[0]) != prop[1]:
                continue
            out.append(n)
        return out

    def query(self, *, labels: list[str] | None = None, text: str | None = None, limit: int = 50) -> list[Node]:
        """Keyword/label retrieval used by the copilot's grounding step."""
        text_l = (text or "").lower()
        results: list[Node] = []
        for n in self.nodes.values():
            if labels and n.label not in labels:
                continue
            if text_l:
                hay = (n.id + " " + n.label + " " + " ".join(str(v) for v in n.props.values())).lower()
                if text_l not in hay and not any(tok in hay for tok in text_l.split() if len(tok) > 2):
                    continue
            results.append(n)
            if len(results) >= limit:
                break
        return results

    def stats(self) -> dict[str, int]:
        return {"nodes": len(self.nodes), "edges": len(self.edges)}


class Neo4jGraph:  # pragma: no cover - requires a running DB
    backend = "neo4j"

    def __init__(self, config: Config) -> None:
        from neo4j import GraphDatabase

        self._driver = GraphDatabase.driver(config.neo4j_uri, auth=(config.neo4j_user, config.neo4j_password))
        self._mirror = InMemoryGraph()  # keep a local mirror for query convenience

    def add_node(self, node: Node) -> None:
        self._mirror.add_node(node)
        with self._driver.session() as s:
            s.run(
                f"MERGE (n:{node.label} {{id:$id}}) SET n += $props",
                id=node.id,
                props=node.props,
            )

    def add_edge(self, edge: Edge) -> None:
        self._mirror.add_edge(edge)
        with self._driver.session() as s:
            s.run(
                "MATCH (a {id:$src}),(b {id:$dst}) "
                f"MERGE (a)-[r:{edge.rel}]->(b) SET r += $props",
                src=edge.src,
                dst=edge.dst,
                props=edge.props,
            )

    def neighbors(self, node_id: str):
        return self._mirror.neighbors(node_id)

    def find_nodes(self, **kw):
        return self._mirror.find_nodes(**kw)

    def query(self, **kw):
        return self._mirror.query(**kw)

    def run_cypher(self, cypher: str, **params) -> list[dict]:
        with self._driver.session() as s:
            return [dict(r) for r in s.run(cypher, **params)]

    def stats(self):
        return self._mirror.stats()


def get_graph(config: Config | None = None):
    """Return a Neo4j-backed graph if configured & reachable, else in-memory."""
    config = config or get_config()
    if config.neo4j_uri:
        try:  # pragma: no cover
            return Neo4jGraph(config)
        except Exception:
            pass
    return InMemoryGraph()
