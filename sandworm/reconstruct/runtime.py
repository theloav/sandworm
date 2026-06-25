"""Runtime reconstruction from dynamic/memory evidence.

Turns ``dynamic.*``/``memory.*`` process-spawn evidence into a process tree (the
"runtime graph" an analyst expects from a sandbox), plus compact summaries of the
other observed runtime facts (network, files, registry, injected regions). All of
this is empty on a static-only run — the report renders it as a *pending*
placeholder until a detonation/memory report is ingested.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore

_RUNTIME_PREFIXES = ("dynamic.", "memory.")


def _is_runtime(it) -> bool:
    return it.source.startswith(_RUNTIME_PREFIXES)


@dataclass
class ProcNode:
    pid: str
    name: str
    command_line: str = ""
    children: list[ProcNode] = field(default_factory=list)
    depth: int = 0


@dataclass
class RuntimeView:
    observed: bool
    process_tree: list[ProcNode]          # roots; pre-order flatten for rendering
    network: list[str]
    files: list[str]
    registry: list[str]
    injected: list[str]                   # injected/suspicious memory regions (malfind)

    def flatten(self) -> list[ProcNode]:
        out: list[ProcNode] = []

        def walk(n: ProcNode, depth: int) -> None:
            n.depth = depth
            out.append(n)
            for c in n.children:
                walk(c, depth + 1)

        for root in self.process_tree:
            walk(root, 0)
        return out


def build_runtime_view(store: EvidenceStore) -> RuntimeView:
    spawns = []
    network: list[str] = []
    files: list[str] = []
    registry: list[str] = []
    injected: list[str] = []
    observed = False

    for it in store:
        if not _is_runtime(it):
            continue
        if it.object.get("status") == "skipped":
            continue
        observed = True
        o = it.object
        if it.artifact == "process" and it.operation == "spawn":
            spawns.append(it)
        elif it.artifact == "process" and it.operation == "inject":
            injected.append(str(o.get("name") or o.get("Process") or o.get("pid") or "injected region"))
        elif it.artifact == "network":
            val = o.get("value") or o.get("host") or o.get("ForeignAddr")
            if val:
                network.append(str(val))
        elif it.artifact == "file":
            if o.get("path"):
                files.append(str(o["path"]))
        elif it.artifact == "registry":
            if o.get("key"):
                registry.append(str(o["key"]))

    tree = _build_tree(spawns)
    return RuntimeView(
        observed=observed,
        process_tree=tree,
        network=_dedupe(network),
        files=_dedupe(files),
        registry=_dedupe(registry),
        injected=_dedupe(injected),
    )


def _build_tree(spawns: list) -> list[ProcNode]:
    nodes: dict[str, ProcNode] = {}
    parent_of: dict[str, str | None] = {}
    for it in spawns:
        pid = str(it.object.get("pid"))
        if pid in (None, "None", ""):
            continue
        nodes[pid] = ProcNode(
            pid=pid,
            name=str(it.object.get("name") or it.object.get("ImageFileName") or "?"),
            command_line=str(it.details.get("command_line") or ""),
        )
        ppid = it.subject.get("pid")
        parent_of[pid] = str(ppid) if ppid not in (None, "None", "") else None

    roots: list[ProcNode] = []
    for pid, node in nodes.items():
        ppid = parent_of.get(pid)
        if ppid and ppid in nodes and ppid != pid:
            nodes[ppid].children.append(node)
        else:
            roots.append(node)
    return roots


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
