"""Behavioral-graph schema: node/edge shapes shared by both backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Node labels.
NODE_PROCESS = "Process"
NODE_FILE = "File"
NODE_REGISTRY = "Registry"
NODE_HOST = "Host"
NODE_MODULE = "Module"
NODE_MACRO = "Macro"
NODE_STRING = "String"
NODE_API = "ApiCall"
NODE_EVIDENCE = "Evidence"
NODE_TECHNIQUE = "Technique"


@dataclass
class Node:
    id: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    props: dict[str, Any] = field(default_factory=dict)
