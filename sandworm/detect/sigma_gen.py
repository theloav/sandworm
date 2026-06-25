"""Generate Sigma rules from behavioral evidence.

Sigma describes log-based detections (process creation, network, registry). We
translate behavioral EvidenceItems into Sigma detection blocks with a tactic tag
drawn from the ATT&CK mapping. Output is valid Sigma YAML (emitted by hand to
avoid a YAML dependency).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.evidence import EvidenceStore
from ..reconstruct.attack_map import AttackMapping


@dataclass
class SigmaRule:
    title: str
    logsource: dict
    detection: dict
    level: str = "high"
    tags: list[str] = field(default_factory=list)
    description: str = ""

    def to_yaml(self) -> str:
        lines = [
            f"title: {self.title}",
            f"description: {self.description}",
            "status: experimental",
            "author: SANDWORM",
            "logsource:",
        ]
        for k, v in self.logsource.items():
            lines.append(f"    {k}: {v}")
        lines.append("detection:")
        for sel_name, fields in self.detection.items():
            if sel_name == "condition":
                continue
            lines.append(f"    {sel_name}:")
            for fk, fv in fields.items():
                if isinstance(fv, list):
                    lines.append(f"        {fk}:")
                    for item in fv:
                        lines.append(f"            - {item}")
                else:
                    lines.append(f"        {fk}: {fv}")
        lines.append(f"    condition: {self.detection.get('condition', 'selection')}")
        if self.tags:
            lines.append("tags:")
            for t in self.tags:
                lines.append(f"    - {t}")
        lines.append(f"level: {self.level}")
        return "\n".join(lines)


def _attack_tag(mappings: list[AttackMapping], predicate) -> list[str]:
    tags = []
    for m in mappings:
        if predicate(m):
            tags.append(f"attack.{m.tactic.replace('-', '_')}")
            tags.append(f"attack.{m.technique_id.lower()}")
    return sorted(set(tags))


def generate_sigma(store: EvidenceStore, mappings: list[AttackMapping]) -> list[SigmaRule]:
    rules: list[SigmaRule] = []

    # 1) Process/command execution rule from command sinks & process spawns.
    cmd_targets: list[str] = []
    for it in store:
        if it.artifact in {"process", "api_call", "macro"} and it.operation in {"exec", "spawn"}:
            tgt = it.object.get("sink") or it.object.get("command") or it.object.get("api")
            if tgt:
                cmd_targets.append(str(tgt))
    if cmd_targets:
        rules.append(
            SigmaRule(
                title="SANDWORM: Suspicious command/script execution",
                description="Execution sinks observed during SANDWORM analysis",
                logsource={"category": "process_creation"},
                detection={
                    "selection": {"CommandLine|contains": sorted(set(cmd_targets))[:15]},
                    "condition": "selection",
                },
                tags=_attack_tag(mappings, lambda m: m.tactic == "execution"),
            )
        )

    # 2) Network/C2 rule from network egress evidence.
    hosts: list[str] = []
    for it in store:
        if it.artifact in {"network", "host"} and it.operation in {"connect", "resolve"}:
            h = it.object.get("host") or it.object.get("value")
            if h:
                hosts.append(str(h))
    if hosts:
        rules.append(
            SigmaRule(
                title="SANDWORM: C2 / network egress indicator",
                description="Network destinations observed/extracted during analysis",
                logsource={"category": "network_connection"},
                detection={
                    "selection": {"DestinationHostname|contains": sorted(set(hosts))[:15]},
                    "condition": "selection",
                },
                level="medium",
                tags=_attack_tag(mappings, lambda m: m.tactic == "command-and-control"),
            )
        )

    # 3) Registry persistence rule.
    keys = [str(it.object.get("key")) for it in store if it.artifact == "registry" and it.operation == "write" and it.object.get("key")]
    if keys:
        rules.append(
            SigmaRule(
                title="SANDWORM: Registry persistence",
                description="Registry writes consistent with persistence",
                logsource={"category": "registry_set"},
                detection={"selection": {"TargetObject|contains": sorted(set(keys))[:15]}, "condition": "selection"},
                tags=_attack_tag(mappings, lambda m: m.tactic == "persistence"),
            )
        )

    return rules
