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
    kind: str = "ioc"  # "ioc" (matches atoms that rotate) | "behavioral" (survives infra changes)

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

    # 2) Network/C2 rule from network egress evidence. Normalize URLs to
    # hostnames so DestinationHostname matches real telemetry (not full URLs).
    hosts: list[str] = []
    for it in store:
        if it.artifact in {"network", "host"} and it.operation in {"connect", "resolve"}:
            h = it.object.get("host") or it.object.get("value")
            if h:
                hosts.append(_hostname(str(h)))
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
                kind="behavioral",
            )
        )

    rules.extend(_behavioral_rules(store, mappings))
    return rules


def _hostname(value: str) -> str:
    """Reduce a URL/host to its bare hostname for DestinationHostname matching."""
    import re

    v = re.sub(r"^[a-z]+://", "", value, flags=re.I)
    return v.split("/")[0].split("?")[0].split(":")[0]


def _has_capability(store: EvidenceStore, capability: str) -> bool:
    return any(it.object.get("capability") == capability for it in store)


def _has_verdict(store: EvidenceStore, verdict: str) -> bool:
    return any(it.object.get("verdict") == verdict for it in store)


def _behavioral_rules(store: EvidenceStore, mappings: list[AttackMapping]) -> list[SigmaRule]:
    """Behavior-based rules that survive infrastructure changes (file/process
    patterns, not rotating IOCs). Derived from capability evidence."""
    out: list[SigmaRule] = []

    # Shadow-copy / recovery deletion — extremely high-signal, infra-independent.
    if _has_capability(store, "inhibit_recovery"):
        out.append(
            SigmaRule(
                title="SANDWORM: Shadow copy / backup deletion (ransomware pre-encryption)",
                description="Process deletes volume shadow copies or backups — classic ransomware pre-encryption step",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection_img": {"Image|endswith": ["\\vssadmin.exe", "\\wbadmin.exe", "\\bcdedit.exe", "\\wmic.exe"]},
                    "selection_cmd": {"CommandLine|contains|all": ["delete", "shadow"]},
                    "condition": "selection_img or selection_cmd",
                },
                tags=_attack_tag(mappings, lambda m: m.technique_id == "T1490") or ["attack.impact", "attack.t1490"],
                kind="behavioral",
            )
        )

    # Web shell — the *behavior* is a web-server worker spawning a shell. This
    # survives renaming the shell file / rotating the C2, unlike an IOC rule.
    if _has_verdict(store, "php_webshell"):
        out.append(
            SigmaRule(
                title="SANDWORM: Web server process spawning a shell (web shell)",
                description="A web-server worker (php/httpd/nginx/w3wp) spawns a command interpreter — classic web-shell command execution",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection_parent": {"ParentImage|endswith": ["\\php.exe", "\\php-cgi.exe", "\\httpd.exe", "\\w3wp.exe", "\\nginx.exe"]},
                    "selection_child": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\sh", "\\bash", "\\whoami.exe"]},
                    "condition": "selection_parent and selection_child",
                },
                tags=_attack_tag(mappings, lambda m: m.technique_id in {"T1505.003", "T1059"}) or ["attack.persistence", "attack.t1505.003"],
                kind="behavioral",
            )
        )

    # Mass file rewrite to a ransom extension — the encryption behavior itself.
    if _has_capability(store, "ransomware"):
        out.append(
            SigmaRule(
                title="SANDWORM: Ransomware file-encryption behavior",
                description="High-volume file writes to a ransom/encrypted extension plus a dropped ransom note",
                logsource={"category": "file_event", "product": "windows"},
                detection={
                    "selection_ext": {"TargetFilename|endswith": [".wnry", ".wncry", ".locky", ".crypt", ".encrypted"]},
                    "selection_note": {"TargetFilename|contains": ["DECRYPT", "README", "HOW_TO", "WanaDecryptor"]},
                    "condition": "selection_ext or selection_note",
                },
                tags=_attack_tag(mappings, lambda m: m.technique_id == "T1486") or ["attack.impact", "attack.t1486"],
                kind="behavioral",
            )
        )
    return out
