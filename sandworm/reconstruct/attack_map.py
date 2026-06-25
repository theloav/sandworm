"""ATT&CK mapping with confidence AND an explanation.

Every mapping answers *why*: it names the concrete EvidenceItems that triggered
it. No bare technique IDs are ever emitted. Mapping is rule-based over the
normalized evidence schema, so it works identically across formats (a PHP
``system()`` sink and a CAPE ``CreateProcess`` both map to Command & Scripting
Interpreter execution).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass

from ..core.evidence import EvidenceItem, EvidenceStore

# ATT&CK tactic order, used by the coverage report + narrative phases.
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


@dataclass
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    why: str
    evidence_ids: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Rule:
    technique_id: str
    technique_name: str
    tactic: str
    base_conf: float
    match: Callable[[EvidenceItem], bool]
    why_tmpl: str


def _obj_str(it: EvidenceItem) -> str:
    return " ".join(str(v) for v in {**it.object, **it.details}.values()).lower()


def _rules() -> list[_Rule]:
    def has_sink(*names: str) -> Callable[[EvidenceItem], bool]:
        wanted = {n.lower() for n in names}

        def f(it: EvidenceItem) -> bool:
            sink = str(it.object.get("sink", "")).lower()
            api = str(it.object.get("api", "")).lower()
            fn = str(it.object.get("function", "")).lower()
            return bool({sink, api, fn} & wanted) or any(n in _obj_str(it) for n in wanted)

        return f

    return [
        _Rule(
            "T1059", "Command and Scripting Interpreter", "execution", 0.9,
            lambda it: it.artifact in {"api_call", "process", "macro"}
            and (has_sink("system", "exec", "shell_exec", "passthru", "proc_open", "popen", "eval", "assert", "shell", "invoke-expression")(it)),
            "observed execution sink: {detail}",
        ),
        _Rule(
            "T1059.004", "Unix Shell", "execution", 0.85,
            lambda it: has_sink("/dev/tcp", "download_exec", "execve", "reverse_shell", "netcat")(it)
            and any(tok in it.source for tok in ("shell", "elf", "linux")),
            "shell command-execution behavior: {detail}",
        ),
        _Rule(
            "T1027", "Obfuscated Files or Information", "defense-evasion", 0.9,
            lambda it: it.operation == "decode" and it.artifact == "string",
            "payload was statically de-obfuscated ({detail})",
        ),
        _Rule(
            "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion", 0.85,
            lambda it: it.operation == "decode" and "function" in it.object,
            "decoder routine applied: {detail}",
        ),
        _Rule(
            "T1055", "Process Injection", "defense-evasion", 0.92,
            lambda it: has_sink("writeprocessmemory", "createremotethread", "virtualallocex", "ptrace")(it),
            "memory-injection API present: {detail}",
        ),
        _Rule(
            "T1071", "Application Layer Protocol", "command-and-control", 0.7,
            lambda it: it.artifact == "network" and it.operation in {"connect", "resolve"},
            "network egress / C2 indicator: {detail}",
        ),
        _Rule(
            "T1105", "Ingress Tool Transfer", "command-and-control", 0.7,
            lambda it: has_sink("remote_download", "download_exec", "urldownloadtofile", "downloadstring", "invoke-webrequest")(it),
            "remote file download capability: {detail}",
        ),
        _Rule(
            "T1547.001", "Registry Run Keys / Startup Folder", "persistence", 0.7,
            lambda it: it.artifact == "registry" and it.operation == "write",
            "registry persistence write: {detail}",
        ),
        _Rule(
            "T1053", "Scheduled Task/Job", "persistence", 0.7,
            lambda it: has_sink("cron", "crontab", "schtasks")(it),
            "scheduling-based persistence: {detail}",
        ),
        _Rule(
            "T1059.001", "PowerShell", "execution", 0.8,
            lambda it: "powershell" in it.source and it.artifact in {"api_call", "string"} and it.operation in {"exec", "decode"},
            "PowerShell execution/obfuscation: {detail}",
        ),
        _Rule(
            "T1505.003", "Web Shell", "persistence", 0.85,
            lambda it: it.object.get("verdict") == "php_webshell",
            "obfuscated PHP unwraps to an execution sink (web shell): {detail}",
        ),
        _Rule(
            "T1056.001", "Input Capture: Keylogging", "collection", 0.6,
            lambda it: has_sink("setwindowshookex")(it),
            "keylogging hook installed: {detail}",
        ),
        _Rule(
            "T1486", "Data Encrypted for Impact", "impact", 0.5,
            lambda it: has_sink("cryptencrypt")(it),
            "bulk encryption capability: {detail}",
        ),
        _Rule(
            "T1552.001", "Credentials In Files", "credential-access", 0.85,
            lambda it: it.details.get("canary_kind") in {"aws_key", "credential", "password"},
            "accessed planted credential canary: {detail}",
        ),
    ]


def _detail_for(it: EvidenceItem) -> str:
    for key in ("sink", "api", "import", "symbol", "function", "command", "value", "key", "host", "verdict", "capability", "yara_rule"):
        if key in it.object:
            return f"{key}={it.object[key]}"
    if it.details.get("decoded_preview"):
        return f"decoded {it.details.get('decoded_len', '?')} bytes"
    return it.artifact + "/" + it.operation


def map_evidence(store: EvidenceStore) -> list[AttackMapping]:
    """Produce ATT&CK mappings, one per (technique) with aggregated evidence."""
    rules = _rules()
    agg: dict[str, AttackMapping] = {}
    for it in store:
        for rule in rules:
            try:
                if not rule.match(it):
                    continue
            except Exception:
                continue
            detail = _detail_for(it)
            why = rule.why_tmpl.format(detail=detail)
            # Combine confidence: take max of evidence confidence * rule base.
            conf = round(min(0.99, rule.base_conf * (0.5 + 0.5 * it.confidence) + 0.0), 3)
            existing = agg.get(rule.technique_id)
            if existing is None:
                agg[rule.technique_id] = AttackMapping(
                    technique_id=rule.technique_id,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    confidence=conf,
                    why=why,
                    evidence_ids=[it.id],
                )
            else:
                existing.evidence_ids.append(it.id)
                # More corroborating evidence raises confidence (capped).
                existing.confidence = round(min(0.99, max(existing.confidence, conf) + 0.03), 3)
                if detail not in existing.why:
                    existing.why += f"; {why}"
    # Stable order: by tactic order then technique id.
    order = {t: i for i, t in enumerate(TACTICS)}
    return sorted(agg.values(), key=lambda m: (order.get(m.tactic, 99), m.technique_id))


def tactic_coverage(mappings: list[AttackMapping]) -> dict[str, list[str]]:
    cov: dict[str, list[str]] = {}
    for m in mappings:
        cov.setdefault(m.tactic, []).append(m.technique_id)
    return cov
