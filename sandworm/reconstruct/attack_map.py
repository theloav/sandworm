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
from ..core.provenance import INFERRED, provenance_of, strongest

# Cap how many distinct observations are spelled out in a mapping's "why".
_WHY_MAX_CLAUSES = 6

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
    status: str = INFERRED  # observed | inferred | speculative

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
            "PHP web shell: payload reaches a code/command execution sink ({detail})",
        ),
        _Rule(
            "T1056.001", "Input Capture: Keylogging", "collection", 0.6,
            lambda it: has_sink("setwindowshookex")(it),
            "keylogging hook installed: {detail}",
        ),
        _Rule(
            "T1486", "Data Encrypted for Impact", "impact", 0.7,
            lambda it: has_sink("cryptencrypt", "cryptgenkey")(it)
            or it.object.get("capability") == "ransomware",
            "encryption / ransomware indicators: {detail}",
        ),
        _Rule(
            "T1490", "Inhibit System Recovery", "impact", 0.85,
            lambda it: it.object.get("capability") == "inhibit_recovery"
            or has_sink("vssadmin", "wbadmin", "bcdedit")(it),
            "shadow-copy / backup deletion: {detail}",
        ),
        _Rule(
            "T1552.001", "Credentials In Files", "credential-access", 0.85,
            lambda it: it.details.get("canary_kind") in {"aws_key", "credential", "password"},
            "accessed planted credential canary: {detail}",
        ),
    ]


def _detail_for(it: EvidenceItem) -> str:
    # Surface the concrete indicators behind capability findings (e.g. ransomware)
    # so the "why" is transparent rather than just "capability=ransomware".
    if it.object.get("indicators"):
        inds = it.object["indicators"]
        return f"{it.object.get('capability', 'indicators')}: {', '.join(map(str, inds[:6]))}"
    for key in ("sink", "api", "import", "symbol", "function", "command", "value", "key", "host", "verdict", "capability", "yara_rule"):
        if key in it.object:
            return f"{key}={it.object[key]}"
    if it.details.get("decoded_preview"):
        return f"decoded {it.details.get('decoded_len', '?')} bytes"
    return it.artifact + "/" + it.operation


def map_evidence(store: EvidenceStore) -> list[AttackMapping]:
    """Produce ATT&CK mappings, one per technique, with aggregated evidence and
    an epistemic ``status`` (observed/inferred/speculative) derived from which
    lanes the backing evidence came from."""
    rules = _rules()
    agg: dict[str, AttackMapping] = {}
    prov: dict[str, list[str]] = {}  # technique_id -> contributing provenances
    for it in store:
        item_prov = provenance_of(it.source, it.confidence)
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
            prov.setdefault(rule.technique_id, []).append(item_prov)
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
                # Keep the explanation readable: list the first few distinct
                # observations, then summarize the rest rather than emitting a
                # wall of text. (evidence_ids still record every backing item.)
                if detail not in existing.why and existing.why.count("; ") < _WHY_MAX_CLAUSES:
                    existing.why += f"; {why}"
    for tid, mapping in agg.items():
        mapping.status = strongest(prov.get(tid, []))
    # Stable order: by tactic order then technique id.
    order = {t: i for i, t in enumerate(TACTICS)}
    out = sorted(agg.values(), key=lambda m: (order.get(m.tactic, 99), m.technique_id))
    for m in out:
        extra = len(m.evidence_ids) - (m.why.count("; ") + 1)
        if extra > 0:
            m.why += f" (+{extra} more corroborating observations)"
    return out


def tactic_coverage(mappings: list[AttackMapping]) -> dict[str, list[str]]:
    cov: dict[str, list[str]] = {}
    for m in mappings:
        cov.setdefault(m.tactic, []).append(m.technique_id)
    return cov
