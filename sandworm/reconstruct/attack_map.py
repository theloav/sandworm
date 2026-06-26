"""ATT&CK mapping with confidence AND an explanation.

Every mapping answers *why*: it names the concrete EvidenceItems that triggered
it. No bare technique IDs are ever emitted. Mapping is rule-based over the
normalized evidence schema, so it works identically across formats (a PHP
``system()`` sink and a CAPE ``CreateProcess`` both map to Command & Scripting
Interpreter execution).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from ..core.evidence import EvidenceItem, EvidenceStore
from ..core.provenance import INFERRED, provenance_of, strongest
from .bayes import PRIOR, fuse

# Cap how many distinct observations are spelled out in a mapping's "why".
_WHY_MAX_CLAUSES = 6

# ATT&CK tactic order, used by the coverage report + narrative phases.
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Technique id -> (name, tactic). Lets any analyzer surface a technique simply by
# emitting ``details.attack_hint = "Txxxx"`` — no bespoke mapping rule required.
TECHNIQUE_INFO: dict[str, tuple[str, str]] = {
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1014": ("Rootkit", "defense-evasion"),
    "T1016": ("System Network Configuration Discovery", "discovery"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1055": ("Process Injection", "defense-evasion"),
    "T1056.004": ("Input Capture: Credential API Hooking", "collection"),
    "T1055.004": ("Process Injection: APC Injection", "defense-evasion"),
    "T1055.012": ("Process Injection: Process Hollowing", "defense-evasion"),
    "T1056.001": ("Input Capture: Keylogging", "collection"),
    "T1057": ("Process Discovery", "discovery"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1095": ("Non-Application Layer Protocol", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1112": ("Modify Registry", "defense-evasion"),
    "T1113": ("Screen Capture", "collection"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1497": ("Virtualization/Sandbox Evasion", "defense-evasion"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1622": ("Debugger Evasion", "defense-evasion"),
}


@dataclass
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    why: str
    evidence_ids: list[str]
    status: str = INFERRED  # observed | inferred | speculative
    prior: float = 0.0                       # Bayesian base rate the posterior updated from
    lane_posterior: dict[str, float] = field(default_factory=dict)  # static/dynamic/memory posteriors

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


def _lane_of(source: str) -> str:
    if source.startswith("dynamic."):
        return "dynamic"
    if source.startswith("memory."):
        return "memory"
    return "static"


def _obj_str(it: EvidenceItem) -> str:
    return " ".join(str(v) for v in {**it.object, **it.details}.values()).lower()


def _rules() -> list[_Rule]:
    def has_sink(*names: str) -> Callable[[EvidenceItem], bool]:
        wanted = {n.lower() for n in names}

        def f(it: EvidenceItem) -> bool:
            # Exact match on the explicit sink/api/function/import/command fields.
            fields = {
                str(it.object.get(k, "")).lower()
                for k in ("sink", "api", "function", "import", "symbol", "command")
            }
            if fields & wanted:
                return True
            # Code-preview scan: only match a sink as an actual CALL (`name(`) or a
            # path token (`/name`) inside decoded code — NOT as a bare substring,
            # which produced false positives like "system" in "system information".
            hay = (str(it.object.get("command", "")) + " " + str(it.details.get("decoded_preview", ""))).lower()
            return any(f"{n}(" in hay or f"/{n}" in hay for n in wanted)

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
            # Impact is inferred ONLY from the multi-category ransomware heuristic
            # (common.py), never from a lone encryption API — that misclassified
            # benign crypto-using backdoors.
            "T1486", "Data Encrypted for Impact", "impact", 0.7,
            lambda it: it.object.get("capability") == "ransomware",
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
    supports: dict[str, dict[str, list[float]]] = {}  # tid -> lane -> per-item supports

    def _support(tid: str, conf: float, it: EvidenceItem) -> None:
        lane = _lane_of(it.source)
        supports.setdefault(tid, {}).setdefault(lane, []).append(conf)

    def _emit(tid: str, name: str, tactic: str, conf: float, why: str, it: EvidenceItem) -> None:
        prov.setdefault(tid, []).append(provenance_of(it.source, it.confidence))
        _support(tid, conf, it)
        existing = agg.get(tid)
        if existing is None:
            agg[tid] = AttackMapping(tid, name, tactic, conf, why, [it.id])
        else:
            existing.evidence_ids.append(it.id)
            detail_key = why.split(":", 1)[-1].strip()
            if detail_key not in existing.why and existing.why.count("; ") < _WHY_MAX_CLAUSES:
                existing.why += f"; {why}"

    for it in store:
        item_prov = provenance_of(it.source, it.confidence)
        # Generic attack-hint path: any analyzer can attribute a technique by
        # setting details.attack_hint, without a bespoke rule here.
        hint = it.details.get("attack_hint")
        if isinstance(hint, str) and hint in TECHNIQUE_INFO:
            name, tactic = TECHNIQUE_INFO[hint]
            why = it.details.get("why") or _detail_for(it)
            conf = round(min(0.99, 0.7 * (0.5 + 0.5 * it.confidence)), 3)
            _emit(hint, name, tactic, conf, f"{name}: {why}", it)
        for rule in rules:
            # Avoid double-counting an item that already attributed this technique
            # via its explicit attack_hint.
            if it.details.get("attack_hint") == rule.technique_id:
                continue
            try:
                if not rule.match(it):
                    continue
            except Exception:
                continue
            detail = _detail_for(it)
            why = rule.why_tmpl.format(detail=detail)
            # Per-item support strength (rule base scaled by the item's confidence);
            # the technique's confidence is the Bayesian fusion of all such supports.
            conf = round(min(0.99, rule.base_conf * (0.5 + 0.5 * it.confidence) + 0.0), 3)
            prov.setdefault(rule.technique_id, []).append(item_prov)
            _support(rule.technique_id, conf, it)
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
                # Keep the explanation readable: list the first few distinct
                # observations, then summarize the rest rather than emitting a
                # wall of text. (evidence_ids still record every backing item.)
                if detail not in existing.why and existing.why.count("; ") < _WHY_MAX_CLAUSES:
                    existing.why += f"; {why}"
    # Bayesian posterior per technique: fuse the per-lane supports into one
    # auditable confidence + per-lane posteriors (prior is reported too).
    for tid, mapping in agg.items():
        mapping.status = strongest(prov.get(tid, []))
        posterior, lanes = fuse(supports.get(tid, {}))
        mapping.confidence = posterior
        mapping.lane_posterior = lanes
        mapping.prior = PRIOR
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
