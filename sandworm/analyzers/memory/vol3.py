"""Volatility3 orchestration.

Runs a curated set of vol3 plugins (pslist/psscan/malfind/netscan/cmdline) over a
memory image via subprocess and normalizes the JSON renderer output into
EvidenceItems. This is opt-in: it needs a memory image path passed via
``ctx.extra['memory_image']`` and volatility3 installed. Absent either, it emits a
single 'skipped' note so the pipeline never hard-fails.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

SOURCE = "memory.vol3"

_PLUGINS = {
    "windows.pslist.PsList": ("process", "spawn"),
    "windows.malfind.Malfind": ("process", "inject"),
    "windows.netscan.NetScan": ("network", "connect"),
    "windows.cmdline.CmdLine": ("process", "exec"),
}

# Which vol3 plugin a recorded-report section came from → (artifact, operation,
# optional attack_hint). Lets a recorded memory report drive ATT&CK directly:
# malfind => injected memory (T1055), so memory evidence upgrades the standing of
# an injection technique from inferred → observed.
_PLUGIN_MAP = {
    "windows.pslist.PsList": ("process", "spawn", None),
    "windows.psscan.PsScan": ("process", "spawn", None),
    "windows.malfind.Malfind": ("process", "inject", "T1055"),
    "windows.netscan.NetScan": ("network", "connect", None),
    "windows.cmdline.CmdLine": ("process", "exec", None),
}

# Credential/authentication APIs whose in-memory hooking is Credential API Hooking
# (T1056.004); any other inline hook in a foreign module corroborates injection
# (T1055). Matched case-insensitively as a substring of the hooked function.
_CRED_HOOK_APIS = (
    "lsaaplogonuser", "msvppasswordvalidate", "credread", "credenumerate",
    "cryptdecrypt", "pwdvalidate", "samiconnect", "lsalogonuser",
)


def _section_rows(section: dict) -> list[dict]:
    return [r for r in section.get("rows", [])[:500] if isinstance(r, dict)]


def _pid_of(row: dict) -> str | None:
    pid = row.get("PID", row.get("pid"))
    return str(pid) if pid not in (None, "") else None


def _hidden_processes(sections: list[dict], ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Cross-plugin: a PID visible to the pool scanner (psscan) but absent from the
    linked process list (pslist) is an unlinked EPROCESS — a hidden process, the
    classic DKOM rootkit tell. We emit it as observed T1014 with the corroborating
    plugins named, so the verdict reflects evidence neither plugin shows alone."""
    listed: set[str] = set()
    scanned: dict[str, dict] = {}
    for section in sections:
        plugin = section.get("plugin", "")
        if plugin.endswith("PsList"):
            listed |= {p for r in _section_rows(section) if (p := _pid_of(r))}
        elif plugin.endswith("PsScan"):
            for r in _section_rows(section):
                if (p := _pid_of(r)):
                    scanned[p] = r
    for pid in sorted(scanned.keys() - listed, key=lambda p: int(p) if p.isdigit() else 0):
        row = scanned[pid]
        name = str(row.get("ImageFileName") or row.get("Process") or "?")
        yield ctx.ev(
            source=SOURCE, artifact="process", operation="spawn",
            subject={"analyzer": "psscan vs pslist", "pid": row.get("PPID")},
            object={"pid": pid, "name": name, "hidden": True},
            details={"plugin": "windows.psscan.PsScan", "hidden": True, "attack_hint": "T1014",
                     "why": f"PID {pid} ({name}) is visible to pool-tag scanning but unlinked from the "
                            "active process list — a hidden process (DKOM rootkit indicator)"},
            confidence=0.85, evidence_refs=[ref],
        )


def _api_hooks(section: dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """IAT/EAT/inline hooks recovered from memory. A hook on a credential API is
    Credential API Hooking (T1056.004); any other inline hook patched into a
    foreign module corroborates injection/tampering (T1055)."""
    for row in _section_rows(section):
        fn = str(row.get("HookFunction") or row.get("Function") or row.get("Symbol") or "")
        proc = str(row.get("Process") or row.get("ImageFileName") or "?")
        cred = any(api in fn.lower() for api in _CRED_HOOK_APIS)
        hint = "T1056.004" if cred else "T1055"
        why = (f"in-memory hook on credential API {fn} in {proc} (Credential API Hooking)" if cred
               else f"in-memory {row.get('HookType','inline')} hook on {fn} in {proc} (code patched into a foreign module)")
        yield ctx.ev(
            source=SOURCE, artifact="api_call", operation="inject",
            subject={"analyzer": "windows.apihooks", "process": proc},
            object={"hooked": fn, "process": proc, "hook_type": row.get("HookType", "inline")},
            details={"plugin": "windows.apihooks.ApiHooks", "attack_hint": hint, "why": why, "hook": True},
            confidence=0.82, evidence_refs=[ref],
        )


def _extracted_config(section: dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Config carved from process memory — the payoff of the memory lane: static
    says a binary *can* encrypt/beacon; the heap shows it *did*. C2 atoms become
    memory-confirmed network IOCs; a recovered key is a high-value artifact; an
    encrypted-file tally turns the ransomware capability into an observed event."""
    for row in _section_rows(section):
        kind = str(row.get("kind") or row.get("type") or "").lower()
        val = row.get("value")
        if kind in ("c2", "url", "domain", "ipv4", "host") and val:
            yield ctx.ev(
                source=SOURCE, artifact="network", operation="connect",
                subject={"analyzer": "memory.config", "pid": row.get("PID")},
                object={"kind": "url" if kind in ("c2", "url") else kind, "value": str(val), "host": str(val)},
                details={"plugin": "config_extract", "ioc": True, "memory_extracted": True,
                         "why": f"C2 endpoint recovered from process memory: {val}"},
                confidence=0.86, evidence_refs=[ref],
            )
        elif kind in ("rsa_key", "aes_key", "key") and val:
            yield ctx.ev(
                source=SOURCE, artifact="string", operation="decode",
                subject={"analyzer": "memory.config", "pid": row.get("PID")},
                object={"layer": "memory", "key_material": str(val)[:48]},
                details={"plugin": "config_extract", "memory_extracted": True,
                         "why": f"encryption key material recovered from heap ({kind})"},
                confidence=0.8, evidence_refs=[ref],
            )
        elif kind in ("encrypted_files", "ransom") and (cnt := row.get("count")):
            ext = row.get("extension", "")
            yield ctx.ev(
                source=SOURCE, artifact="file", operation="write",
                subject={"analyzer": "memory.config", "pid": row.get("PID")},
                object={"capability": "ransomware", "encrypted_count": cnt, "extension": ext},
                details={"plugin": "config_extract", "memory_extracted": True,
                         "why": f"{cnt} files were encrypted to '{ext}' (observed in memory) — capability confirmed as an event"},
                confidence=0.9, evidence_refs=[ref],
            )


def normalize_memory_report(report: list | dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Normalize a *recorded* vol3 report into EvidenceItems (offline replay).

    Reads a JSON file shaped as ``[{"plugin": "...", "rows": [...]}, ...]`` (the
    output an operator captures from a prior memory-forensics run). Like the CAPE
    replay path, this executes nothing — it ingests prior evidence, so it is safe
    to run without the isolation gate.

    Beyond per-row mapping it runs deeper memory forensics: hidden-process
    detection (psscan∖pslist → T1014), API-hook recovery (T1056.004 / T1055), and
    config carved from the heap (memory-confirmed C2 / keys / encrypted-file
    tally), so the memory lane confirms *events*, not just capability.
    """
    sections = [s for s in (report if isinstance(report, list) else report.get("sections", [])) if isinstance(s, dict)]
    for section in sections:
        plugin = section.get("plugin", "")
        if plugin.endswith("ApiHooks"):
            yield from _api_hooks(section, ctx, ref)
            continue
        if plugin in ("config_extract", "sandworm.config_extract"):
            yield from _extracted_config(section, ctx, ref)
            continue
        art, op, hint = _PLUGIN_MAP.get(plugin, ("process", "read", None))
        for row in _section_rows(section):
            details: dict = {"plugin": plugin}
            if hint:
                details["attack_hint"] = hint
                details["why"] = f"{plugin} found a memory region consistent with code injection"
            yield ctx.ev(
                source=SOURCE,
                artifact=art,
                operation=op,
                subject={"analyzer": plugin, "pid": row.get("PID") or row.get("pid")},
                object={k: v for k, v in row.items() if isinstance(v, (str, int, float, bool))},
                details=details,
                confidence=0.8,
                evidence_refs=[ref],
            )
    yield from _hidden_processes(sections, ctx, ref)


class Vol3Analyzer(BaseAnalyzer):
    name = "memory.vol3"
    handles = {"*"}
    requires_isolation = False  # reads a static image; no detonation

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        image = ctx.extra.get("memory_image")
        vol = shutil.which("vol") or shutil.which("volatility3")
        if not image or not Path(image).exists() or not vol:
            return [
                ctx.ev(
                    source="memory.vol3",
                    artifact="process",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "no memory image or volatility3 not installed"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]
        items: list[EvidenceItem] = []
        for plugin, (art, op) in _PLUGINS.items():  # pragma: no cover - needs vol3 + image
            try:
                proc = subprocess.run(
                    [vol, "-r", "json", "-f", str(image), plugin],
                    capture_output=True,
                    timeout=300,
                    check=False,
                )
                rows = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
            except Exception:
                continue
            for row in rows[:500]:
                items.append(
                    ctx.ev(
                        source="memory.vol3",
                        artifact=art,
                        operation=op,
                        subject={"analyzer": plugin},
                        object=row,
                        details={"plugin": plugin},
                        confidence=0.75,
                        evidence_refs=[ref],
                    )
                )
        return items


def register(registry) -> None:
    registry.register(Vol3Analyzer())
