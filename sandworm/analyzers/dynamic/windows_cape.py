"""Adapter to an existing Windows sandbox backend (CAPE / DRAKVUF).

SANDWORM does NOT build hypervisor instrumentation. This adapter submits the PE to
a CAPE/DRAKVUF instance (or ingests a pre-produced report) and normalizes its
process/file/registry/network/api output into EvidenceItems.

Live submission is implemented by ``sandworm.sandbox.CAPEBackend`` and never by
an analyzer running in the controller. Replay of a *recorded* CAPE report
(``normalize_cape_report``) is NOT
  detonation: it ingests evidence produced by a prior, properly-isolated run. It
executes nothing, so it is as safe as static analysis and may run offline.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ...core.evidence import EvidenceItem, EvidenceLocation
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

SOURCE = "dynamic.windows.cape"
_MAX_API_EVENTS = 50_000


def _integer(value: object) -> int | None:
    """Parse decimal/hex report values without guessing invalid addresses."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("`", "").replace(",", "")
    if not cleaned:
        return None
    try:
        return int(cleaned, 0)
    except ValueError:
        try:
            base = 16 if any(c in "abcdefABCDEF" for c in cleaned) else 10
            return int(cleaned, base)
        except ValueError:
            return None


def _address(value: object) -> int | None:
    parsed = _integer(value)
    return parsed if parsed is not None and parsed > 0 else None


def _basename(value: object) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _sha256(value: object) -> str | None:
    candidate = str(value or "").lower()
    return candidate if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate) else None


def _process_fields(proc: dict) -> tuple[int | None, int | None, str | None, str | None]:
    pid = _integer(proc.get("pid", proc.get("process_id")))
    ppid = _integer(proc.get("ppid", proc.get("parent_id")))
    name = proc.get("process_name") or proc.get("name")
    path = proc.get("module_path") or proc.get("process_path")
    return pid, ppid, str(name) if name else None, str(path) if path else None


def _module_base(proc: dict, call: dict | None = None) -> int | None:
    call = call or {}
    raw_environ = proc.get("environ")
    environ: dict = raw_environ if isinstance(raw_environ, dict) else {}
    for value in (
        call.get("module_base"),
        call.get("image_base"),
        proc.get("image_base"),
        proc.get("module_base"),
        environ.get("DllBase"),
        environ.get("ImageBase"),
    ):
        if (parsed := _address(value)) is not None:
            return parsed
    return None


def _target_metadata(report: dict) -> tuple[str | None, set[str]]:
    target_hash = _sha256(report.get("target_sha256"))
    raw_target = report.get("target")
    target: dict = raw_target if isinstance(raw_target, dict) else {}
    raw_file_meta = target.get("file")
    file_meta: dict = raw_file_meta if isinstance(raw_file_meta, dict) else {}
    if native_hash := _sha256(file_meta.get("sha256")):
        target_hash = native_hash
    names = {
        name
        for value in (file_meta.get("name"), file_meta.get("path"), report.get("target_name"))
        if (name := _basename(value))
    }
    return target_hash, names


def _call_location(
    call: dict,
    proc: dict,
    *,
    target_hash: str | None,
    target_names: set[str],
) -> EvidenceLocation | None:
    caller = _address(
        call.get("caller", call.get("caller_address", call.get("instruction_pointer")))
    )
    if caller is None:
        return None
    event_proc = {**call, **proc}
    pid, _, process_name, process_path = _process_fields(event_proc)
    module = (
        call.get("module")
        or call.get("module_name")
        or call.get("module_path")
        or process_path
        or process_name
    )
    base = _module_base(proc, call)
    module_hash = _sha256(call.get("module_sha256"))
    is_target = bool(call.get("is_target_module")) or _basename(module) in target_names
    if module_hash is None and is_target:
        module_hash = target_hash
    rva = caller - base if base is not None and caller >= base else None
    return EvidenceLocation(
        rva=rva,
        virtual_address=caller,
        instruction_address=caller,
        module=str(module) if module else None,
        module_base=base,
        pid=pid,
        thread_id=_integer(call.get("thread_id", call.get("tid"))),
        event_id=str(call["id"]) if call.get("id") is not None else None,
        artifact_sha256=module_hash,
    )


def _arguments(call: dict) -> list[dict]:
    """Keep useful call arguments while bounding report-controlled payloads."""
    out: list[dict] = []
    rows = call.get("arguments")
    if not isinstance(rows, list):
        return out
    for row in rows[:64]:
        if not isinstance(row, dict):
            continue
        clean: dict = {}
        for key in ("name", "value", "pretty_value"):
            value = row.get(key)
            if isinstance(value, (str, int, float, bool)):
                clean[key] = value[:2048] if isinstance(value, str) else value
        if clean:
            out.append(clean)
    return out


def normalize_cape_report(report: dict, ctx: Context, ref: str) -> Iterator[EvidenceItem]:
    """Normalize a CAPE/DRAKVUF JSON report into EvidenceItems.

    This is pure data transformation over an already-produced report and never
    executes the sample.
    """
    behavior = report.get("behavior", {})
    start = report.get("start_time")  # ISO; lets the timeline show absolute times too
    target_hash, target_names = _target_metadata(report)
    processes = [proc for proc in behavior.get("processes", []) if isinstance(proc, dict)]
    process_names = {
        pid: name
        for proc in processes
        for pid, _, name, _ in [_process_fields(proc)]
        if pid is not None and name
    }

    def _t(details: dict, t: object) -> dict:
        # A relative offset (seconds from process start) recorded by the sandbox
        # drives the temporal timeline. Stored in details so the causal timeline
        # (which sorts on EvidenceItem.ts) is unaffected.
        if isinstance(t, (int, float)):
            details = {**details, "t_offset": float(t), "t_label": f"T+{float(t):.3f}s"}
            if start:
                details["t_start"] = start
        return details

    # Process tree (parent → child), the substrate for the runtime process graph.
    for proc in processes:
        pid, ppid, name, module_path = _process_fields(proc)
        base = _module_base(proc)
        process_locations = (
            [
                EvidenceLocation(
                    virtual_address=base,
                    module=module_path or name,
                    module_base=base,
                    pid=pid,
                    artifact_sha256=(
                        target_hash
                        if _basename(module_path or name) in target_names
                        else None
                    ),
                )
            ]
            if base is not None
            else []
        )
        yield ctx.ev(
            source=SOURCE,
            artifact="process",
            operation="spawn",
            subject={
                "pid": ppid,
                "name": proc.get("parent_name") or (
                    process_names.get(ppid) if ppid is not None else None
                ),
            },
            object={"pid": pid, "name": name},
            details=_t(
                {
                    "command_line": proc.get("command_line"),
                    "first_seen": proc.get("first_seen"),
                    "module_path": module_path,
                },
                proc.get("t"),
            ),
            confidence=0.9,
            evidence_refs=[ref],
            locations=process_locations,
        )
    # API calls of interest (injection etc.). Mapped to ATT&CK via has_sink. A
    # structured ``api_calls: [{api, t}]`` carries per-call timing; ``apistats_flat``
    # (a bare list) stays supported for reports without timestamps.
    api_events: list[tuple[dict, dict]] = []
    flat_events = behavior.get("api_calls")
    if isinstance(flat_events, list) and flat_events:
        api_events = [
            (call if isinstance(call, dict) else {"api": call}, {})
            for call in flat_events
            if isinstance(call, (dict, str))
        ]
    else:
        for proc in processes:
            calls = proc.get("calls")
            if isinstance(calls, list):
                api_events.extend((call, proc) for call in calls if isinstance(call, dict))
        if not api_events:
            api_events = [({"api": api}, {}) for api in behavior.get("apistats_flat", [])]
    for call, proc in api_events[:_MAX_API_EVENTS]:
        api = call.get("api")
        if not api:
            continue
        event_proc = {**call, **proc}
        pid, _, process_name, process_path = _process_fields(event_proc)
        location = _call_location(
            call,
            proc,
            target_hash=target_hash,
            target_names=target_names,
        )
        details = {
            key: call[key]
            for key in ("category", "status", "return", "repeated", "timestamp")
            if key in call
        }
        if process_path:
            details["module_path"] = process_path
        if arguments := _arguments(call):
            details["arguments"] = arguments
        yield ctx.ev(
            source=SOURCE,
            artifact="api_call",
            operation="exec",
            subject={"pid": pid, "name": process_name, "analyzer": SOURCE},
            object={"api": api},
            details=_t(details, call.get("t")),
            confidence=0.7,
            evidence_refs=[ref],
            locations=[location] if location is not None else [],
        )
    # Network egress, routed to the simulated responder during detonation. Hosts
    # may be a bare string or ``{host, t}``.
    for host in report.get("network", {}).get("hosts", []):
        hv = host.get("host") if isinstance(host, dict) else host
        yield ctx.ev(
            source=SOURCE,
            artifact="network",
            operation="connect",
            subject={"analyzer": SOURCE},
            object={"kind": "ipv4" if _looks_ipv4(str(hv)) else "domain", "value": hv, "host": hv},
            details=_t({"ioc": True, "false_positive_risk": "low", "note": "egress observed (routed to simulated network)"},
                       host.get("t") if isinstance(host, dict) else None),
            confidence=0.85,
            evidence_refs=[ref],
        )
    # Dropped files.
    for f in report.get("dropped", []):
        yield ctx.ev(
            source=SOURCE,
            artifact="file",
            operation="create",
            subject={"analyzer": SOURCE},
            object={"path": f.get("name"), "sha256": f.get("sha256")},
            details=_t({}, f.get("t")),
            confidence=0.8,
            evidence_refs=[ref],
        )
    # Registry persistence writes. Entries may be a bare string or ``{key, t}``.
    for key in behavior.get("regkey_written", []):
        kv = key.get("key") if isinstance(key, dict) else key
        yield ctx.ev(
            source=SOURCE,
            artifact="registry",
            operation="write",
            subject={"analyzer": SOURCE},
            object={"key": kv},
            details=_t({}, key.get("t") if isinstance(key, dict) else None),
            confidence=0.75,
            evidence_refs=[ref],
        )


def _looks_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


class WindowsCapeAnalyzer(BaseAnalyzer):
    name = SOURCE
    handles = {"pe"}
    requires_isolation = True

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sample.sha256}"
        report_path = ctx.extra.get("cape_report")
        if not report_path or not Path(report_path).exists():
            return [
                ctx.ev(
                    source=SOURCE,
                    artifact="process",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"status": "skipped"},
                    details={"reason": "no CAPE/DRAKVUF backend report available; submit job or pass cape_report"},
                    confidence=0.2,
                    evidence_refs=[ref],
                )
            ]
        report = json.loads(Path(report_path).read_text())
        return list(normalize_cape_report(report, ctx, ref))


def register(registry) -> None:
    registry.register(WindowsCapeAnalyzer())
