"""End-to-end orchestration.

Routes a sample through triage -> static analyzers (always) -> dynamic analyzers
(only behind the verified isolation gate) -> reconstruction (graph, timeline,
narrative, ATT&CK) -> detection generation -> coverage. Everything flows through
the EvidenceStore; consumers never touch analyzers directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..analyzers.base import Context
from ..analyzers.registry import REGISTRY, register_builtins
from ..detect.sigma_gen import SigmaRule, generate_sigma
from ..detect.yara_gen import YaraRule, generate_yara
from ..reconstruct.attack_map import AttackMapping, map_evidence
from ..reconstruct.graph import add_detections_to_graph, build_graph, graph_summary
from ..reconstruct.narrative import Phase, build_narrative
from ..reconstruct.timeline import TimelineEntry, build_timeline
from ..reporting.coverage import CoverageReport, compute_coverage
from .audit import AuditLogger
from .config import Config, get_config
from .evidence import EvidenceStore
from .isolation import IsolationError, guard_detonation
from .sample import Sample
from .triage import TriageResult, analyzer_tags_for, identify


@dataclass
class RunResult:
    run_id: str
    sample: Sample
    triage: TriageResult
    isolated: bool
    store: EvidenceStore
    mappings: list[AttackMapping]
    phases: list[Phase]
    timeline: list[TimelineEntry]
    yara: list[YaraRule]
    sigma: list[SigmaRule]
    coverage: CoverageReport
    graph: object = None
    analyzers_run: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _report_target_hash(report: object) -> str | None:
    """The sha256 of the sample a recorded report was captured from, if declared.

    A recorded report describes ONE specific run of ONE specific binary. We carry
    that provenance as ``target_sha256`` so the report can only be attributed back
    to the sample it actually came from. CAPE reports are a dict (top-level key);
    vol3 reports are a list of plugin sections (we scan for a leading meta element
    carrying the key). Returns ``None`` when the report declares no provenance.
    """
    if isinstance(report, dict):
        h = report.get("target_sha256")
        return str(h).lower() if h else None
    if isinstance(report, list):
        for section in report:
            if isinstance(section, dict) and section.get("target_sha256"):
                return str(section["target_sha256"]).lower()
    return None


def _ingest_recorded_reports(
    *, cape_report: str | None, memory_report: str | None, ctx: Context, sample: Sample,
    store: EvidenceStore, notes: list[str], audit: AuditLogger, run_id: str,
) -> list[str]:
    """Ingest recorded dynamic/memory reports into the evidence store.

    Replaying a *recorded* report is NOT detonation — it transforms evidence a
    prior, properly-isolated run already produced and executes nothing. So this
    path deliberately does not pass through the isolation gate; it is as safe as
    static analysis and runs offline. (Live detonation stays gated in the
    registry.) The resulting ``dynamic.*``/``memory.*`` evidence automatically
    upgrades technique standing inferred → observed downstream.

    Two provenance gates protect accuracy — a recorded run is only this sample's
    behaviour if it was *captured from this sample*:

    1. **Format** — the bundled CAPE/vol3 adapters normalize a Windows/PE sandbox
       run, so the report only belongs to a pe/dll sample. (A real PE always
       triages 'pe' via the MZ magic, so 'generic'/'unknown' are not PE.)
    2. **Identity** — the report must declare ``target_sha256`` and it must equal
       this sample's hash. This is the gate that stops a recorded loader run from
       being folded into an unrelated PE (e.g. WannaCry) and reported as that
       file's confirmed loader.exe→notepad injection / C2 that never happened.

    On any mismatch we refuse and fall back to static-only rather than
    ingest-and-warn, so the verdict is never inflated by another binary's run.
    """
    import json

    ran: list[str] = []
    ref = f"sample:{sample.sha256}"
    win_report_ok = sample.format_hint in {"pe", "dll"}

    def _ingest(path: str, kind: str, normalize, source: str, unit: str) -> None:
        report = json.loads(Path(path).read_text())
        if not win_report_ok:
            notes.append(
                f"⚠ refused the recorded {kind} report: it is a Windows/PE run but this sample is "
                f"'{sample.format_hint}'. It describes a different binary, so it is NOT folded into the "
                "verdict (analysed static-only). Provide a report captured from THIS sample, or run static-only."
            )
            return
        declared = _report_target_hash(report)
        if declared is None:
            notes.append(
                f"⚠ refused the recorded {kind} report: it does not declare which sample it was captured from "
                "(no target_sha256), so its runtime events cannot be attributed to this file (analysed "
                "static-only). Bind the report to its source sample to ingest it."
            )
            return
        if declared != sample.sha256.lower():
            notes.append(
                f"⚠ refused the recorded {kind} report: it was captured from a different sample "
                f"(sha256 {declared[:12]}…), not this one ({sample.sha256[:12]}…). Its process tree / "
                "injection / C2 are that binary's behaviour, not this file's — analysed static-only."
            )
            return
        items = list(normalize(report, ctx, ref))
        store.extend(items)
        ran.append(f"{source}(replay)")
        notes.append(f"ingested recorded {kind} report ({len(items)} {unit}; replay — no live detonation)")
        audit.log(run_id=run_id, action=f"ingest_{kind}_report", source=source,
                  sample_hash=sample.sha256, events=len(items), path=str(path))

    if cape_report and Path(cape_report).exists():
        from ..analyzers.dynamic.windows_cape import normalize_cape_report
        _ingest(cape_report, "dynamic", normalize_cape_report, "dynamic.windows.cape", "events")

    if memory_report and Path(memory_report).exists():
        from ..analyzers.memory.vol3 import normalize_memory_report
        _ingest(memory_report, "memory", normalize_memory_report, "memory.vol3", "artifacts")

    return ran


def analyze_sample(
    sample: Sample,
    *,
    config: Config | None = None,
    run_id: str | None = None,
    enable_dynamic: bool = True,
    cape_report: str | None = None,
    memory_report: str | None = None,
    on_evidence=None,
) -> RunResult:
    config = config or get_config()
    run_id = run_id or uuid.uuid4().hex[:12]
    audit = AuditLogger(config)
    audit.log(run_id=run_id, action="run_start", sample_hash=sample.sha256, name=sample.name, size=sample.size)

    register_builtins()
    store = EvidenceStore()
    # Real-time streaming: subscribe before any analyzer runs so findings are
    # emitted as they are discovered, not after the batch completes.
    if on_evidence is not None:
        store.subscribe(on_evidence)
    notes: list[str] = []

    # --- Triage / format routing ---
    triage = identify(sample.data, sample.name)
    sample.format_hint = triage.fmt
    audit.log(run_id=run_id, action="triage", sample_hash=sample.sha256, fmt=triage.fmt, supported=triage.supported, reasons=triage.reasons)
    if not triage.supported:
        notes.append(f"format '{triage.fmt}' is recognized but not yet supported for deep analysis; running common analyzer only")

    # --- Isolation gate (decides whether the dynamic lane runs at all) ---
    isolated = False
    if enable_dynamic:
        try:
            isolated = guard_detonation(run_id, config=config, audit=audit)
        except IsolationError:
            isolated = False
    if not isolated:
        notes.append("isolation NOT verified — dynamic detonation refused; static-only analysis")

    ctx = Context(run_id=run_id, config=config, audit=audit, isolated=isolated)

    # --- Dispatch analyzers ---
    tags = analyzer_tags_for(triage.fmt) | {"*"}
    selected: list = []
    seen = set()
    for tag in tags:
        for a in REGISTRY.for_format(tag, include_dynamic=enable_dynamic, isolated=isolated):
            if a.name not in seen:
                seen.add(a.name)
                selected.append(a)

    analyzers_run: list[str] = []
    for analyzer in selected:
        items = analyzer.analyze(sample, ctx)
        store.extend(items)
        analyzers_run.append(analyzer.name)

    # --- Recorded dynamic/memory replay (offline-safe; not a live detonation) ---
    analyzers_run.extend(
        _ingest_recorded_reports(
            cape_report=cape_report, memory_report=memory_report, ctx=ctx, sample=sample,
            store=store, notes=notes, audit=audit, run_id=run_id,
        )
    )

    # --- Reconstruction ---
    mappings = map_evidence(store)
    phases = build_narrative(mappings)
    timeline = build_timeline(store)
    graph = build_graph(store, mappings, sample_name=sample.name)

    # --- Detections ---
    yara = generate_yara(store, sample)
    sigma = generate_sigma(store, mappings)
    coverage = compute_coverage(mappings, sigma, yara)

    # Complete the reasoning graph: Technique -> Detection.
    add_detections_to_graph(graph, mappings, yara=yara, sigma=sigma)

    audit.log(
        run_id=run_id,
        action="run_done",
        sample_hash=sample.sha256,
        evidence=len(store),
        techniques=len(mappings),
        analyzers=analyzers_run,
        graph=graph_summary(graph),
    )

    return RunResult(
        run_id=run_id,
        sample=sample,
        triage=triage,
        isolated=isolated,
        store=store,
        mappings=mappings,
        phases=phases,
        timeline=timeline,
        yara=yara,
        sigma=sigma,
        coverage=coverage,
        graph=graph,
        analyzers_run=analyzers_run,
        notes=notes,
    )


def persist_run(result: RunResult, config: Config | None = None) -> Path:
    """Dump the evidence store to the run dir for `replay`/`ask`."""
    config = config or get_config()
    run_dir = config.run_dir(result.run_id)
    result.store.dump(str(run_dir / "evidence.jsonl"))
    (run_dir / "meta.txt").write_text(
        f"sample={result.sample.name}\nsha256={result.sample.sha256}\nformat={result.triage.fmt}\nisolated={result.isolated}\n"
    )
    return run_dir


def build_report_inputs(result: RunResult):
    from ..reporting.report import ReportInputs

    return ReportInputs(
        run_id=result.run_id,
        sample_name=result.sample.name,
        sha256=result.sample.sha256,
        fmt=result.triage.fmt,
        isolation="verified" if result.isolated else "not verified (static-only)",
        store=result.store,
        mappings=result.mappings,
        phases=result.phases,
        timeline=result.timeline,
        yara=result.yara,
        sigma=result.sigma,
        coverage=result.coverage,
        graph=result.graph,
    )
