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
    """
    import json

    ran: list[str] = []
    ref = f"sample:{sample.sha256}"
    # The bundled CAPE/vol3 adapters normalize a *Windows/PE* sandbox run. Folding
    # such a report into a non-PE sample (a PHP shell, an ELF, a script) would
    # attribute another binary's behaviour to this file — inflating the verdict
    # with injection/persistence/C2 that never happened here. So we REFUSE the
    # mismatch rather than ingest-and-warn: a report about a different platform is
    # not evidence about this sample.
    win_report_ok = sample.format_hint in {"pe", "dll", "generic", "unknown", ""}

    if cape_report and Path(cape_report).exists():
        if not win_report_ok:
            notes.append(
                f"⚠ refused the recorded dynamic report: it is a Windows/PE sandbox run but this sample is "
                f"'{sample.format_hint}'. It describes a different binary, so it is NOT folded into the verdict "
                "(analysed static-only). Provide a report produced from THIS sample, or run static-only."
            )
        else:
            from ..analyzers.dynamic.windows_cape import normalize_cape_report

            report = json.loads(Path(cape_report).read_text())
            items = list(normalize_cape_report(report, ctx, ref))
            store.extend(items)
            ran.append("dynamic.windows.cape(replay)")
            notes.append(f"ingested recorded dynamic report ({len(items)} events; replay — no live detonation)")
            audit.log(run_id=run_id, action="ingest_dynamic_report", source="dynamic.windows.cape",
                      sample_hash=sample.sha256, events=len(items), path=str(cape_report))

    if memory_report and Path(memory_report).exists():
        if not win_report_ok:
            notes.append(
                f"⚠ refused the recorded memory report: it is Windows-oriented but this sample is "
                f"'{sample.format_hint}' — it does not describe this file (analysed static-only)."
            )
        else:
            from ..analyzers.memory.vol3 import normalize_memory_report

            report = json.loads(Path(memory_report).read_text())
            items = list(normalize_memory_report(report, ctx, ref))
            store.extend(items)
            ran.append("memory.vol3(replay)")
            notes.append(f"ingested recorded memory report ({len(items)} artifacts; replay — no live detonation)")
            audit.log(run_id=run_id, action="ingest_memory_report", source="memory.vol3",
                      sample_hash=sample.sha256, artifacts=len(items), path=str(memory_report))
    return ran


def analyze_sample(
    sample: Sample,
    *,
    config: Config | None = None,
    run_id: str | None = None,
    enable_dynamic: bool = True,
    cape_report: str | None = None,
    memory_report: str | None = None,
) -> RunResult:
    config = config or get_config()
    run_id = run_id or uuid.uuid4().hex[:12]
    audit = AuditLogger(config)
    audit.log(run_id=run_id, action="run_start", sample_hash=sample.sha256, name=sample.name, size=sample.size)

    register_builtins()
    store = EvidenceStore()
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
