"""End-to-end orchestration.

Routes a sample through triage -> static analyzers (always) -> a configured
sandbox backend (optional) -> artifact normalization -> reconstruction (graph,
timeline, narrative, ATT&CK) -> detection generation -> coverage. Everything
flows through the EvidenceStore; the controller never executes sample bytes.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..analyzers.base import Context
from ..analyzers.registry import REGISTRY, register_builtins
from ..detect.sigma_gen import SigmaRule, generate_sigma
from ..detect.yara_gen import YaraRule, generate_yara, load_clean_corpus
from ..reconstruct.attack_map import AttackMapping, map_evidence
from ..reconstruct.correlation import annotate_runtime_addresses
from ..reconstruct.graph import add_detections_to_graph, build_graph, graph_summary
from ..reconstruct.narrative import Phase, build_narrative
from ..reconstruct.timeline import TimelineEntry, build_timeline
from ..reporting.coverage import CoverageReport, compute_coverage
from ..sandbox.base import AnalysisPolicy, Artifact, ArtifactBundle, SandboxBackend
from ..sandbox.replay import ReplayBackend
from .audit import AuditLogger
from .config import Config, get_config
from .evidence import EvidenceStore
from .sample import Sample
from .triage import TriageResult, analyzer_tags_for, identify

_STATIC_CACHE_VERSION = 4


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
    execution_mode: str = "static"
    sandbox_backend: str | None = None
    artifact_bundle: ArtifactBundle | None = None


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
        if h:
            return str(h).lower()
        target = report.get("target")
        if isinstance(target, dict):
            file_meta = target.get("file")
            if isinstance(file_meta, dict) and file_meta.get("sha256"):
                return str(file_meta["sha256"]).lower()
        return None
    if isinstance(report, list):
        for section in report:
            if isinstance(section, dict) and section.get("target_sha256"):
                return str(section["target_sha256"]).lower()
    return None


def _ingest_recorded_reports(
    *, cape_report: str | None, memory_report: str | None, ctx: Context, sample: Sample,
    store: EvidenceStore, static_store: EvidenceStore, notes: list[str],
    audit: AuditLogger, run_id: str,
) -> list[str]:
    """Ingest recorded dynamic/memory reports into the evidence store.

    Replaying a *recorded* report is NOT detonation — it transforms evidence a
    prior, properly-isolated run already produced and executes nothing. Live
    execution is owned by a SandboxBackend, never by this normalizer. The
    resulting ``dynamic.*``/``memory.*`` evidence automatically upgrades
    technique standing inferred → observed downstream.

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
        report_path = Path(path)
        if ctx.config.max_report_bytes and report_path.stat().st_size > ctx.config.max_report_bytes:
            raise ValueError(
                f"{kind} report exceeds the {ctx.config.max_report_bytes:,}-byte limit"
            )
        report = json.loads(report_path.read_text())
        linux_memory = kind == "memory" and isinstance(report, dict) and report.get("platform") == "linux" and sample.format_hint in {"elf", "shell", "php", "javascript", "generic"}
        if not win_report_ok and not linux_memory:
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
        items, correlation_count = annotate_runtime_addresses(static_store, items, sample)
        store.extend(items)
        ran.append(f"{source}(replay)")
        notes.append(f"ingested recorded {kind} report ({len(items)} {unit}; replay — no live detonation)")
        if correlation_count:
            notes.append(
                f"correlated {correlation_count} {kind} instruction address(es) "
                "to decoded static functions"
            )
        audit.log(run_id=run_id, action=f"ingest_{kind}_report", source=source,
                  sample_hash=sample.sha256, events=len(items), path=str(path))

    if cape_report and Path(cape_report).exists():
        from ..analyzers.dynamic.windows_cape import normalize_cape_report
        _ingest(cape_report, "dynamic", normalize_cape_report, "dynamic.windows.cape", "events")

    if memory_report and Path(memory_report).exists():
        from ..analyzers.memory.vol3 import normalize_memory_report
        _ingest(memory_report, "memory", normalize_memory_report, "memory.vol3", "artifacts")

    return ran


def _cache_path(config: Config, sample: Sample) -> Path:
    """Versioned, content-addressed cache for deterministic static evidence."""
    return config.cache_dir / f"{sample.sha256}.v{_STATIC_CACHE_VERSION}.jsonl"


def _run_backend(
    *,
    backend: SandboxBackend,
    policy: AnalysisPolicy,
    sample: Sample,
    ctx: Context,
    store: EvidenceStore,
    notes: list[str],
    audit: AuditLogger,
    run_id: str,
) -> tuple[list[str], ArtifactBundle | None]:
    """Submit, collect, normalize, and always release a backend job."""
    job = None
    bundle = None
    ran: list[str] = []
    try:
        audit.log(
            run_id=run_id,
            action="sandbox_submit",
            backend=backend.name,
            sample_hash=sample.sha256,
            policy={
                "timeout_seconds": policy.timeout_seconds,
                "network": policy.network,
                "capture_memory": policy.capture_memory,
                "platform": policy.platform,
            },
        )
        job = backend.submit(sample, policy)
        status = backend.status(job)
        if status.state.value in {"failed", "destroyed"}:
            raise RuntimeError(f"sandbox job {job.id} is {status.state.value}: {status.message}")
        bundle = backend.collect(job)
        if bundle.target_sha256.lower() != sample.sha256.lower():
            raise RuntimeError("sandbox returned artifacts for a different sample")
        # Re-hash immediately before parsing so a mutable path cannot silently
        # diverge from the backend's manifest between collection and ingestion.
        for artifact in bundle.artifacts:
            current = Artifact.from_path(
                artifact.kind, artifact.path, media_type=artifact.media_type
            )
            if current.sha256 != artifact.sha256 or current.size != artifact.size:
                raise RuntimeError(f"sandbox artifact changed after collection: {artifact.path}")

        cape = bundle.by_kind("cape_report")
        memory = bundle.by_kind("memory_report")
        if len(cape) > 1 or len(memory) > 1:
            raise RuntimeError("sandbox returned multiple primary reports of the same kind")
        staged_store = EvidenceStore()
        staged_notes: list[str] = []
        ran.extend(
            _ingest_recorded_reports(
                cape_report=str(cape[0].path) if cape else None,
                memory_report=str(memory[0].path) if memory else None,
                ctx=ctx,
                sample=sample,
                store=staged_store,
                static_store=store,
                notes=staged_notes,
                audit=audit,
                run_id=run_id,
            )
        )
        from ..sandbox.runtime import normalize_runtime
        for artifact in bundle.by_kind("trace"):
            if artifact.size > (ctx.config.max_report_bytes or 128 * 1024**2):
                raise ValueError("runtime report exceeds size limit")
            document = json.loads(artifact.path.read_text())
            if document.get("target_sha256") != sample.sha256:
                raise ValueError("runtime report belongs to a different sample")
            items = normalize_runtime(document, ctx)
            items, count = annotate_runtime_addresses(store, items, sample)
            staged_store.extend(items)
            ran.append("dynamic.runtime")
            staged_notes.append(f"ingested {len(items)} runtime events; {count} address correlations")
        if bundle.by_kind("memory_dump") and policy.options.get("memory_platform"):
            from ..analyzers.memory.collect import collect_memory
            from ..analyzers.memory.vol3 import normalize_memory_report
            for dump in bundle.by_kind("memory_dump"):
                try:
                    symbols = policy.options.get("symbols")
                    report = collect_memory(sample, dump.path, platform=policy.options["memory_platform"], symbols=Path(symbols) if symbols else None)
                    staged_store.extend(normalize_memory_report(report, ctx, "artifact:" + dump.sha256))
                    ran.append("memory.vol3(image)")
                    staged_notes.append(f"memory-image processing: {len(report['sections'])} plugins completed, {len(report['errors'])} failed")
                except (RuntimeError, ValueError) as exc:
                    staged_notes.append(f"memory-image processing unavailable: {exc}")
        store.extend(staged_store)
        notes.extend(staged_notes)
        notes.append(
            f"collected {len(bundle.artifacts)} artifact(s) from {backend.name} "
            f"({bundle.execution_mode}; manifest verified)"
        )
        audit.log(
            run_id=run_id,
            action="sandbox_collect",
            backend=backend.name,
            job_id=job.id,
            execution_mode=bundle.execution_mode,
            isolation_verified=bundle.isolation_verified,
            image_id=bundle.image_id,
            artifacts=[
                {"kind": artifact.kind, "sha256": artifact.sha256, "size": artifact.size}
                for artifact in bundle.artifacts
            ],
        )
    except Exception as exc:
        notes.append(f"sandbox backend '{backend.name}' failed safely: {exc}")
        audit.log(
            run_id=run_id,
            action="sandbox_error",
            backend=backend.name,
            sample_hash=sample.sha256,
            error=repr(exc),
        )
        bundle = None
        ran = []
    finally:
        if job is not None:
            try:
                backend.destroy(job)
                audit.log(
                    run_id=run_id,
                    action="sandbox_destroy",
                    backend=backend.name,
                    job_id=job.id,
                )
            except Exception as exc:
                notes.append(f"sandbox cleanup warning for '{backend.name}': {exc}")
                audit.log(
                    run_id=run_id,
                    action="sandbox_destroy_error",
                    backend=backend.name,
                    job_id=job.id,
                    error=repr(exc),
                )
    return ran, bundle


def analyze_sample(
    sample: Sample,
    *,
    config: Config | None = None,
    run_id: str | None = None,
    enable_dynamic: bool = True,
    cape_report: str | None = None,
    memory_report: str | None = None,
    runtime_report: str | None = None,
    intelligence_snapshot: str | None = None,
    decompiler_report: str | None = None,
    sandbox_backend: SandboxBackend | None = None,
    sandbox_policy: AnalysisPolicy | None = None,
    on_evidence=None,
    use_cache: bool = True,
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

    # Recorded reports use the same artifact-bundle path as live sandboxes but
    # never execute bytes. A live backend is only invoked when explicitly passed
    # by the caller and dynamic analysis is enabled.
    if sandbox_backend is not None and (cape_report or memory_report or runtime_report):
        raise ValueError("pass either sandbox_backend or recorded reports, not both")
    backend: SandboxBackend | None = None
    if cape_report or memory_report or runtime_report:
        backend = ReplayBackend(cape_report=cape_report, memory_report=memory_report, runtime_report=runtime_report)
    elif enable_dynamic:
        backend = sandbox_backend

    isolated = False
    if enable_dynamic and backend is None:
        notes.append("no sandbox backend configured — no sample execution; static-only analysis")
    elif not enable_dynamic and backend is None:
        notes.append("dynamic analysis disabled — static-only analysis")

    ctx = Context(run_id=run_id, config=config, audit=audit, isolated=False)

    analyzers_run: list[str] = []

    # --- Static-evidence cache (content-addressed by sha256) ---
    # A pure static, offline run is a deterministic function of the sample bytes,
    # so re-analysing the same file can reload persisted evidence instead of
    # re-running every analyzer. Only the static path is cacheable: a live
    # detonation is non-deterministic, and a recorded-report replay depends on
    # external files, so both bypass the cache.
    cacheable = backend is None
    cache_path = _cache_path(config, sample)
    cache_hit = use_cache and cacheable and cache_path.exists()

    if cache_hit:
        try:
            for item in EvidenceStore.load(str(cache_path)):
                # Cached static evidence belongs to this analysis, not the run
                # that originally populated the content-addressed cache.
                rebound = item.model_copy(
                    update={"run_id": run_id, "ts": datetime.now(UTC).isoformat()}
                )
                store.append(rebound)  # append fires the stream subscriber, if any
            analyzers_run.append("<cache>")
            notes.append(f"loaded static evidence from cache ({len(store)} items; re-analysis skipped)")
            audit.log(run_id=run_id, action="cache_hit", sample_hash=sample.sha256, evidence=len(store))
        except Exception:
            cache_hit = False  # corrupt cache — fall through to a fresh run

    if not cache_hit:
        # --- Dispatch analyzers ---
        tags = analyzer_tags_for(triage.fmt) | {"*"}
        selected: list = []
        seen = set()
        for tag in tags:
            # Execution-capable analyzers are never dispatched in-process. The
            # optional backend below owns detonation and returns inert artifacts.
            for a in REGISTRY.for_format(tag, include_dynamic=False, isolated=False):
                if a.name not in seen:
                    seen.add(a.name)
                    selected.append(a)

        # Analyzers are independent by contract (they only read the sample +
        # Context and return EvidenceItems), so run them concurrently. The store
        # append is already thread-safe. This collapses wall time to the slowest
        # analyzer — which matters most when capa/pefile subprocesses are in the
        # mix. Results are appended in a stable analyzer order so evidence ids
        # stay deterministic.
        if len(selected) > 1:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=min(8, len(selected))) as pool:
                results = list(pool.map(lambda a: (a.name, a.analyze(sample, ctx)), selected))
        else:
            results = [(a.name, a.analyze(sample, ctx)) for a in selected]
        for name, items in results:
            store.extend(items)
            analyzers_run.append(name)

        # Persist the static evidence for future cache hits (before dynamic
        # replay, so the cached store is the pure-static, deterministic subset).
        if cacheable:
            try:
                store.dump(str(cache_path))
            except Exception:
                pass

    if decompiler_report:
        from ..analyzers.static.ghidra import normalize_decompilation
        path = Path(decompiler_report)
        if path.stat().st_size > 32 * 1024**2:
            raise ValueError("decompiler report exceeds 32 MiB")
        document = json.loads(path.read_text())
        if document.get("target_sha256") != sample.sha256:
            raise ValueError("decompiler report belongs to another sample")
        store.extend(normalize_decompilation(document, ctx))
        analyzers_run.append("static.ghidra")

    bundle = None
    if backend is not None:
        backend_ran, bundle = _run_backend(
            backend=backend,
            policy=sandbox_policy or AnalysisPolicy(platform=triage.fmt),
            sample=sample,
            ctx=ctx,
            store=store,
            notes=notes,
            audit=audit,
            run_id=run_id,
        )
        analyzers_run.extend(backend_ran)
        isolated = bool(
            bundle is not None
            and bundle.execution_mode == "sandbox"
            and bundle.isolation_verified
        )
        ctx.isolated = isolated

    if intelligence_snapshot:
        from ..enrich.intelligence import enrich_snapshot
        store.extend(enrich_snapshot(store, intelligence_snapshot, run_id))

    # --- Reconstruction ---
    mappings = map_evidence(store)
    phases = build_narrative(mappings)
    timeline = build_timeline(store)
    graph = build_graph(store, mappings, sample_name=sample.name)

    # --- Detections ---
    # Test generated YARA against any real goodware in docker/clean_corpus/ (in
    # addition to the bundled snippets) so rules that would false-positive on
    # benign binaries are pruned before they ever ship.
    yara = generate_yara(store, sample, clean_corpus=load_clean_corpus())
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
        execution_mode=bundle.execution_mode if bundle is not None else "static",
        sandbox_backend=backend.name if backend is not None and bundle is not None else None,
        artifact_bundle=bundle,
    )


def persist_run(result: RunResult, config: Config | None = None) -> Path:
    """Dump the evidence store to the run dir for `replay`/`ask`."""
    config = config or get_config()
    run_dir = config.run_dir(result.run_id)
    result.store.dump(str(run_dir / "evidence.jsonl"))
    (run_dir / "meta.txt").write_text(
        f"sample={result.sample.name}\nsha256={result.sample.sha256}\nformat={result.triage.fmt}\n"
        f"execution_mode={result.execution_mode}\nbackend={result.sandbox_backend or ''}\n"
        f"isolated={result.isolated}\n"
    )
    if result.artifact_bundle is not None:
        manifest_path = run_dir / "artifacts.json"
        manifest_path.write_text(
            json.dumps(result.artifact_bundle.manifest(), indent=2, sort_keys=True) + "\n"
        )
        manifest_path.chmod(0o600)
    return run_dir


def build_report_inputs(result: RunResult):
    from ..reporting.report import ReportInputs

    return ReportInputs(
        run_id=result.run_id,
        sample_name=result.sample.name,
        sha256=result.sample.sha256,
        fmt=result.triage.fmt,
        isolation=(
            f"verified sandbox ({result.sandbox_backend})"
            if result.isolated
            else "recorded artifact replay (no local execution)"
            if result.execution_mode == "replay"
            else "not configured (static-only)"
        ),
        store=result.store,
        mappings=result.mappings,
        phases=result.phases,
        timeline=result.timeline,
        yara=result.yara,
        sigma=result.sigma,
        coverage=result.coverage,
        graph=result.graph,
    )
