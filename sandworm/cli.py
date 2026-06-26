"""SANDWORM command-line interface.

Commands:
  analyze   route a sample through the full pipeline, write an HTML report
  report    re-render a report from a persisted run
  ask       graph-grounded copilot question over a run's evidence
  replay    print the evidence/timeline for a persisted run
  plugins   list registered analyzers (built-in + discovered plugins)
"""

from __future__ import annotations

from pathlib import Path

import typer

from .analyzers.registry import REGISTRY, register_builtins
from .core.config import get_config
from .core.evidence import EvidenceStore
from .core.pipeline import analyze_sample, build_report_inputs, persist_run
from .core.sample import Sample, SampleStore
from .reconstruct.attack_map import map_evidence
from .reconstruct.graph import build_graph

app = typer.Typer(add_completion=False, help="SANDWORM — reconstruct what happened, explain why, emit detections.")


@app.command()
def analyze(
    sample_path: str = typer.Argument(..., help="Path to the sample to analyze."),
    out: str = typer.Option("", "--out", "-o", help="HTML report output path."),
    no_dynamic: bool = typer.Option(False, "--no-dynamic", help="Skip the dynamic lane entirely."),
    cape_report: str = typer.Option("", "--cape-report", help="Ingest a recorded CAPE/DRAKVUF JSON report (offline replay; not a live detonation)."),
    memory_report: str = typer.Option("", "--memory-report", help="Ingest a recorded volatility3 JSON report (offline replay)."),
    store_sample: bool = typer.Option(False, "--store", help="Defang+store the sample encrypted-at-rest."),
    stream: bool = typer.Option(False, "--stream", help="Stream evidence live (ALERT on high-signal findings) as it is discovered."),
):
    """Analyze a sample end-to-end and write an HTML report."""
    cfg = get_config()
    p = Path(sample_path)
    if not p.exists():
        typer.secho(f"sample not found: {sample_path}", fg=typer.colors.RED)
        raise typer.Exit(1)
    for label, val in (("--cape-report", cape_report), ("--memory-report", memory_report)):
        if val and not Path(val).exists():
            typer.secho(f"{label} not found: {val}", fg=typer.colors.RED)
            raise typer.Exit(1)
    sample = Sample.from_path(p)
    if store_sample:
        SampleStore(cfg).store(sample)

    feed = None
    if stream:
        from .reporting.stream import StreamFeed
        def _emit(line: str) -> None:
            typer.secho(line, fg=typer.colors.RED if line.startswith("ALERT") else None)
        feed = StreamFeed(sink=_emit)
        typer.secho("── live evidence feed ──", fg=typer.colors.CYAN)

    result = analyze_sample(
        sample, config=cfg, enable_dynamic=not no_dynamic,
        cape_report=cape_report or None, memory_report=memory_report or None,
        on_evidence=feed,
    )
    if feed is not None:
        typer.secho(f"── feed complete: {len(feed.lines)} events, {feed.alerts} alert(s) ──\n", fg=typer.colors.CYAN)
    run_dir = persist_run(result, cfg)

    typer.secho(f"run {result.run_id}  format={result.triage.fmt}  isolated={result.isolated}", fg=typer.colors.CYAN)
    for note in result.notes:
        typer.secho(f"  · {note}", fg=typer.colors.YELLOW)
    typer.echo(f"  evidence items : {len(result.store)}")
    typer.echo(f"  analyzers      : {', '.join(result.analyzers_run)}")
    from .reporting.summary import build_summary

    summary = build_summary(result.store, result.mappings, result.phases, isolated=result.isolated)
    typer.secho(
        f"  verdict        : risk={summary.risk}  maliciousness={summary.maliciousness_score}/100"
        f"  family={summary.family_hint}",
        fg=typer.colors.CYAN,
    )
    typer.echo("  ATT&CK techniques:")
    for m in result.mappings:
        typer.echo(f"     [{m.status:<9}] {m.technique_id} {m.technique_name}  conf={m.confidence:.2f}  — {m.why[:70]}")
    cov = result.coverage
    detect = "yes" if cov.detectable else "no"
    typer.echo(
        f"  detections     : YARA={len(result.yara)}  Sigma={len(result.sigma)}"
        f" (behavioural={cov.inventory.behavioral_rules}, IOC={cov.inventory.ioc_rules})  detectable={detect}"
    )
    typer.echo(
        f"  evidence/cov   : evidence={len(result.store)}  ATT&CK={cov.inferred_techniques} inferred"
        f"/{cov.observed_techniques} observed  technique-rule-coverage={cov.overall*100:.0f}%"
        f"  runtime={'N/A' if cov.runtime_coverage is None else f'{cov.runtime_coverage*100:.0f}%'}"
    )

    out_path = Path(out) if out else run_dir / "report.html"
    from .reporting.report import write_report

    write_report(build_report_inputs(result), out_path)
    typer.secho(f"report → {out_path}", fg=typer.colors.GREEN)


@app.command()
def report(run_id: str = typer.Argument(...), out: str = typer.Option("", "--out", "-o")):
    """Re-render an HTML report from a persisted run's evidence."""
    cfg = get_config()
    run_dir = cfg.run_dir(run_id)
    ev = run_dir / "evidence.jsonl"
    if not ev.exists():
        typer.secho(f"no persisted run {run_id}", fg=typer.colors.RED)
        raise typer.Exit(1)
    store = EvidenceStore.load(str(ev))
    _render_from_store(run_id, store, Path(out) if out else run_dir / "report.html")
    typer.secho("report re-rendered", fg=typer.colors.GREEN)


@app.command()
def ask(
    question: str = typer.Argument(..., help="Natural-language question about a run."),
    run_id: str = typer.Option("", "--run", help="Run id to query (defaults to latest)."),
    show_cypher: bool = typer.Option(True, "--show-cypher/--no-cypher"),
):
    """Ask the graph-grounded copilot. Abstains when the graph lacks support."""
    from .copilot.graphrag import ask as copilot_ask

    cfg = get_config()
    rid = run_id or _latest_run(cfg)
    if not rid:
        typer.secho("no runs available", fg=typer.colors.RED)
        raise typer.Exit(1)
    store = EvidenceStore.load(str(cfg.run_dir(rid) / "evidence.jsonl"))
    graph = build_graph(store)
    ans = copilot_ask(graph, question)
    typer.secho(f"[run {rid}] {'grounded' if ans.grounded else 'ABSTAINED'}", fg=typer.colors.CYAN)
    typer.echo(ans.answer)
    if ans.citations:
        typer.secho("citations: " + ", ".join(ans.citations), fg=typer.colors.BLUE)
    if show_cypher:
        typer.secho("\n--- raw Cypher ---", fg=typer.colors.MAGENTA)
        typer.echo(ans.cypher)


@app.command()
def replay(run_id: str = typer.Argument(...)):
    """Print the timeline + evidence for a persisted run."""
    from .reconstruct.timeline import build_timeline

    cfg = get_config()
    store = EvidenceStore.load(str(cfg.run_dir(run_id) / "evidence.jsonl"))
    for e in build_timeline(store):
        typer.echo(f"{e.seq:>3}  [{e.source}] {e.text}  ({e.confidence:.2f})  {e.evidence_id}")


@app.command()
def plugins(plugin_dir: str = typer.Option("", "--dir", help="Extra plugin directory to scan.")):
    """List registered analyzers (built-in + discovered plugins)."""
    register_builtins()
    if plugin_dir:
        loaded = REGISTRY.load_plugins(plugin_dir)
        if loaded:
            typer.secho(f"loaded plugins: {', '.join(loaded)}", fg=typer.colors.GREEN)
    for a in REGISTRY.all():
        lane = "dynamic(gated)" if a.requires_isolation else "static"
        typer.echo(f"  {a.name:<26} handles={sorted(a.handles)}  [{lane}]")


@app.command()
def lineage(
    run_id: str = typer.Argument("", help="Run to compare; defaults to the latest persisted run."),
    threshold: float = typer.Option(0.5, "--threshold", help="Minimum behavioural similarity to report."),
):
    """Cross-sample lineage: build a behavioural-signature corpus from persisted
    runs and show the target run's nearest neighbours + their behavioural diff."""
    from .reconstruct.lineage import LineageIndex, diff, signature_of

    cfg = get_config()
    runs = sorted((cfg.work_dir / "runs").glob("*/evidence.jsonl")) if (cfg.work_dir / "runs").exists() else []
    if not runs:
        typer.secho("no persisted runs found (run `analyze` first)", fg=typer.colors.YELLOW)
        raise typer.Exit(0)
    index = LineageIndex(cfg.work_dir / "lineage.json")
    sigs: dict[str, object] = {}
    for jsonl in runs:
        rid = jsonl.parent.name
        store = EvidenceStore.load(str(jsonl))
        meta = _read_meta(jsonl.parent / "meta.txt")
        sig = signature_of(meta.get("sha256", rid), meta.get("sample", rid), store,
                           created=meta.get("created", ""))
        index.add(sig)
        sigs[rid] = sig
    index.save()

    rid = run_id or _latest_run(cfg)
    target = sigs.get(rid)
    if target is None:
        typer.secho(f"run '{rid}' not found among persisted runs", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.secho(f"lineage for {target.name} ({rid}) — corpus of {len(index.sigs)} sample(s)\n",  # type: ignore[attr-defined]
                fg=typer.colors.GREEN)
    neighbours = index.neighbours(target, threshold=threshold)  # type: ignore[arg-type]
    if not neighbours:
        typer.echo("no behavioural neighbours above the threshold (sample looks novel).")
        return
    for n in neighbours:
        d = diff(target, n.signature)  # type: ignore[arg-type]
        typer.secho(f"  {n.similarity*100:.0f}% · {n.signature.name} ({n.signature.sha256[:12]})", fg=typer.colors.CYAN)
        typer.echo(f"      shared:    {', '.join(d.shared) or '—'}")
        typer.echo(f"      evolution: {d.evolution_note(target, n.signature)}")  # type: ignore[arg-type]


def _read_meta(path: Path) -> dict:
    meta: dict = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                meta[k.strip()] = v.strip()
    return meta


@app.command()
def generate(
    base: str = typer.Argument(..., help="A benign sample to derive variants from."),
    count: int = typer.Option(10, "--count"),
    out: str = typer.Option("variants", "--out", help="Output directory."),
    seed: int = typer.Option(0, "--seed"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Check each variant keeps the base's techniques."),
):
    """Generate benign, semantics-preserving variants of a sample for detection
    engineering (stress-test YARA/Sigma; feed the rule optimiser). Never adds
    capability — only perturbs the surface and rotates IOCs to reserved ranges."""
    from .enrich.generate import generate_variants, label_preserved

    sample = Sample.from_path(base)
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = generate_variants(sample, count, seed=seed)
    typer.secho(f"generated {len(variants)} variant(s) of {sample.name} → {out_dir}/", fg=typer.colors.GREEN)
    for v in variants:
        (out_dir / v.name).write_bytes(v.data)
        line = f"  {v.name}  [{', '.join(v.mutations)}]"
        if verify:
            ok = label_preserved(sample, Sample.from_bytes(v.name, v.data))
            line += "  label=preserved" if ok else "  label=CHANGED"
        typer.echo(line)


@app.command(name="optimize-rules")
def optimize_rules(
    malicious_dir: str = typer.Argument(..., help="Directory of malicious samples the rules should catch."),
    clean_dir: str = typer.Option("", "--clean", help="Extra directory of benign samples rules must NOT hit."),
    generations: int = typer.Option(25, "--generations"),
    seed: int = typer.Option(0, "--seed"),
):
    """Evolve a Pareto frontier of YARA rules (strict / balanced / loose) over a
    malicious corpus + the bundled clean corpus — optimise detections, offline."""
    from .detect.optimize import optimize
    from .detect.yara_gen import CLEAN_CORPUS, generate_yara

    register_builtins()
    mal_paths = sorted(p for p in Path(malicious_dir).glob("*") if p.is_file())
    if not mal_paths:
        typer.secho("no samples found", fg=typer.colors.RED)
        raise typer.Exit(1)
    pool: list[bytes] = []
    malicious: list[bytes] = []
    for p in mal_paths:
        sample = Sample.from_path(p)
        malicious.append(sample.data)
        result = analyze_sample(sample, enable_dynamic=False)
        for rule in generate_yara(result.store, sample):
            pool.extend(rule.strings)
    pool = list(dict.fromkeys(pool))
    clean = list(CLEAN_CORPUS)
    if clean_dir:
        clean += [p.read_bytes() for p in Path(clean_dir).glob("*") if p.is_file()]

    front = optimize(pool, malicious, clean, generations=generations, seed=seed)
    picks = front.pick()
    if not picks:
        typer.secho("no rule strings extracted — nothing to optimise", fg=typer.colors.YELLOW)
        raise typer.Exit(0)
    typer.secho(f"Pareto frontier: {len(front.points)} non-dominated rule(s)\n", fg=typer.colors.GREEN)
    for label, s in picks.items():
        typer.secho(f"# {label}: recall={s.recall:.2f} fp_rate={s.fp_rate:.2f} cost={s.cost:.2f}",
                    fg=typer.colors.CYAN)
        typer.echo(s.candidate.to_rule(f"SANDWORM_OPT_{label.upper()}",
                   {"objective": label, "recall": s.recall, "fp_rate": s.fp_rate}).to_yara())
        typer.echo("")


def _latest_run(cfg) -> str:
    runs = cfg.work_dir / "runs"
    if not runs.exists():
        return ""
    candidates = sorted(runs.glob("*/evidence.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0].parent.name if candidates else ""


def _render_from_store(run_id: str, store: EvidenceStore, out_path: Path) -> None:
    from .detect.sigma_gen import generate_sigma
    from .reconstruct.narrative import build_narrative
    from .reconstruct.timeline import build_timeline
    from .reporting.coverage import compute_coverage
    from .reporting.report import ReportInputs, write_report

    mappings = map_evidence(store)
    graph = build_graph(store, mappings)
    sigma = generate_sigma(store, mappings)
    coverage = compute_coverage(mappings, sigma, [])
    inp = ReportInputs(
        run_id=run_id,
        sample_name=f"run {run_id}",
        sha256="(replayed)",
        fmt="(replayed)",
        isolation="(replayed)",
        store=store,
        mappings=mappings,
        phases=build_narrative(mappings),
        timeline=build_timeline(store),
        yara=[],
        sigma=sigma,
        coverage=coverage,
        graph=graph,
    )
    write_report(inp, out_path)


if __name__ == "__main__":
    app()
