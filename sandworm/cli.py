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
    store_sample: bool = typer.Option(False, "--store", help="Defang+store the sample encrypted-at-rest."),
):
    """Analyze a sample end-to-end and write an HTML report."""
    cfg = get_config()
    p = Path(sample_path)
    if not p.exists():
        typer.secho(f"sample not found: {sample_path}", fg=typer.colors.RED)
        raise typer.Exit(1)
    sample = Sample.from_path(p)
    if store_sample:
        SampleStore(cfg).store(sample)

    result = analyze_sample(sample, config=cfg, enable_dynamic=not no_dynamic)
    run_dir = persist_run(result, cfg)

    typer.secho(f"run {result.run_id}  format={result.triage.fmt}  isolated={result.isolated}", fg=typer.colors.CYAN)
    for note in result.notes:
        typer.secho(f"  · {note}", fg=typer.colors.YELLOW)
    typer.echo(f"  evidence items : {len(result.store)}")
    typer.echo(f"  analyzers      : {', '.join(result.analyzers_run)}")
    typer.echo("  ATT&CK techniques:")
    for m in result.mappings:
        typer.echo(f"     {m.technique_id} {m.technique_name}  conf={m.confidence:.2f}  — {m.why[:80]}")
    typer.echo(f"  YARA rules     : {len(result.yara)}   Sigma rules: {len(result.sigma)}")
    typer.echo(f"  coverage       : {result.coverage.overall*100:.0f}%")

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
