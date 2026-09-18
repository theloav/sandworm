"""Offline benchmark and actual-engine goodware audits."""
from __future__ import annotations

import json
from pathlib import Path

import typer


def register_commands(app: typer.Typer) -> None:
    @app.command("benchmark-matchers")
    def benchmark_matchers(out: Path, megabytes: int = 8, repeats: int = 5):
        """Compare current regex sweep with optional Aho-Corasick; verify parity."""
        from .performance import matcher_benchmark
        report = matcher_benchmark(megabytes, repeats)
        out.write_text(json.dumps(report, indent=2) + "\n")
        typer.echo(json.dumps(report["median_seconds"]))

    @app.command("index-corpus")
    def index_corpus(runs: Path, database: Path):
        """Materialize exact-value and facet indexes over a trusted run directory."""
        from ..core.corpus_index import CorpusIndex
        index = CorpusIndex(database)
        changed = 0
        for path in sorted(runs.rglob("evidence.jsonl")):
            if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(runs.resolve()):
                changed += int(index.ingest(path))
        typer.echo(json.dumps({"sources_indexed": changed}))

    @app.command("query-corpus")
    def query_corpus(database: Path, value: str = "", artifact: str = "", operation: str = "", limit: int = 100):
        """Search indexed evidence without loading every persisted run."""
        from ..core.corpus_index import CorpusIndex
        if not database.is_file():
            raise typer.BadParameter("index database does not exist")
        typer.echo(json.dumps(CorpusIndex(database).search(value=value or None, artifact=artifact or None, operation=operation or None, limit=limit), indent=2))

    @app.command("detection-bundle")
    def detection_bundle(sample: Path, out: Path, sigma_target: str = "", sigma_pipeline: str = "", sigma_product: str = ""):
        """Generate review-ready rules, optional SIEM conversions and YARA smoke tests."""
        from ..core.pipeline import analyze_sample
        from ..core.sample import Sample
        from ..detect.bundle import write_bundle
        result = analyze_sample(Sample.from_path(sample), enable_dynamic=False)
        report = write_bundle(result, out, target=sigma_target, pipeline=sigma_pipeline, product=sigma_product)
        typer.echo(str(out))
        if any(row["status"] == "failed" for row in report["conversions"]):
            raise typer.Exit(2)

    @app.command("benchmark")
    def benchmark(manifest: Path, out: Path = Path("benchmark-results"), threshold: float = 0.5,
                  baseline: Path | None = None):
        """Measure ATT&CK precision/recall and calibration without sample execution."""
        from .benchmark import evaluate, write_results
        report = evaluate(manifest, threshold=threshold)
        write_results(report, out)
        typer.echo(json.dumps({"micro": report["micro"], "emitted_brier": report["calibration_emitted"]["brier"]}))
        if baseline:
            previous = json.loads(baseline.read_text())
            if previous["manifest_sha256"] != report["manifest_sha256"] or previous["threshold"] != threshold:
                raise typer.BadParameter("baseline must use the identical corpus and threshold")
            regressed = any(row["fp"] > previous["per_technique"][tid]["fp"] or row["fn"] > previous["per_technique"][tid]["fn"]
                            for tid, row in report["per_technique"].items())
            before, after = previous["calibration_emitted"]["brier"], report["calibration_emitted"]["brier"]
            if regressed or (before is not None and after is not None and after > before + 0.02):
                raise typer.Exit(1)

    @app.command("goodware-inventory")
    def goodware_inventory(corpus: Path, out: Path, provenance: str = typer.Option(...)):
        """Hash actual files for auditing; does not certify benign status."""
        from .goodware import inventory
        if out.resolve().is_relative_to(corpus.resolve()):
            raise typer.BadParameter("write the inventory outside the scanned corpus")
        out.write_text(json.dumps(inventory(corpus, provenance=provenance), indent=2) + "\n")
        typer.echo(str(out))

    @app.command("yara-audit")
    def yara_audit(rules: Path, manifest: Path, corpus: Path, out: Path, timeout: int = 30):
        """Scan hash-pinned goodware using YARA-X; no sample execution."""
        from .goodware import audit
        report = audit(rules, manifest, corpus, timeout=timeout)
        out.write_text(json.dumps(report, indent=2) + "\n")
        typer.echo(json.dumps({k: report[k] for k in ("files_scanned", "matching_files", "observed_fp_rate", "complete")}))
        if not report["complete"]:
            raise typer.Exit(2)
