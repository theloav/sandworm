"""CLI entry points for operations and advanced analysis integrations."""
from __future__ import annotations

import getpass
import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path

import typer

from ..core.config import get_config


def register_commands(app: typer.Typer) -> None:
    def root() -> Path:
        return get_config().work_dir / "platform"

    @app.command()
    def serve(host: str = "127.0.0.1", port: int = 8000, local_http: bool = False):
        """Serve the browser workspace/API; run workers separately."""
        if local_http and host not in {"127.0.0.1", "localhost", "::1"}:
            raise typer.BadParameter("--local-http is only allowed on a loopback address")
        try:
            import uvicorn

            from .api import create_app
        except ImportError as exc:
            raise typer.BadParameter("install the web extra") from exc
        uvicorn.run(create_app(root(), secure_cookies=not local_http), host=host, port=port, proxy_headers=False)

    @app.command()
    def worker(once: bool = False, url: str = "", local_http: bool = False):
        """Run a queue worker. Multiple local worker processes share atomic leases."""
        from .worker import serve_worker
        if url:
            from .remote import remote_worker
            remote_worker(url, os.environ.get("SANDWORM_WORKER_KEY", ""), once=once, local_http=local_http)
        else:
            serve_worker(root(), once=once)

    @app.command("user-add")
    def user_add(username: str, workspace: str = "default", role: str = "admin"):
        """Create an account; password is prompted without echo or shell history."""
        from .store import PlatformStore
        password = getpass.getpass("New password (12+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            raise typer.BadParameter("passwords did not match")
        try:
            uid = PlatformStore(root()).create_user(username, password, workspace, role)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        typer.echo(f"Created {username} ({uid}) in {workspace}")

    @app.command("key-issue")
    def key_issue(username: str):
        """Issue a service key for a local account; the key is displayed once."""
        from .store import PlatformStore
        store = PlatformStore(root())
        with store.connect() as db:
            user = db.execute("SELECT id FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not user:
            raise typer.BadParameter("unknown account")
        typer.echo(store.issue(user["id"])[0])

    @app.command()
    def retention(days: int = 30, apply: bool = False):
        """List expired jobs; --apply removes artifacts and keeps audit tombstones."""
        from .store import PlatformStore
        from .worker import retain
        typer.echo(json.dumps({"dry_run": not apply, "jobs": retain(PlatformStore(root()), days, dry_run=not apply)}))

    @app.command("sandbox-build")
    def sandbox_build(image: Path, sha256: str, out: Path):
        """Provision a Linux guest from a hash-pinned Ubuntu cloud image."""
        from ..sandbox.provision import build_guest
        typer.echo(json.dumps(build_guest(image, sha256, out), indent=2))

    @app.command()
    def doctor():
        """Report installed capabilities and external prerequisites."""
        from importlib.util import find_spec

        from ..sandbox.profiles import available_profiles
        status = {"modules": {name: find_spec(name) is not None for name in ("fastapi", "pyzipper", "unicorn", "capstone", "sklearn", "volatility3")},
                  "tools": {name: shutil.which(name) for name in ("qemu-system-x86_64", "qemu-img", "genisoimage", "vol", "java")},
                  "kvm": os.access("/dev/kvm", os.R_OK | os.W_OK), "ghidra": bool(os.environ.get("GHIDRA_HOME")),
                  "profiles": list(available_profiles())}
        typer.echo(json.dumps(status, indent=2))

    @app.command()
    def decompile(sample_path: Path, out: Path = Path("decompiled.json")):
        """Export Ghidra decompiled functions, call targets and p-code."""
        from ..analyzers.static.ghidra import decompile as run
        from ..core.sample import Sample
        out.write_text(json.dumps(run(Sample.from_path(sample_path)), indent=2))
        typer.echo(str(out))

    @app.command("memory-analyze")
    def memory_analyze(sample_path: Path, image: Path, out: Path = Path("memory-report.json"), platform: str = "windows", symbols: Path | None = None):
        """Collect Volatility findings from a captured image for this sample."""
        from ..analyzers.memory.collect import collect_memory
        from ..core.sample import Sample
        out.write_text(json.dumps(collect_memory(Sample.from_path(sample_path), image, platform=platform, symbols=symbols), indent=2))
        typer.echo(str(out))

    @app.command()
    def cluster(distance: float = 0.3, out: Path = Path("clusters.json")):
        """Cluster persisted runs using graph features and cosine DBSCAN."""
        from ..core.evidence import EvidenceStore
        from ..reconstruct.clustering import cluster_runs
        runs = {p.parent.name: EvidenceStore.load(str(p)) for p in (get_config().work_dir / "runs").glob("*/evidence.jsonl")}
        out.write_text(json.dumps(cluster_runs(runs, distance=distance), indent=2))
        typer.echo(str(out))

    @app.command()
    def hypotheses(run_id: str):
        """Generate separately labeled hypotheses using the configured LLM."""
        from ..copilot.hypotheses import propose
        from ..core.evidence import EvidenceStore
        from ..core.providers import get_provider
        if "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
            raise typer.BadParameter("invalid run id")
        store = EvidenceStore.load(str(get_config().work_dir / "runs" / run_id / "evidence.jsonl"))
        typer.echo(json.dumps(propose(store, get_provider()), indent=2))

    @app.command()
    def differential(sample_path: Path, profiles: str, out: Path = Path("differential.json")):
        """Run a sample under two or more named sandbox profiles."""
        from ..core.pipeline import analyze_sample, persist_run
        from ..core.sample import Sample
        from ..enrich.differential import diff_runs
        from ..sandbox.profiles import resolve_profile
        names = list(dict.fromkeys(profiles.split(",")))
        if not 2 <= len(names) <= 8:
            raise typer.BadParameter("provide 2–8 distinct comma-separated profile names")
        sample, runs = Sample.from_path(sample_path), {}
        for name in names:
            backend, policy = resolve_profile(name, get_config())
            result = analyze_sample(sample, sandbox_backend=backend, sandbox_policy=policy, enable_dynamic=backend is not None, use_cache=False)
            if backend is not None and result.artifact_bundle is None:
                raise typer.BadParameter(f"profile {name} failed; comparison aborted")
            persist_run(result)
            runs[name] = result.store
        out.write_text(json.dumps([asdict(d) for d in diff_runs(runs)], indent=2))
        typer.echo(str(out))
