"""Bounded analysis workers. Submitted bytes are parsed, never launched here."""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import signal
import time
import uuid
from dataclasses import replace
from pathlib import Path

from ..core.config import Config
from ..core.pipeline import analyze_sample, build_report_inputs, persist_run
from ..core.sample import SampleStore
from ..reporting.export import findings_json
from ..reporting.report import write_report
from ..reporting.summary import build_summary
from .store import PlatformStore


def job_config(store: PlatformStore, jid: str) -> Config:
    cfg = Config(work_dir=store.job_dir(jid))
    # Graph data is served per run. Do not merge tenant data into a shared graph.
    return replace(cfg, neo4j_uri=None, llm_provider="mock")


def execute(root: str, job: dict, attempt: str) -> None:
    if hasattr(os, "setsid"):
        os.setsid()
        os.environ["SANDWORM_ATTEMPT_PROCESS_GROUP"] = str(os.getpid())
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except (ImportError, ValueError, OSError):
        pass
    store = PlatformStore(root)
    cfg = job_config(store, job["id"])
    sample = SampleStore(cfg).load(job["sha256"], job["name"])
    # Each attempt has its own output path. Only the lease holder can publish it.
    cfg = replace(cfg, work_dir=Path(attempt))
    options = job["options"]
    from ..sandbox.profiles import resolve_profile
    backend, policy = resolve_profile(options.get("profile", "static"), cfg)
    decompiler_report = None
    if policy.options.get("decompile") == "true":
        from ..analyzers.static.ghidra import decompile
        path = Path(attempt) / "decompiled.json"
        path.write_text(json.dumps(decompile(sample)))
        decompiler_report = str(path)
    result = analyze_sample(sample, config=cfg, run_id=job["id"],
                            sandbox_backend=backend, sandbox_policy=policy,
                            enable_dynamic=backend is not None, use_cache=False, decompiler_report=decompiler_report)
    if backend is not None and result.artifact_bundle is None:
        raise RuntimeError("sandbox analysis failed; see worker log")
    run_dir = persist_run(result, cfg)
    write_report(build_report_inputs(result), run_dir / "report.html")
    summary = build_summary(result.store, result.mappings, result.phases, isolated=result.isolated)
    (run_dir / "findings.json").write_text(json.dumps(findings_json(result, summary)))


def run_once(store: PlatformStore, worker: str = "local", *, poll: float = 1.0) -> bool:
    job = store.claim(worker)
    if not job:
        return False
    lease = job["lease"]
    attempt = store.job_dir(job["id"]) / "attempts" / lease
    attempt.mkdir(parents=True, mode=0o700)
    child = multiprocessing.get_context("spawn").Process(target=execute, args=(str(store.root), job, str(attempt)))
    child.start()
    deadline = time.monotonic() + min(int(job["options"].get("timeout", 600)), 3600)
    error = ""
    try:
        while child.is_alive():
            status = store.heartbeat(job["id"], lease)
            if status != "running" or time.monotonic() > deadline:
                error = "cancelled or lease lost" if status != "running" else "analysis deadline exceeded"
                break
            child.join(poll)
    finally:
        if child.is_alive():
            # Parser tools inherit this child's group; cancel the whole attempt.
            try:
                if child.pid and hasattr(os, "killpg") and os.getpgid(child.pid) == child.pid:
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
            except ProcessLookupError:
                pass
            child.join(3)
            # The controller may have exited while a descendant ignored TERM.
            # Always reap the original attempt group, not only the leader.
            if child.pid and hasattr(os, "killpg"):
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if child.is_alive():
                child.kill()
                child.join()
    result_path = attempt / "runs" / job["id"] / "findings.json"
    if not error and (child.exitcode != 0 or not result_path.is_file()):
        error = f"analysis process failed (exit {child.exitcode})"
    result = {} if error else json.loads(result_path.read_text())
    if not error:
        result["attempt"] = lease
    store.finish(job["id"], lease, result=result, error=error)
    store.event(job["workspace"], worker, "worker_finished", job["id"])
    return True


def serve_worker(root: str | Path, *, once: bool = False) -> None:
    store = PlatformStore(root)
    worker = f"{os.uname().nodename if hasattr(os, 'uname') else 'worker'}-{uuid.uuid4().hex[:8]}"
    while True:
        worked = run_once(store, worker)
        if once:
            return
        if not worked:
            time.sleep(2)


def retain(store: PlatformStore, days: int, *, dry_run: bool = True) -> list[str]:
    if days < 1:
        raise ValueError("retention must be at least one day")
    with store.connect() as db:
        rows = db.execute("SELECT id,workspace FROM jobs WHERE status IN ('completed','failed','cancelled') AND updated<? AND id NOT IN (SELECT source_job FROM schedules WHERE enabled=1)",
                          (time.time() - days * 86400,)).fetchall()
    ids = []
    for row in rows:
        path = store.job_dir(row["id"])
        ids.append(row["id"])
        if not dry_run:
            if path.is_dir():
                shutil.rmtree(path)
            with store.connect() as db:
                db.execute("UPDATE jobs SET status='expired',result='{}',updated=? WHERE id=?", (time.time(), row["id"]))
            store.event(row["workspace"], "retention", "expired", row["id"])
    return ids
