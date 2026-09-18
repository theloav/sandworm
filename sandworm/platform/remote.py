"""HTTPS worker transport. Worker credentials are supplied through environment."""
from __future__ import annotations

import json
import multiprocessing
import os
import signal
import tempfile
import time
from urllib.parse import urlparse

from ..core.sample import Sample, SampleStore
from .store import PlatformStore
from .worker import execute, job_config


def remote_worker(url: str, token: str, *, once: bool = False, local_http: bool = False) -> None:
    import httpx

    parsed = urlparse(url)
    if parsed.scheme != "https" and not (local_http and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("remote workers require HTTPS; --local-http permits loopback only")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("worker URL must not contain credentials, queries or fragments")
    if not token:
        raise ValueError("set SANDWORM_WORKER_KEY to a worker service key")
    with httpx.Client(base_url=url.rstrip("/"), headers={"Authorization": "Bearer " + token}, timeout=60, follow_redirects=False) as client:
        def post(path, body=None):
            response = client.post(path, json=body or {})
            response.raise_for_status()
            return response

        while True:
            job = post("/api/worker/claim").json()
            if job:
                lease = {"lease": job["lease"]}
                with tempfile.TemporaryDirectory(prefix="sw-remote-") as tmp:
                    store = PlatformStore(tmp)
                    payload = post(f"/api/worker/{job['id']}/sample", lease).content
                    sample = Sample.from_bytes(job["name"], payload)
                    if sample.sha256 != job["sha256"]:
                        raise RuntimeError("downloaded sample failed identity verification")
                    SampleStore(job_config(store, job["id"])).store(sample)
                    attempt = store.job_dir(job["id"]) / "attempts" / job["lease"]
                    attempt.mkdir(parents=True, mode=0o700)
                    child = multiprocessing.get_context("spawn").Process(target=execute, args=(tmp, job, str(attempt)))
                    child.start()
                    error = ""
                    deadline = time.monotonic() + 900
                    try:
                        while child.is_alive():
                            status = post(f"/api/worker/{job['id']}/heartbeat", lease).json()["status"]
                            if status != "running" or time.monotonic() > deadline:
                                error = "cancelled or worker deadline exceeded"
                                break
                            child.join(2)
                    finally:
                        if child.is_alive():
                            try:
                                if child.pid and hasattr(os, "killpg") and os.getpgid(child.pid) == child.pid:
                                    os.killpg(child.pid, signal.SIGKILL)
                                else:
                                    child.kill()
                            except ProcessLookupError:
                                pass
                            child.join()
                    directory = attempt / "runs" / job["id"]
                    if not error and child.exitcode:
                        error = f"analysis process failed (exit {child.exitcode})"
                    body = lease | {"error": error}
                    if not error:
                        evidence = [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]
                        findings = json.loads((directory / "findings.json").read_text())
                        body.update(evidence=evidence, isolated=findings["isolated"])
                    post(f"/api/worker/{job['id']}/result", body)
            if once:
                return
            if not job:
                time.sleep(2)
