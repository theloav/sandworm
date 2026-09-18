"""Service authentication, tenant boundaries, durable leases and real worker flow."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyzipper")
from fastapi.testclient import TestClient

from sandworm.platform.api import create_app
from sandworm.platform.store import PlatformStore
from sandworm.platform.worker import run_once


@pytest.fixture
def service(tmp_path):
    app = create_app(tmp_path / "platform", secure_cookies=False)
    store = app.state.store
    admin = store.create_user("admin", "sufficiently-long-password", "alpha", "admin")
    viewer = store.create_user("viewer", "sufficiently-long-password", "alpha", "viewer")
    other = store.create_user("other", "sufficiently-long-password", "beta", "admin")
    keys = {"admin": store.issue(admin)[0], "viewer": store.issue(viewer)[0], "other": store.issue(other)[0]}
    with TestClient(app) as client:
        yield client, store, keys


def auth(key):
    return {"Authorization": "Bearer " + key}


def test_authentication_csrf_revocation_and_workspace_boundaries(service):
    client, store, keys = service
    assert client.get("/api/jobs").status_code == 401
    logged = client.post("/api/login", json={"username": "admin", "password": "sufficiently-long-password"})
    assert logged.status_code == 200
    assert "httponly" in logged.headers["set-cookie"].lower()
    assert client.post("/api/keys").status_code == 403
    csrf = {"X-CSRF-Token": logged.json()["csrf"]}
    assert client.post("/api/keys", headers=csrf).status_code == 201
    client.cookies.clear()
    denied = client.post("/api/jobs?name=demo.php", content=b"<?php echo 'hello';", headers=auth(keys["viewer"]))
    assert denied.status_code == 403
    job = client.post("/api/jobs?name=demo.php", content=b"<?php echo 'hello';", headers=auth(keys["admin"])).json()
    assert client.get(f"/api/jobs/{job['id']}", headers=auth(keys["other"])).status_code == 404
    assert client.post(f"/api/jobs/{job['id']}/cancel", headers=auth(keys["other"])).status_code == 404
    assert client.get("/api/jobs", headers=auth(keys["other"])).json() == []
    who = store.authenticate(keys["admin"], "key")
    store.revoke(who["credential_id"], who["id"])
    assert client.get("/api/jobs", headers=auth(keys["admin"])).status_code == 401
    assert keys["admin"].encode() not in store.path.read_bytes()


def test_worker_submission_to_reports_and_graph(service):
    client, store, keys = service
    headers = auth(keys["admin"])
    response = client.post("/api/jobs?name=demo.php", content=b"<?php system($_GET['c']); ?>", headers=headers)
    assert response.status_code == 202, response.text
    jid = response.json()["id"]
    assert run_once(store, poll=0.05)
    job = client.get(f"/api/jobs/{jid}", headers=headers).json()
    assert job["status"] == "completed", job
    for kind in ("html", "json", "jsonl"):
        result = client.get(f"/api/jobs/{jid}/download/{kind}", headers=headers)
        assert result.status_code == 200
        assert "attachment" in result.headers["content-disposition"]
        assert result.content
    assert client.get(f"/api/jobs/{jid}/graph", headers=headers).json()["nodes"]
    assert client.get(f"/api/jobs/{jid}/evidence", headers=headers).json()["total"] > 0
    answer = client.post(f"/api/jobs/{jid}/ask", headers=headers, json={"question": "execution sinks"})
    assert answer.status_code == 200, answer.text
    assert answer.json()["citations"]


def test_claim_is_atomic_and_fenced(tmp_path):
    store = PlatformStore(tmp_path)
    jid = store.enqueue(workspace="w", owner="a", name="x", sha256="a" * 64, options={})["id"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda i: store.claim(str(i)), range(4)))
    first = next(c for c in claims if c)
    assert sum(c is not None for c in claims) == 1
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=? WHERE id=?", (time.time() - 1000, jid))
    second = store.claim("replacement")
    assert second and second["lease"] != first["lease"]
    assert not store.finish(jid, first["lease"], result={"stale": True})
    assert store.cancel(jid, "w", "a")
    assert store.heartbeat(jid, second["lease"]) == "cancelling"
    store.finish(jid, second["lease"], result={"ignored": True})
    assert store.job(jid, "w")["status"] == "cancelled"


def test_scheduled_jobs_and_path_validation(tmp_path):
    store = PlatformStore(tmp_path)
    store.enqueue(workspace="w", owner="a", name="x", sha256="a" * 64, options={}, due=time.time() + 3600)
    assert store.claim("worker") is None
    with pytest.raises(ValueError):
        store.job_dir("../escape")
    with pytest.raises(ValueError):
        store.create_user("weak", "short", "w")


def test_recurring_schedule_and_retention_protect_source(service):
    client, store, keys = service
    headers = auth(keys["admin"])
    jid = client.post("/api/jobs?name=x.txt", content=b"benign scheduled fixture", headers=headers).json()["id"]
    assert client.post(f"/api/jobs/{jid}/schedule", headers=headers, json={"interval_seconds": 3600}).status_code == 201
    with store.connect() as db:
        db.execute("UPDATE schedules SET next_due=?", (time.time() - 7200,))
    store.tick_schedules()
    jobs = store.jobs("alpha")
    assert len(jobs) == 2
    assert len(list((store.job_dir(jobs[0]["id"]) / "samples").glob("*.zip"))) == 1
    store.tick_schedules()
    assert len(store.jobs("alpha")) == 2
    sid = client.get("/api/schedules", headers=headers).json()[0]["id"]
    assert client.delete(f"/api/schedules/{sid}", headers=auth(keys["other"])).status_code == 200
    assert client.get("/api/schedules", headers=headers).json()[0]["enabled"] == 1


def test_remote_worker_roundtrip(service):
    client, store, keys = service
    uid = store.create_user("remote", "long-remote-password", "alpha", "worker")
    token = store.issue(uid)[0]
    jid = client.post("/api/jobs?name=remote.php", content=b"<?php echo 'hello'; ?>", headers=auth(keys["admin"])).json()["id"]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "SANDWORM_WORK_DIR": str(store.root.parent), "SANDWORM_WORKER_KEY": token}
    server = subprocess.Popen([sys.executable, "-m", "sandworm.cli", "serve", "--local-http", "--port", str(port)], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(url + "/healthz", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        result = subprocess.run([sys.executable, "-m", "sandworm.cli", "worker", "--url", url, "--local-http", "--once"], env=env,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert store.job(jid, "alpha")["status"] == "completed"
        assert client.get(f"/api/jobs/{jid}/download/html", headers=auth(keys["admin"])).status_code == 200
        assert client.post("/api/worker/claim", headers=auth(keys["admin"])).status_code == 403
    finally:
        server.terminate()
        server.wait(10)


def test_oversized_json_rejected_before_model_parsing(service):
    client, _, _ = service
    assert client.post("/api/login", content=b"x" * 65537, headers={"Content-Type": "application/json"}).status_code == 413
