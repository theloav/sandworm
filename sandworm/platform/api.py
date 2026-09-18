"""Workspace-scoped REST API with password sessions and scoped service keys."""

from __future__ import annotations

import hmac
import json
import time
import uuid
from importlib.resources import files
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..core.evidence import EvidenceStore
from ..core.sample import Sample, SampleStore
from ..reconstruct.graph import build_graph
from .store import ROLES, PlatformStore
from .worker import job_config


class Login(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024)


class UserInput(Login):
    role: Literal["viewer", "analyst", "admin", "worker"] = "analyst"


class Lease(BaseModel):
    lease: str = Field(min_length=48, max_length=48, pattern="^[a-f0-9]+$")


class WorkerResult(Lease):
    evidence: list[dict] = Field(default_factory=list, max_length=50000)
    error: str = Field(default="", max_length=2000)
    isolated: bool = False


class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class ScheduleInput(BaseModel):
    interval_seconds: int = Field(ge=300, le=31536000)


def create_app(root: str | Path | None = None, *, secure_cookies: bool = True) -> FastAPI:
    from ..core.config import Config
    store = PlatformStore(root or Config().work_dir / "platform")
    app = FastAPI(title="Sandworm", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store

    @app.middleware("http")
    async def headers(request: Request, call_next):
        # Bound JSON requests before FastAPI parses them; uploads are streamed
        # and capped separately. The receive wrapper also covers chunked bodies.
        if request.method in {"POST", "PUT", "PATCH"} and request.url.path != "/api/jobs":
            cap = 32 * 1024**2 if request.url.path.endswith("/result") else 65536
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > cap:
                    return JSONResponse({"detail": "request body exceeds limit"}, status_code=413)
                body.extend(chunk)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        return response

    def principal(request: Request) -> dict:
        auth = request.headers.get("Authorization", "")
        kind = "key" if auth.startswith("Bearer ") else "session"
        token = auth[7:] if kind == "key" else request.cookies.get("sandworm_session", "")
        who = store.authenticate(token, kind)
        if who is None:
            raise HTTPException(401, "authentication required")
        if not store.rate("api:" + who["id"], 240):
            raise HTTPException(429, "request limit exceeded")
        if kind == "session" and request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), who["csrf"]):
                raise HTTPException(403, "CSRF token required")
        return who

    def require(who: dict, role: str) -> None:
        if ROLES[who["role"]] < ROLES[role]:
            raise HTTPException(403, f"{role} role required")

    def job_for(jid: str, who: dict) -> dict:
        job = store.job(jid, who["workspace"])
        if job is None:
            raise HTTPException(404, "job not found")
        return job

    def output(jid: str, who: dict) -> Path:
        job = job_for(jid, who)
        if job["status"] != "completed":
            raise HTTPException(409, "job has no completed result")
        attempt = job["result"].get("attempt", "")
        if len(attempt) != 48 or any(c not in "0123456789abcdef" for c in attempt):
            raise HTTPException(409, "invalid result reference")
        return store.job_dir(jid) / "attempts" / attempt / "runs" / jid

    @app.get("/", response_class=HTMLResponse)
    def index():
        return files("sandworm.platform").joinpath("static/index.html").read_text()

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in {"app.js", "app.css"}:
            raise HTTPException(404)
        return Response(files("sandworm.platform").joinpath("static/" + name).read_text(),
                        media_type="text/javascript" if name.endswith("js") else "text/css")

    @app.get("/healthz")
    def health():
        with store.connect() as db:
            db.execute("SELECT 1")
        return {"status": "ok", "version": "0.2.0"}

    @app.post("/api/login")
    def login(data: Login, request: Request, response: Response):
        client = request.client.host if request.client else "unknown"
        if not store.rate("login:" + client, 10):
            raise HTTPException(429, "login limit exceeded")
        pair = store.login(data.username, data.password)
        if pair is None:
            raise HTTPException(401, "invalid credentials")
        token, csrf = pair
        response.set_cookie("sandworm_session", token, httponly=True, secure=secure_cookies, samesite="strict", max_age=28800)
        return {"csrf": csrf}

    @app.post("/api/logout")
    def logout(response: Response, who=Depends(principal)):
        store.revoke(who["credential_id"], who["id"])
        response.delete_cookie("sandworm_session")
        return {"ok": True}

    @app.get("/api/me")
    def me(who=Depends(principal)):
        return who

    @app.get("/api/openapi.json")
    def schema(who=Depends(principal)):
        return JSONResponse(app.openapi())

    @app.get("/api/profiles")
    def profiles(who=Depends(principal)):
        from ..sandbox.profiles import available_profiles
        return {name: {"backend": row["backend"]} for name, row in available_profiles().items()}

    @app.post("/api/users", status_code=201)
    def user(data: UserInput, who=Depends(principal)):
        require(who, "admin")
        try:
            uid = store.create_user(data.username, data.password, who["workspace"], data.role)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(409, "could not create user") from exc
        return {"id": uid}

    @app.post("/api/keys", status_code=201)
    def key(who=Depends(principal)):
        token, _ = store.issue(who["id"])
        store.event(who["workspace"], who["id"], "key_issued", who["id"])
        return {"key": token, "expires_in": 86400 * 30}

    @app.post("/api/keys/{kid}/rotate")
    def rotate(kid: str, who=Depends(principal)):
        with store.connect() as db:
            old = db.execute("SELECT id FROM credentials WHERE id=? AND user_id=? AND kind='key' AND revoked=0", (kid, who["id"])).fetchone()
        if not old:
            raise HTTPException(404, "active key not found")
        token, _ = store.issue(who["id"])
        store.revoke(kid, who["id"])
        return {"key": token, "expires_in": 86400 * 30}

    @app.get("/api/users")
    def users(who=Depends(principal)):
        require(who, "admin")
        with store.connect() as db:
            return [dict(r) for r in db.execute("SELECT id,username,role,active FROM users WHERE workspace=?", (who["workspace"],))]

    @app.delete("/api/users/{uid}")
    def disable(uid: str, who=Depends(principal)):
        require(who, "admin")
        if uid == who["id"]:
            raise HTTPException(400, "cannot disable your own account")
        with store.connect() as db:
            db.execute("UPDATE users SET active=0 WHERE id=? AND workspace=?", (uid, who["workspace"]))
        store.event(who["workspace"], who["id"], "user_disabled", uid)
        return {"ok": True}

    @app.get("/api/keys")
    def keys(who=Depends(principal)):
        with store.connect() as db:
            return [dict(r) for r in db.execute("SELECT id,expires,revoked FROM credentials WHERE user_id=? AND kind='key'", (who["id"],))]

    @app.delete("/api/keys/{kid}")
    def revoke(kid: str, who=Depends(principal)):
        store.revoke(kid, who["id"])
        return {"ok": True}

    @app.get("/api/jobs")
    def jobs(q: str = "", offset: int = 0, who=Depends(principal)):
        return store.jobs(who["workspace"], q[:256], offset=max(offset, 0))

    @app.post("/api/jobs", status_code=202)
    async def submit(request: Request, name: str = "sample.bin", profile: str = "static",
                     delay: int = 0, who=Depends(principal)):
        require(who, "analyst")
        from ..sandbox.profiles import available_profiles
        if profile not in available_profiles() or not 0 <= delay <= 86400 * 30:
            raise HTTPException(400, "invalid profile or schedule")
        if not store.rate("submit:" + who["id"], 20):
            raise HTTPException(429, "submission limit exceeded")
        jid = uuid.uuid4().hex
        cfg = job_config(store, jid)
        cap = min(cfg.max_sample_bytes or 32 * 1024**2, 32 * 1024**2)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > cap:
                raise HTTPException(413, "sample exceeds upload limit")
            data.extend(chunk)
        if not data:
            raise HTTPException(400, "empty sample")
        name = name.replace("\\", "/").rsplit("/", 1)[-1][:200]
        name = "".join(c for c in name if c.isprintable()) or "sample.bin"
        sample = Sample.from_bytes(name, bytes(data))
        try:
            SampleStore(cfg).store(sample)
        except Exception as exc:
            raise HTTPException(503, "encrypted sample storage unavailable") from exc
        return store.enqueue(workspace=who["workspace"], owner=who["id"], name=name,
                             sha256=sample.sha256, options={"profile": profile}, job_id=jid, due=time.time() + delay)

    @app.get("/api/jobs/{jid}")
    def job(jid: str, who=Depends(principal)):
        return job_for(jid, who)

    @app.post("/api/jobs/{jid}/cancel")
    def cancel(jid: str, who=Depends(principal)):
        require(who, "analyst")
        job_for(jid, who)
        return {"cancelled": store.cancel(jid, who["workspace"], who["id"])}

    @app.post("/api/jobs/{jid}/schedule", status_code=201)
    def schedule(jid: str, data: ScheduleInput, who=Depends(principal)):
        require(who, "analyst")
        job_for(jid, who)
        return {"id": store.schedule(jid, who["workspace"], who["id"], data.interval_seconds)}

    @app.get("/api/schedules")
    def schedules(who=Depends(principal)):
        with store.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM schedules WHERE workspace=?", (who["workspace"],))]

    @app.delete("/api/schedules/{sid}")
    def unschedule(sid: str, who=Depends(principal)):
        require(who, "analyst")
        with store.connect() as db:
            db.execute("UPDATE schedules SET enabled=0 WHERE id=? AND workspace=?", (sid, who["workspace"]))
        return {"ok": True}

    @app.get("/api/jobs/{jid}/evidence")
    def evidence(jid: str, q: str = "", offset: int = 0, who=Depends(principal)):
        items = EvidenceStore.load(str(output(jid, who) / "evidence.jsonl"))
        rows = [e.model_dump() | {"id": e.id} for e in items if q.lower() in e.model_dump_json().lower()]
        return {"total": len(rows), "items": rows[max(0, offset):max(0, offset) + 100]}

    @app.get("/api/jobs/{jid}/graph")
    def graph(jid: str, who=Depends(principal)):
        from ..graphdb.client import InMemoryGraph
        g = build_graph(EvidenceStore.load(str(output(jid, who) / "evidence.jsonl")), graph=InMemoryGraph())
        from dataclasses import asdict
        return {"nodes": [asdict(n) for n in g.nodes.values()], "edges": [asdict(e) for e in g.edges]}

    @app.get("/api/jobs/{jid}/download/{kind}")
    def download(jid: str, kind: str, who=Depends(principal)):
        allowed = {"html": "report.html", "json": "findings.json", "jsonl": "evidence.jsonl"}
        if kind not in allowed:
            raise HTTPException(404)
        # Attachment avoids rendering sample-derived HTML in the application origin.
        return FileResponse(output(jid, who) / allowed[kind], filename=allowed[kind], media_type="application/octet-stream")

    @app.post("/api/jobs/{jid}/ask")
    def ask(jid: str, data: Question, who=Depends(principal)):
        from dataclasses import asdict

        from ..copilot.graphrag import ask as answer
        from ..graphdb.client import InMemoryGraph
        g = build_graph(EvidenceStore.load(str(output(jid, who) / "evidence.jsonl")), graph=InMemoryGraph())
        return asdict(answer(g, data.question))

    @app.get("/api/jobs/{jid}/export/{kind}")
    def export(jid: str, kind: str, who=Depends(principal)):
        from ..reconstruct.attack_map import map_evidence
        from ..reporting.export import (
            ioc_csv,
            misp_event,
            navigator_layer,
            openioc_xml,
            stix_bundle,
        )
        job = job_for(jid, who)
        items = EvidenceStore.load(str(output(jid, who) / "evidence.jsonl"))
        mappings = map_evidence(items)
        kw = {"sha256": job["sha256"], "name": job["name"]}
        if kind == "stix":
            data, ext = json.dumps(stix_bundle(items, mappings, **kw)), "json"
        elif kind == "misp":
            data, ext = json.dumps(misp_event(items, mappings, **kw)), "json"
        elif kind == "navigator":
            data, ext = json.dumps(navigator_layer(mappings, **kw)), "json"
        elif kind == "openioc":
            data, ext = openioc_xml(items, **kw), "xml"
        elif kind == "csv":
            data, ext = ioc_csv(items, **kw), "csv"
        else:
            raise HTTPException(404)
        return Response(data, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{kind}.{ext}"'})

    @app.get("/api/events")
    def events(who=Depends(principal)):
        require(who, "admin")
        with store.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM events WHERE workspace=? ORDER BY id DESC LIMIT 200", (who["workspace"],))]

    @app.get("/api/metrics")
    def metrics(who=Depends(principal)):
        with store.connect() as db:
            counts = {r["status"]: r["n"] for r in db.execute("SELECT status,count(*) n FROM jobs WHERE workspace=? GROUP BY status", (who["workspace"],))}
            workers = db.execute("SELECT count(DISTINCT worker) FROM jobs WHERE workspace=? AND status='running' AND heartbeat>?", (who["workspace"], time.time() - 90)).fetchone()[0]
        return {"jobs": counts, "active_workers": workers}

    def worker_lease(jid: str, token: str, who: dict) -> dict:
        if who["role"] != "worker":
            raise HTTPException(403, "worker role required")
        job = job_for(jid, who)
        if job["worker"] != "remote:" + who["id"] or store.heartbeat(jid, token) not in {"running", "cancelling"}:
            raise HTTPException(409, "worker lease lost")
        return job

    @app.post("/api/worker/claim")
    def claim(who=Depends(principal)):
        if who["role"] != "worker":
            raise HTTPException(403, "worker role required")
        return store.claim("remote:" + who["id"], workspace=who["workspace"])

    @app.post("/api/worker/{jid}/heartbeat")
    def heartbeat(jid: str, data: Lease, who=Depends(principal)):
        worker_lease(jid, data.lease, who)
        return {"status": store.heartbeat(jid, data.lease)}

    @app.post("/api/worker/{jid}/sample")
    def worker_sample(jid: str, data: Lease, who=Depends(principal)):
        job = worker_lease(jid, data.lease, who)
        sample = SampleStore(job_config(store, jid)).load(job["sha256"], job["name"])
        return Response(sample.data, media_type="application/octet-stream")

    @app.post("/api/worker/{jid}/result")
    def worker_result(jid: str, data: WorkerResult, who=Depends(principal)):
        from dataclasses import replace

        from ..core.evidence import EvidenceItem
        from ..core.pipeline import RunResult, build_report_inputs, persist_run
        from ..core.triage import identify
        from ..detect.sigma_gen import generate_sigma
        from ..detect.yara_gen import generate_yara
        from ..graphdb.client import InMemoryGraph
        from ..reconstruct.attack_map import map_evidence
        from ..reconstruct.narrative import build_narrative
        from ..reconstruct.timeline import build_timeline
        from ..reporting.coverage import compute_coverage
        from ..reporting.export import findings_json
        from ..reporting.report import write_report
        from ..reporting.summary import build_summary

        job = worker_lease(jid, data.lease, who)
        if data.error:
            store.finish(jid, data.lease, error=data.error)
            return {"ok": True}
        sample = SampleStore(job_config(store, jid)).load(job["sha256"], job["name"])
        evidence_store = EvidenceStore()
        for row in data.evidence:
            item = EvidenceItem.model_validate(row)
            if item.run_id != jid:
                raise HTTPException(400, "evidence belongs to another run")
            evidence_store.append(item)
        mappings = map_evidence(evidence_store)
        phases = build_narrative(mappings)
        yara, sigma = generate_yara(evidence_store, sample), generate_sigma(evidence_store, mappings)
        result = RunResult(jid, sample, identify(sample.data, sample.name), data.isolated, evidence_store,
                           mappings, phases, build_timeline(evidence_store), yara, sigma,
                           compute_coverage(mappings, sigma, yara), graph=build_graph(evidence_store, mappings, graph=InMemoryGraph()),
                           execution_mode="sandbox" if data.isolated else "static", sandbox_backend="remote-worker")
        attempt = store.job_dir(jid) / "attempts" / data.lease
        cfg = replace(job_config(store, jid), work_dir=attempt)
        directory = persist_run(result, cfg)
        write_report(build_report_inputs(result), directory / "report.html")
        summary = build_summary(evidence_store, mappings, phases, isolated=data.isolated)
        findings = findings_json(result, summary)
        (directory / "findings.json").write_text(json.dumps(findings))
        if not store.finish(jid, data.lease, result=findings | {"attempt": data.lease}):
            raise HTTPException(409, "worker lease lost")
        store.event(who["workspace"], who["id"], "remote_result", jid)
        return {"ok": True}

    return app
