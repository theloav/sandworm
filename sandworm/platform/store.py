"""Transactional local deployment store. SQLite is shared by API/worker processes.

Use a local filesystem, not NFS. Claims use BEGIN IMMEDIATE and fencing tokens;
an expired worker cannot publish over a newer attempt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import shutil
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROLES = {"worker": 0, "viewer": 0, "analyst": 1, "admin": 2}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


class PlatformStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "platform.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, workspace TEXT NOT NULL,
                    role TEXT NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
                    kind TEXT NOT NULL, expires REAL NOT NULL, csrf TEXT NOT NULL DEFAULT '', revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, workspace TEXT NOT NULL, owner TEXT NOT NULL, name TEXT NOT NULL,
                    sha256 TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    due REAL NOT NULL, options TEXT NOT NULL, worker TEXT, lease TEXT, heartbeat REAL,
                    attempts INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}');
                CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,due);
                CREATE INDEX IF NOT EXISTS jobs_workspace ON jobs(workspace,created);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, workspace TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL, ts REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS rates (key TEXT PRIMARY KEY, bucket INTEGER NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY, workspace TEXT NOT NULL, owner TEXT NOT NULL,
                    source_job TEXT NOT NULL REFERENCES jobs(id), interval_seconds INTEGER NOT NULL,
                    next_due REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def event(self, workspace: str, actor: str, action: str, target: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO events(workspace,actor,action,target,ts) VALUES (?,?,?,?,?)",
                       (workspace, actor, action, target, time.time()))

    def create_user(self, username: str, password: str, workspace: str, role: str = "analyst") -> str:
        if role not in ROLES or not username.strip() or not workspace.strip():
            raise ValueError("username, workspace and a valid role are required")
        if len(password) < 12 or len(password) > 1024:
            raise ValueError("password must contain 12–1024 characters")
        uid, salt = uuid.uuid4().hex, secrets.token_hex(16)
        with self.connect() as db:
            db.execute("INSERT INTO users(id,username,workspace,role,salt,password) VALUES (?,?,?,?,?,?)",
                       (uid, username, workspace, role, salt, password_hash(password, salt)))
        self.event(workspace, uid, "user_created", uid)
        return uid

    def issue(self, uid: str, *, kind: str = "key", lifetime: int = 86400 * 30) -> tuple[str, str]:
        if kind not in {"key", "session"} or not 1 <= lifetime <= 86400 * 365:
            raise ValueError("invalid credential lifetime or kind")
        token = "sw_" + secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24) if kind == "session" else ""
        with self.connect() as db:
            db.execute("INSERT INTO credentials(id,hash,user_id,kind,expires,csrf) VALUES (?,?,?,?,?,?)",
                       (uuid.uuid4().hex, digest(token), uid, kind, time.time() + lifetime, csrf))
        return token, csrf

    def login(self, username: str, password: str) -> tuple[str, str] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        # Pay the password hash cost for unknown users too.
        salt = row["salt"] if row else "00" * 16
        candidate = password_hash(password[:1024], salt)
        if not row or not hmac.compare_digest(candidate, row["password"]):
            return None
        return self.issue(row["id"], kind="session", lifetime=28800)

    def authenticate(self, token: str, kind: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("""SELECT u.id,u.username,u.workspace,u.role,c.csrf,c.id AS credential_id
                FROM credentials c JOIN users u ON u.id=c.user_id
                WHERE c.hash=? AND c.kind=? AND c.revoked=0 AND c.expires>? AND u.active=1""",
                             (digest(token), kind, time.time())).fetchone()
        return dict(row) if row else None

    def revoke(self, credential_id: str, uid: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE credentials SET revoked=1 WHERE id=? AND user_id=?", (credential_id, uid))

    def rate(self, key: str, limit: int, window: int = 60) -> bool:
        bucket = int(time.time()) // window
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM rates WHERE bucket<?", (bucket - 2,))
            row = db.execute("SELECT * FROM rates WHERE key=?", (key,)).fetchone()
            count = row["count"] + 1 if row and row["bucket"] == bucket else 1
            db.execute("INSERT OR REPLACE INTO rates VALUES (?,?,?)", (key, bucket, count))
        return count <= limit

    def enqueue(self, *, workspace: str, owner: str, name: str, sha256: str,
                options: dict, job_id: str | None = None, due: float | None = None) -> dict:
        jid, now = job_id or uuid.uuid4().hex, time.time()
        with self.connect() as db:
            db.execute("""INSERT INTO jobs(id,workspace,owner,name,sha256,status,created,updated,due,options)
                VALUES (?,?,?,?,?,'queued',?,?,?,?)""",
                       (jid, workspace, owner, name, sha256, now, now, due or now, json.dumps(options)))
        self.event(workspace, owner, "submitted", jid)
        return self.job(jid, workspace) or {}

    def job_dir(self, jid: str) -> Path:
        if len(jid) != 32 or any(c not in "0123456789abcdef" for c in jid):
            raise ValueError("invalid job id")
        path = self.root / "jobs" / jid
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise ValueError("invalid job directory")
        return path

    @staticmethod
    def public(row) -> dict:
        result = dict(row)
        for key in ("options", "result"):
            result[key] = json.loads(result[key])
        result.pop("lease", None)
        return result

    def job(self, jid: str, workspace: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND workspace=?", (jid, workspace)).fetchone()
        return self.public(row) if row else None

    def jobs(self, workspace: str, query: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM jobs WHERE workspace=? AND (name LIKE ? OR sha256 LIKE ?)
                ORDER BY created DESC LIMIT ? OFFSET ?""", (workspace, f"%{query}%", f"%{query}%", limit, offset)).fetchall()
        return [self.public(row) for row in rows]

    def cancel(self, jid: str, workspace: str, actor: str) -> bool:
        with self.connect() as db:
            n = db.execute("""UPDATE jobs SET status=CASE WHEN status='running' THEN 'cancelling' ELSE 'cancelled' END,
                updated=? WHERE id=? AND workspace=? AND status IN ('queued','running')""",
                           (time.time(), jid, workspace)).rowcount
        if n:
            self.event(workspace, actor, "cancel_requested", jid)
        return bool(n)

    def claim(self, worker: str, stale_seconds: int = 90, workspace: str | None = None) -> dict | None:
        self.tick_schedules()
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""UPDATE jobs SET status=CASE WHEN status='cancelling' THEN 'cancelled'
                WHEN attempts>=3 THEN 'failed' ELSE 'queued' END, error='worker lease expired',updated=?
                WHERE status IN ('running','cancelling') AND heartbeat<?""", (now, now - stale_seconds))
            row = db.execute("SELECT * FROM jobs WHERE status='queued' AND due<=? AND (? IS NULL OR workspace=?) ORDER BY due LIMIT 1", (now, workspace, workspace)).fetchone()
            if not row:
                return None
            lease = secrets.token_hex(24)
            db.execute("""UPDATE jobs SET status='running',worker=?,lease=?,heartbeat=?,updated=?,attempts=attempts+1
                WHERE id=?""", (worker, lease, now, now, row["id"]))
            claimed = dict(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())
        claimed["options"] = json.loads(claimed["options"])
        return claimed

    def schedule(self, jid: str, workspace: str, owner: str, interval: int) -> str:
        if not 300 <= interval <= 86400 * 365 or self.job(jid, workspace) is None:
            raise ValueError("schedule requires an existing job and interval of 300–31536000 seconds")
        if not (self.job_dir(jid) / "samples").is_dir():
            raise ValueError("source sample no longer available")
        sid = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO schedules(id,workspace,owner,source_job,interval_seconds,next_due) VALUES (?,?,?,?,?,?)",
                       (sid, workspace, owner, jid, interval, time.time() + interval))
        self.event(workspace, owner, "schedule_created", sid)
        return sid

    def tick_schedules(self) -> None:
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM schedules WHERE enabled=1 AND next_due<=? LIMIT 100", (now,)).fetchall()
            for schedule in rows:
                source = db.execute("SELECT * FROM jobs WHERE id=?", (schedule["source_job"],)).fetchone()
                archive = self.job_dir(source["id"]) / "samples" / (source["sha256"] + ".zip")
                if not archive.is_file():
                    db.execute("UPDATE schedules SET enabled=0 WHERE id=?", (schedule["id"],))
                    continue
                jid = uuid.uuid4().hex
                target = self.job_dir(jid) / "samples"
                target.mkdir(parents=True, mode=0o700)
                shutil.copyfile(archive, target / archive.name)
                db.execute("""INSERT INTO jobs(id,workspace,owner,name,sha256,status,created,updated,due,options)
                    VALUES (?,?,?,?,?,'queued',?,?,?,?)""", (jid, source["workspace"], schedule["owner"], source["name"], source["sha256"], now, now, now, source["options"]))
                # Missed intervals coalesce into one run; no unbounded catch-up.
                db.execute("UPDATE schedules SET next_due=? WHERE id=?", (now + schedule["interval_seconds"], schedule["id"]))

    def heartbeat(self, jid: str, lease: str) -> str | None:
        with self.connect() as db:
            db.execute("UPDATE jobs SET heartbeat=? WHERE id=? AND lease=?", (time.time(), jid, lease))
            row = db.execute("SELECT status FROM jobs WHERE id=? AND lease=?", (jid, lease)).fetchone()
        return row["status"] if row else None

    def finish(self, jid: str, lease: str, *, result: dict | None = None, error: str = "") -> bool:
        with self.connect() as db:
            n = db.execute("""UPDATE jobs SET status=CASE WHEN status='cancelling' THEN 'cancelled' ELSE ? END,
                updated=?,result=?,error=? WHERE id=? AND lease=? AND status IN ('running','cancelling')""",
                           ("failed" if error else "completed", time.time(), json.dumps(result or {}), error[:2000], jid, lease)).rowcount
        return bool(n)
