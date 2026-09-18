"""Optional materialized SQLite index over persisted evidence, not an execution lane.

Each database is an operator-selected security boundary. Do not combine private
workspaces and expose the database to a less privileged user.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .evidence import EvidenceItem


class CorpusIndex:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sources(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evidence(
                    source_path TEXT NOT NULL, id TEXT NOT NULL, run_id TEXT NOT NULL,
                    source TEXT NOT NULL, artifact TEXT NOT NULL, operation TEXT NOT NULL,
                    confidence REAL NOT NULL, document TEXT NOT NULL,
                    PRIMARY KEY(source_path,id));
                CREATE INDEX IF NOT EXISTS evidence_facet ON evidence(artifact,operation,run_id);
                CREATE INDEX IF NOT EXISTS evidence_run ON evidence(run_id);
                CREATE TABLE IF NOT EXISTS atoms(
                    value TEXT NOT NULL, source_path TEXT NOT NULL, id TEXT NOT NULL,
                    PRIMARY KEY(value,source_path,id));
                CREATE INDEX IF NOT EXISTS atoms_source ON atoms(source_path);
            """)
        path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, path: Path) -> bool:
        path = path.resolve(strict=True)
        # Stream a bounded line at a time. Roll back the entire source if invalid.
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            stream.seek(0)
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                old = db.execute("SELECT sha256 FROM sources WHERE path=?", (str(path),)).fetchone()
                if old and old["sha256"] == digest:
                    return False
                db.execute("DELETE FROM atoms WHERE source_path=?", (str(path),))
                db.execute("DELETE FROM evidence WHERE source_path=?", (str(path),))
                count = 0
                read_digest = hashlib.sha256()
                while line := stream.readline(1024 * 1024 + 1):
                    count += 1
                    if len(line) > 1024 * 1024 or count > 1000000:
                        raise ValueError("index source exceeds line/event limit")
                    read_digest.update(line)
                    if not line.strip():
                        continue
                    item = EvidenceItem.model_validate_json(line)
                    db.execute("INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                               (str(path), item.id, item.run_id, item.source, item.artifact, item.operation, item.confidence, item.model_dump_json()))
                    # Materialize exact scalar object values. No substring claim:
                    # query a domain as a domain, a URL as its complete value.
                    values = {str(value).casefold() for value in item.object.values() if isinstance(value, (str, int, float))}
                    db.executemany("INSERT OR IGNORE INTO atoms VALUES (?,?,?)", [(value, str(path), item.id) for value in values])
                if read_digest.hexdigest() != digest:
                    raise ValueError("source changed during indexing")
                db.execute("INSERT OR REPLACE INTO sources VALUES (?,?)", (str(path), digest))
        return True

    def search(self, *, value: str | None = None, artifact: str | None = None,
               operation: str | None = None, run_id: str | None = None, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 1000 or not any((value, artifact, operation, run_id)):
            raise ValueError("provide a filter and limit in [1,1000]")
        conditions, parameters = [], []
        join = ""
        if value is not None:
            join = " JOIN atoms a ON a.source_path=e.source_path AND a.id=e.id"
            conditions.append("a.value=?")
            parameters.append(value.casefold())
        for column, argument in (("artifact", artifact), ("operation", operation), ("run_id", run_id)):
            if argument is not None:
                conditions.append(f"e.{column}=?")
                parameters.append(argument)
        query = "SELECT e.document,e.source_path FROM evidence e" + join + " WHERE " + " AND ".join(conditions) + " LIMIT ?"
        with self.connect() as db:
            return [{"evidence": json.loads(row["document"]), "source_path": row["source_path"]}
                    for row in db.execute(query, [*parameters, limit])]
