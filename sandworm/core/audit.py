"""Append-only JSONL audit log.

Every analyzer action and every detonation (and every *refused* detonation) is
recorded here with run_id, sample hash, analyzer and action. Nothing is silently
dropped — this is the tamper-evident record of what SANDWORM did with a sample.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Config, get_config

_LOCK = threading.Lock()


class AuditLogger:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()

    def log(
        self,
        *,
        run_id: str,
        action: str,
        analyzer: str = "core",
        sample_hash: str | None = None,
        **details: Any,
    ) -> dict[str, Any]:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "run_id": run_id,
            "analyzer": analyzer,
            "action": action,
            "sample_hash": sample_hash,
            "pid": os.getpid(),
            "details": details,
        }
        path: Path = self.config.audit_path
        line = json.dumps(record, default=str)
        with _LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record

    def read_all(self) -> list[dict[str, Any]]:
        path = self.config.audit_path
        if not path.exists():
            return []
        out = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
