"""YARA-X audits of actual, hash-pinned files. Hash lists alone cannot be scanned."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path

from .metrics import wilson


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root: Path, *, provenance: str) -> dict:
    if not provenance.strip() or not root.is_dir():
        raise ValueError("existing corpus directory and provenance required")
    rows = []
    seen = set()
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        digest = sha256_file(path)
        if digest in seen:
            continue
        seen.add(digest)
        rows.append({"path": path.relative_to(root).as_posix(), "sha256": digest, "size": path.stat().st_size})
    if not rows:
        raise ValueError("no files in corpus")
    return {"schema_version": 1, "provenance": provenance, "files": rows,
            "label_policy": "Operator asserts benign status; inventory does not establish trustworthiness."}


def audit(rule_path: Path, manifest_path: Path, root: Path, *, timeout: int = 30) -> dict:
    import yara_x

    if timeout < 1:
        raise ValueError("timeout must be positive")
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if manifest.get("schema_version") != 1 or not manifest.get("files") or not manifest.get("provenance"):
        raise ValueError("nonempty versioned inventory with provenance required")
    source = rule_path.read_text()
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)
    compiler.add_source(source)
    rules = compiler.build()
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout)
    root = root.resolve()
    matched, errors, scanned, seen = [], [], 0, set()
    per_rule = {rule.identifier: 0 for rule in rules}
    if not per_rule:
        raise ValueError("at least one compiled rule required")
    for row in manifest["files"]:
        path = (root / row["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("corpus path escapes root")
        if row["sha256"] in seen:
            raise ValueError("duplicate corpus digest; deduplicate before measuring")
        seen.add(row["sha256"])
        try:
            if path.stat().st_size != row["size"] or sha256_file(path) != row["sha256"]:
                raise ValueError("file identity mismatch")
            result = scanner.scan_file(str(path))
            if sha256_file(path) != row["sha256"]:
                raise ValueError("file changed during scan")
            ids = [rule.identifier for rule in result.matching_rules]
            scanned += 1
            if ids:
                matched.append({"path": row["path"], "sha256": row["sha256"], "rules": ids})
                for name in ids:
                    per_rule[name] += 1
        except (OSError, ValueError, yara_x.ScanError, yara_x.TimeoutError) as exc:
            errors.append({"path": row["path"], "error": type(exc).__name__})
    return {"schema_version": 1, "engine": "yara-x", "engine_version": importlib.metadata.version("yara-x"),
            "rules_sha256": sha256_file(rule_path), "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "provenance": manifest["provenance"], "files_total": len(manifest["files"]), "files_scanned": scanned,
            "matching_files": len(matched), "observed_fp_rate": len(matched) / scanned if scanned else None,
            "wilson95": wilson(len(matched), scanned), "complete": not errors,
            "per_rule_matching_files": per_rule, "matches": matched, "errors": errors,
            "scope": "Conditional on operator benign labels and this corpus/rule set only; errors are not counted as clean files. Not a population FP guarantee."}
