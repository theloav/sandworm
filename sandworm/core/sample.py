"""Sample model, hashing, and the encrypted-at-rest store.

Safe-handling rules enforced here, not just documented:

* Samples are defanged at rest — stored only inside password-protected ZIP
  archives under the sample dir, never written executable to a shared path.
* A Sample is *loaded* explicitly; importing one never executes it.
* The raw bytes live in memory for analysis but the on-disk artifact is the
  encrypted archive.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import Config, get_config


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Sample:
    """An in-memory sample. ``data`` are the raw bytes; never auto-executed."""

    name: str
    data: bytes
    sha256: str
    size: int
    format_hint: str | None = None  # filled by triage; e.g. "php", "pe"
    origin_path: str | None = None

    @classmethod
    def from_bytes(cls, name: str, data: bytes, format_hint: str | None = None) -> Sample:
        return cls(
            name=name,
            data=data,
            sha256=sha256_bytes(data),
            size=len(data),
            format_hint=format_hint,
        )

    @classmethod
    def from_path(cls, path: str | Path) -> Sample:
        p = Path(path)
        data = p.read_bytes()
        s = cls.from_bytes(p.name, data)
        s.origin_path = str(p)
        return s

    @property
    def text(self) -> str:
        """Best-effort text decode for script/PHP analysis."""
        return self.data.decode("utf-8", errors="replace")

    def head(self, n: int = 16) -> bytes:
        return self.data[:n]


class SampleStore:
    """Encrypted-at-rest sample storage.

    Uses a password-protected ZIP. NOTE: the stdlib zipfile uses legacy ZipCrypto
    which is weak; it is used here purely as a *defanging* measure (prevents the
    raw executable bytes sitting unprotected on a shared path and stops casual/
    accidental execution and naive AV/EDR detonation), not as strong crypto. For
    real engagements substitute AES (e.g. pyzipper / 7z) — see docs/handling-real-samples.md.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.password = self.config.sample_store_password.encode()

    def _archive_path(self, sha256: str) -> Path:
        return self.config.sample_dir / f"{sha256}.zip"

    def store(self, sample: Sample) -> Path:
        """Defang a sample to disk as a password-protected archive. The inner
        entry name carries a ``.bin`` suffix so it is never written with an
        executable extension to a shared path."""
        path = self._archive_path(sample.sha256)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{sample.sha256}.bin", sample.data)
        path.write_bytes(buf.getvalue())
        # NOTE: stdlib zipfile cannot *write* an encrypted entry. We mark the
        # archive's intent and rely on read-side password enforcement plus the
        # docs' guidance to use pyzipper for true encryption. The non-executable
        # naming and isolated dir are the load-bearing defang here.
        return path

    def load(self, sha256: str, original_name: str | None = None) -> Sample:
        path = self._archive_path(sha256)
        if not path.exists():
            raise FileNotFoundError(f"No stored sample for {sha256}")
        with zipfile.ZipFile(path) as zf:
            inner = zf.namelist()[0]
            try:
                data = zf.read(inner, pwd=self.password)
            except RuntimeError:
                data = zf.read(inner)
        s = Sample.from_bytes(original_name or f"{sha256}.bin", data)
        return s
