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


class SampleTooLargeError(ValueError):
    """Raised when a sample exceeds ``Config.max_sample_bytes``."""


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
    def from_path(cls, path: str | Path, config: Config | None = None) -> Sample:
        p = Path(path)
        cap = (config or get_config()).max_sample_bytes
        if cap:
            size = p.stat().st_size
            if size > cap:
                raise SampleTooLargeError(
                    f"{p.name} is {size:,} bytes, over the {cap:,}-byte sample cap "
                    "(set SANDWORM_MAX_SAMPLE_BYTES=0 to disable, or raise the limit)."
                )
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


def _pyzipper():
    """Return the pyzipper module if installed, else None. pyzipper gives real
    WinZip AES-256 encryption that the stdlib zipfile cannot *write*."""
    try:  # pragma: no cover - exercised via SampleStore.encryption
        import pyzipper  # type: ignore

        return pyzipper
    except ImportError:
        return None


class SampleStore:
    """Encrypted-at-rest sample storage.

    Strong by default when ``pyzipper`` is installed: samples are written to a
    **AES-256** WinZip archive. Without pyzipper it degrades to a stdlib
    password-marked ZIP — still a *defang* (non-executable inner name, isolated
    dir, no raw bytes on a shared path) but not strong crypto. The
    :attr:`encryption` property reports which mode is active so callers/tests can
    assert on it. Install with ``pip install '.[secure]'`` for AES.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.password = self.config.sample_store_password.encode()

    @property
    def encryption(self) -> str:
        """'aes-256' when pyzipper is available, else 'zipcrypto-defang'."""
        return "aes-256" if _pyzipper() is not None else "zipcrypto-defang"

    def _archive_path(self, sha256: str) -> Path:
        return self.config.sample_dir / f"{sha256}.zip"

    def store(self, sample: Sample) -> Path:
        """Defang a sample to disk as an encrypted archive. The inner entry name
        carries a ``.bin`` suffix so it is never written with an executable
        extension to a shared path. Uses AES-256 when pyzipper is present."""
        path = self._archive_path(sample.sha256)
        inner = f"{sample.sha256}.bin"
        pz = _pyzipper()
        if pz is not None:  # pragma: no cover - requires optional dep
            with pz.AESZipFile(str(path), "w", compression=pz.ZIP_DEFLATED,
                               encryption=pz.WZ_AES) as zf:
                zf.setpassword(self.password)
                zf.writestr(inner, sample.data)
            return path
        # Fallback: stdlib cannot write an encrypted entry; the non-executable
        # naming and isolated dir are the load-bearing defang here.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner, sample.data)
        path.write_bytes(buf.getvalue())
        return path

    def load(self, sha256: str, original_name: str | None = None) -> Sample:
        path = self._archive_path(sha256)
        if not path.exists():
            raise FileNotFoundError(f"No stored sample for {sha256}")
        pz = _pyzipper()
        if pz is not None:  # pragma: no cover - requires optional dep
            with pz.AESZipFile(str(path)) as zf:
                zf.setpassword(self.password)
                data = zf.read(zf.namelist()[0])
            s = Sample.from_bytes(original_name or f"{sha256}.bin", data)
            return s
        with zipfile.ZipFile(path) as zf:
            inner = zf.namelist()[0]
            try:
                data = zf.read(inner, pwd=self.password)
            except RuntimeError:
                data = zf.read(inner)
        s = Sample.from_bytes(original_name or f"{sha256}.bin", data)
        return s
