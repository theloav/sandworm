"""Plugin discovery and per-format dispatch.

The registry knows which analyzers exist and which format tags each claims.
Built-in analyzers register at import time; external plugins are discovered by
scanning a directory for modules that expose a top-level ``ANALYZER`` (an
instance) or a ``register(registry)`` hook — no core changes required to add one.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from .base import Analyzer


class AnalyzerRegistry:
    def __init__(self) -> None:
        self._analyzers: list[Analyzer] = []

    def register(self, analyzer: Analyzer) -> Analyzer:
        # De-dupe by name so re-import doesn't double-register.
        self._analyzers = [a for a in self._analyzers if a.name != analyzer.name]
        self._analyzers.append(analyzer)
        return analyzer

    def all(self) -> list[Analyzer]:
        return list(self._analyzers)

    def names(self) -> list[str]:
        return [a.name for a in self._analyzers]

    def for_format(self, fmt: str, *, include_dynamic: bool, isolated: bool) -> list[Analyzer]:
        """Return analyzers that claim ``fmt``.

        Static analyzers always run. Dynamic analyzers (``requires_isolation``)
        are only included when ``include_dynamic`` is requested AND ``isolated``
        is True — the gate is enforced here as a second line of defense.
        """
        out: list[Analyzer] = []
        for a in self._analyzers:
            claims = fmt in a.handles or "*" in a.handles
            if not claims:
                continue
            if a.requires_isolation and not (include_dynamic and isolated):
                continue
            out.append(a)
        return out

    def load_plugins(self, directory: str | Path) -> list[str]:
        """Import every ``*.py`` in ``directory`` and register any analyzers it
        exposes. Returns the names of newly discovered analyzers."""
        directory = Path(directory)
        loaded: list[str] = []
        if not directory.exists():
            return loaded
        for py in sorted(directory.glob("*.py")):
            if py.name.startswith("_"):
                continue
            mod_name = f"sandworm_plugin_{py.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                continue
            before = set(self.names())
            if hasattr(module, "register"):
                module.register(self)
            if hasattr(module, "ANALYZER"):
                self.register(module.ANALYZER)
            loaded.extend(n for n in self.names() if n not in before)
        return loaded


# The global registry built-in analyzers attach to at import time.
REGISTRY = AnalyzerRegistry()


def register_builtins() -> AnalyzerRegistry:
    """Import built-in analyzer modules so their classes self-register.

    Done lazily (called by triage/cli) to avoid import cycles and to let optional
    heavy backends fail gracefully without breaking registry import.
    """
    from .static import (  # noqa: F401
        common,
        decode,
        elf,
        fingerprint,
        lnk,
        office,
        pdf,
        pe,
        php,
        script,
        unpack,
    )

    for mod in (common, php, script, pe, elf, office, unpack, decode, fingerprint, lnk, pdf):
        reg = getattr(mod, "register", None)
        if reg is not None:
            reg(REGISTRY)

    # Dynamic analyzers (gated). Import defensively.
    try:
        from .dynamic import linux_sandbox, php_runtime, script_runtime, windows_cape  # noqa: F401

        for mod in (php_runtime, script_runtime, windows_cape, linux_sandbox):
            reg = getattr(mod, "register", None)
            if reg is not None:
                reg(REGISTRY)
    except Exception:
        pass
    return REGISTRY
