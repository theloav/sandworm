"""Script analyzer: PowerShell / JavaScript / shell deobfuscation + sinks.

Mirrors the PHP lane's "peel layers, flag sinks" philosophy for interpreted
scripts. Handles the common obfuscation primitives per language and emits each
unwrap as evidence.
"""

from __future__ import annotations

import base64
import re
import urllib.parse

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

_PREVIEW = 240


def _clip(s: str, n: int = _PREVIEW) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + f"…(+{len(s) - n})"


def _try_b64(token: str) -> str | None:
    token = token.strip().strip("'\"")
    if len(token) < 8 or len(token) % 4 not in (0, 2, 3):
        # allow padding fixups
        pass
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return None
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None
    # PowerShell -enc payloads are UTF-16LE
    for enc in ("utf-16-le", "utf-8"):
        try:
            dec = raw.decode(enc)
            if sum(c.isprintable() for c in dec) > 0.8 * max(1, len(dec)):
                return dec
        except Exception:
            continue
    return None


def deobfuscate_powershell(code: str) -> list[dict]:
    layers: list[dict] = []
    # -EncodedCommand / -enc <base64>
    for m in re.finditer(r"-[Ee](?:nc(?:odedCommand)?)?\s+([A-Za-z0-9+/=]{16,})", code):
        dec = _try_b64(m.group(1))
        if dec:
            layers.append({"function": "-EncodedCommand", "before": _clip(m.group(1)), "after": _clip(dec), "after_len": len(dec)})
    # [Convert]::FromBase64String('...')
    for m in re.finditer(r"FromBase64String\(\s*['\"]([A-Za-z0-9+/=]+)['\"]", code):
        dec = _try_b64(m.group(1))
        if dec:
            layers.append({"function": "FromBase64String", "before": _clip(m.group(1)), "after": _clip(dec), "after_len": len(dec)})
    return layers


def deobfuscate_js(code: str) -> list[dict]:
    layers: list[dict] = []
    # unescape('%xx...') / decodeURIComponent
    for m in re.finditer(r"(?:unescape|decodeURIComponent)\(\s*['\"]([^'\"]+)['\"]\s*\)", code):
        try:
            dec = urllib.parse.unquote(m.group(1))
            if dec != m.group(1):
                layers.append({"function": "unescape", "before": _clip(m.group(1)), "after": _clip(dec), "after_len": len(dec)})
        except Exception:
            pass
    # atob('base64')
    for m in re.finditer(r"atob\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)", code):
        decoded = _try_b64(m.group(1))
        if decoded:
            layers.append({"function": "atob", "before": _clip(m.group(1)), "after": _clip(decoded), "after_len": len(decoded)})
    # String.fromCharCode(a,b,c,...)
    for m in re.finditer(r"String\.fromCharCode\(([\d,\sx]+)\)", code):
        try:
            nums = [int(x, 0) for x in re.split(r"\s*,\s*", m.group(1).strip()) if x.strip()]
            dec = "".join(chr(n) for n in nums)
            layers.append({"function": "fromCharCode", "before": _clip(m.group(1)), "after": _clip(dec), "after_len": len(dec)})
        except Exception:
            pass
    return layers


def deobfuscate_shell(code: str) -> list[dict]:
    layers: list[dict] = []
    # echo <base64> | base64 -d | sh
    for m in re.finditer(r"base64\s+(?:-d|--decode)", code):
        # pull a preceding quoted/echoed token
        pre = code[max(0, m.start() - 200) : m.start()]
        bm = re.search(r"([A-Za-z0-9+/=]{16,})", pre)
        if bm:
            dec = _try_b64(bm.group(1))
            if dec:
                layers.append({"function": "base64 -d", "before": _clip(bm.group(1)), "after": _clip(dec), "after_len": len(dec)})
    # eval "$(printf ...)" / xxd reverse — left as future work
    for m in re.finditer(r"\$\(\s*echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64", code):
        dec = _try_b64(m.group(1))
        if dec:
            layers.append({"function": "echo|base64", "before": _clip(m.group(1)), "after": _clip(dec), "after_len": len(dec)})
    return layers


_SCRIPT_SINKS = {
    "powershell": {
        r"\bIEX\b|Invoke-Expression": ("code_exec", "Invoke-Expression", 0.85),
        r"\bDownloadString\b|Invoke-WebRequest|Net\.WebClient": ("network", "remote_download", 0.7),
        r"Start-Process": ("process", "Start-Process", 0.6),
        r"-WindowStyle\s+Hidden|-NoProfile|-NonInteractive": ("evasion", "stealth_flags", 0.5),
    },
    "javascript": {
        r"\beval\s*\(": ("code_exec", "eval", 0.8),
        r"ActiveXObject|WScript\.Shell": ("process", "wscript_shell", 0.8),
        r"new Function\(": ("code_exec", "Function_ctor", 0.7),
    },
    "shell": {
        r"/dev/tcp/": ("network", "reverse_shell", 0.85),
        r"\b(curl|wget)\b.*\|\s*(bash|sh)\b": ("code_exec", "download_exec", 0.8),
        r"\bnc\b\s+-": ("network", "netcat", 0.6),
        r"\bchmod\s+\+x\b": ("file", "make_executable", 0.5),
        r"crontab|/etc/cron": ("persistence", "cron", 0.7),
    },
}


def find_script_sinks(code: str, lang: str) -> list[tuple[str, str, float]]:
    out = []
    for pat, (cat, name, conf) in _SCRIPT_SINKS.get(lang, {}).items():
        if re.search(pat, code, re.IGNORECASE):
            out.append((cat, name, conf))
    return out


class ScriptAnalyzer(BaseAnalyzer):
    name = "static.script"
    handles = {"script", "powershell", "javascript", "shell"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        return self.analyze_code(sample.text, sample.format_hint or "shell", sample.sha256, ctx)

    def analyze_code(self, code: str, lang: str, sha256: str, ctx: Context) -> list[EvidenceItem]:
        ref = f"sample:{sha256}"
        items: list[EvidenceItem] = []
        if lang in ("powershell",):
            layers = deobfuscate_powershell(code)
        elif lang in ("javascript",):
            layers = deobfuscate_js(code)
        else:
            layers = deobfuscate_shell(code)

        for i, layer in enumerate(layers):
            items.append(
                ctx.ev(
                    source=f"static.script.{lang}",
                    artifact="string",
                    operation="decode",
                    subject={"analyzer": self.name},
                    object={"layer": i, "function": layer["function"]},
                    details={"decoded_preview": layer["after"], "decoded_len": layer["after_len"], "source_preview": layer["before"]},
                    confidence=0.9,
                    evidence_refs=[ref, f"layer:{i}"],
                )
            )

        # scan original + decoded layers for sinks
        scanned = code + "\n" + "\n".join(layer["after"] for layer in layers)
        for cat, name, conf in find_script_sinks(scanned, lang):
            items.append(
                ctx.ev(
                    source=f"static.script.{lang}",
                    artifact="api_call" if cat in {"code_exec", "process"} else "network" if cat == "network" else "string",
                    operation="exec" if cat in {"code_exec", "process"} else "connect" if cat == "network" else "read",
                    subject={"analyzer": self.name},
                    object={"sink": name, "category": cat},
                    details={"language": lang, "note": f"{lang} sink '{name}'"},
                    confidence=conf,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(ScriptAnalyzer())
