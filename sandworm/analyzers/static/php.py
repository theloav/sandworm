"""PHP webshell analyzer — the differentiator.

Two jobs, done well:

1. **Recursive deobfuscation** of the classic webshell stack. We statically
   *evaluate* (never execute) nested decoder chains —
   ``eval`` / ``assert`` wrappers around ``base64_decode``, ``gzinflate``,
   ``gzuncompress``, ``gzdecode``, ``str_rot13``, ``strrev``, ``urldecode``,
   ``hex2bin``/``pack('H*',…)``, and ``chr()`` chains — peeling one layer at a
   time and emitting each layer as evidence.

2. **Dangerous-sink flagging**: ``system`` / ``exec`` / ``passthru`` /
   ``shell_exec`` / ``proc_open`` / ``popen`` and friends, ``preg_replace`` with
   the ``/e`` modifier, ``create_function``, variable-function calls
   (``$f($_GET[...])``), and superglobal-tainted input reaching a sink.

Each finding is an EvidenceItem with a confidence and the raw evidence that backs
it, so the ATT&CK mapper and detection generators can explain *why*.
"""

from __future__ import annotations

import base64
import codecs
import gzip
import re
import urllib.parse
import zlib

from ...core.evidence import EvidenceItem
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context

# --- Dangerous sinks (sink name -> (att&ck-ish intent, base confidence)) ---
COMMAND_SINKS = {
    "system": 0.9,
    "exec": 0.9,
    "passthru": 0.9,
    "shell_exec": 0.92,
    "proc_open": 0.88,
    "popen": 0.85,
    "pcntl_exec": 0.9,
}
CODE_SINKS = {
    "eval": 0.85,
    "assert": 0.8,
    "create_function": 0.8,
    "call_user_func": 0.6,
    "call_user_func_array": 0.6,
}
FILE_SINKS = {
    "file_put_contents": 0.6,
    "fwrite": 0.5,
    "fputs": 0.5,
    "move_uploaded_file": 0.7,
}
SUPERGLOBALS = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "php://input"]

_PREVIEW = 220


# --------------------------------------------------------------------------- #
# A tiny, side-effect-free evaluator for PHP decoder expressions.
# Grammar:  expr := concat ;  concat := primary ('.' primary)* ;
#           primary := STRING | NUMBER | IDENT '(' args ')' | '(' expr ')'
# Only whitelisted decoder functions are evaluated; everything else returns None.
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
  | (?P<SQSTR>'(?:\\.|[^'\\])*')
  | (?P<DQSTR>"(?:\\.|[^"\\])*")
  | (?P<NUMBER>\d+)
  | (?P<IDENT>[A-Za-z_]\w*)
  | (?P<DOT>\.)
  | (?P<LP>\()
  | (?P<RP>\))
  | (?P<COMMA>,)
  | (?P<OTHER>.)
    """,
    re.VERBOSE,
)


class _Tok:
    __slots__ = ("kind", "val", "pos")

    def __init__(self, kind: str, val: str, pos: int):
        self.kind = kind
        self.val = val
        self.pos = pos


def _lex(s: str) -> list[_Tok]:
    toks: list[_Tok] = []
    for m in _TOKEN_RE.finditer(s):
        kind = m.lastgroup or "OTHER"
        if kind == "WS":
            continue
        toks.append(_Tok(kind, m.group(), m.start()))
    return toks


def _unescape_php_string(lit: str) -> bytes:
    quote = lit[0]
    body = lit[1:-1]
    if quote == "'":
        # single-quoted: only \' and \\ are special
        return body.replace("\\'", "'").replace("\\\\", "\\").encode("latin-1", "replace")
    # double-quoted: handle common C-style escapes
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            mapping = {"n": 10, "r": 13, "t": 9, "v": 11, "f": 12, "0": 0, "\\": 92, '"': 34, "$": 36}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < len(body) + 1:
                hexd = body[i + 2 : i + 4]
                if re.fullmatch(r"[0-9a-fA-F]{1,2}", hexd):
                    out.append(int(hexd, 16))
                    i += 2 + len(hexd)
                    continue
            out.append(ord(nxt))
            i += 2
            continue
        out.extend(c.encode("latin-1", "replace"))
        i += 1
    return bytes(out)


class _DecoderEvalError(Exception):
    pass


class _Parser:
    """Parses + evaluates a decoder expression to bytes. Raises on anything it
    cannot statically resolve, which the caller treats as "not a static layer"."""

    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    def _peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> _Tok:
        t = self._peek()
        if t is None:
            raise _DecoderEvalError("unexpected end")
        self.i += 1
        return t

    def parse(self) -> bytes:
        val = self._concat()
        return val

    def _concat(self) -> bytes:
        val = self._primary()
        while True:
            t = self._peek()
            if t and t.kind == "DOT":
                self._next()
                val = val + self._primary()
            else:
                break
        return val

    def _primary(self) -> bytes:
        t = self._next()
        if t.kind in ("SQSTR", "DQSTR"):
            return _unescape_php_string(t.val)
        if t.kind == "NUMBER":
            return t.val.encode()
        if t.kind == "LP":
            v = self._concat()
            nt = self._next()
            if nt.kind != "RP":
                raise _DecoderEvalError("expected )")
            return v
        if t.kind == "IDENT":
            ahead = self._peek()
            if ahead and ahead.kind == "LP":
                self._next()  # consume (
                args = self._args()
                ct = self._next()
                if ct.kind != "RP":
                    raise _DecoderEvalError("expected ) after args")
                return _apply(t.val.lower(), args)
            raise _DecoderEvalError(f"bare identifier {t.val}")
        raise _DecoderEvalError(f"unexpected token {t.kind}:{t.val}")

    def _args(self) -> list[bytes]:
        args: list[bytes] = []
        first = self._peek()
        if first and first.kind == "RP":
            return args
        args.append(self._concat())
        nxt = self._peek()
        while nxt and nxt.kind == "COMMA":
            self._next()
            args.append(self._concat())
            nxt = self._peek()
        return args


def _apply(fn: str, args: list[bytes]) -> bytes:
    a0 = args[0] if args else b""
    try:
        if fn == "base64_decode":
            return base64.b64decode(a0 + b"=" * (-len(a0) % 4), validate=False)
        if fn == "gzinflate":
            return zlib.decompress(a0, -zlib.MAX_WBITS)
        if fn == "gzuncompress":
            return zlib.decompress(a0)
        if fn == "gzdecode":
            return gzip.decompress(a0)
        if fn == "str_rot13":
            return codecs.encode(a0.decode("latin-1"), "rot13").encode("latin-1")
        if fn == "strrev":
            return a0[::-1]
        if fn in ("urldecode", "rawurldecode"):
            return urllib.parse.unquote_to_bytes(a0)
        if fn == "hex2bin":
            return bytes.fromhex(a0.decode("latin-1"))
        if fn == "chr":
            return bytes([int(a0) & 0xFF])
        if fn == "pack":
            # pack('H*', $hex) is the common obfuscation idiom
            fmt = args[0].decode("latin-1") if args else ""
            if fmt.upper().startswith("H") and len(args) > 1:
                return bytes.fromhex(args[1].decode("latin-1"))
            raise _DecoderEvalError("unsupported pack format")
        if fn in ("stripslashes", "trim"):
            return a0
    except _DecoderEvalError:
        raise
    except Exception as exc:  # decode failed -> not a clean static layer
        raise _DecoderEvalError(str(exc)) from exc
    raise _DecoderEvalError(f"unknown function {fn}")


_DECODER_NAMES = (
    "base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|"
    "urldecode|rawurldecode|hex2bin|pack|chr"
)


def _extract_balanced(code: str, open_pos: int) -> tuple[str, int]:
    """Given index of a '(', return (inner, index-after-matching-')')."""
    depth = 0
    i = open_pos
    in_str: str | None = None
    while i < len(code):
        c = code[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in "'\"":
            in_str = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return code[open_pos + 1 : i], i + 1
        i += 1
    raise _DecoderEvalError("unbalanced parentheses")


def _extract_concat_expr(code: str, start: int) -> tuple[str, int]:
    """From ``start`` (at a decoder identifier or string literal), consume the
    maximal PHP concatenation expression (primaries joined by '.') and return
    (expr_text, end_index). This lets ``chr(..).chr(..)`` chains be evaluated as
    one unit instead of one call at a time."""
    i = start
    n = len(code)

    def skip_ws(j: int) -> int:
        while j < n and code[j].isspace():
            j += 1
        return j

    def consume_primary(j: int) -> int | None:
        j = skip_ws(j)
        if j >= n:
            return None
        if code[j] in "'\"":
            quote = code[j]
            k = j + 1
            while k < n:
                if code[k] == "\\":
                    k += 2
                    continue
                if code[k] == quote:
                    return k + 1
                k += 1
            return None
        m = re.match(r"[A-Za-z_]\w*\s*\(", code[j:])
        if m:
            open_paren = j + code[j:].index("(")
            try:
                _, end = _extract_balanced(code, open_paren)
                return end
            except _DecoderEvalError:
                return None
        m2 = re.match(r"\d+", code[j:])
        if m2:
            return j + m2.end()
        return None

    end = consume_primary(i)
    if end is None:
        return code[start : start + 1], start + 1
    while True:
        j = skip_ws(end)
        if j < n and code[j] == ".":
            nxt = consume_primary(j + 1)
            if nxt is None:
                break
            end = nxt
        else:
            break
    return code[start:end], end


def _eval_decoder_chain(expr: str) -> bytes | None:
    try:
        toks = _lex(expr)
        return _Parser(toks).parse()
    except (_DecoderEvalError, IndexError):
        return None


def deobfuscate(code: str, max_depth: int = 24) -> tuple[list[dict], str]:
    """Peel obfuscation layers. Returns (layers, final_payload).

    Each layer dict: {depth, wrapper, function, before, after, after_len}.
    """
    layers: list[dict] = []
    current = code
    seen: set[str] = set()
    for depth in range(max_depth):
        if current in seen:
            break
        seen.add(current)

        # Prefer an eval/assert wrapper: evaluate its *argument* (a decoder chain)
        # to obtain the next layer of code (we never execute, only decode).
        wrapper_match = re.search(r"\b(eval|assert)\s*\(", current, re.IGNORECASE)
        target = None
        if wrapper_match:
            try:
                inner, _ = _extract_balanced(current, current.index("(", wrapper_match.start()))
                decoded = _eval_decoder_chain(inner)
                if decoded is not None:
                    target = ("eval/" + wrapper_match.group(1).lower(), inner, decoded)
            except _DecoderEvalError:
                target = None

        # Otherwise, a standalone outermost decoder call.
        if target is None:
            dm = re.search(rf"\b({_DECODER_NAMES})\s*\(", current, re.IGNORECASE)
            if dm:
                try:
                    start = dm.start()
                    # Consume the whole concatenation chain (e.g. chr().chr()...)
                    # so it collapses to one contiguous decoded string.
                    full, end = _extract_concat_expr(current, start)
                    decoded = _eval_decoder_chain(full)
                    if decoded is not None:
                        target = ("inline/" + dm.group(1).lower(), full, decoded)
                        # substitute in place so surrounding code is preserved
                        decoded_str = decoded.decode("utf-8", "replace")
                        current = current[:start] + decoded_str + current[end:]
                        layers.append(
                            {
                                "depth": depth,
                                "wrapper": target[0],
                                "function": dm.group(1).lower(),
                                "before": _clip(full),
                                "after": _clip(decoded_str),
                                "after_len": len(decoded),
                            }
                        )
                        continue
                except _DecoderEvalError:
                    target = None

        if target is None:
            break

        wrapper, before, decoded = target
        decoded_str = decoded.decode("utf-8", "replace")
        layers.append(
            {
                "depth": depth,
                "wrapper": wrapper,
                "function": wrapper.split("/")[-1],
                "before": _clip(before),
                "after": _clip(decoded_str),
                "after_len": len(decoded),
            }
        )
        current = decoded_str
    return layers, current


def _clip(s: str, n: int = _PREVIEW) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + f"…(+{len(s) - n} chars)"


def find_sinks(code: str) -> list[tuple[str, str, float]]:
    """Return (category, sink_name, confidence) for dangerous sinks present."""
    out: list[tuple[str, str, float]] = []
    for name, conf in COMMAND_SINKS.items():
        if re.search(rf"\b{name}\s*\(", code):
            out.append(("command_exec", name, conf))
    for name, conf in CODE_SINKS.items():
        if re.search(rf"\b{name}\s*\(", code):
            out.append(("code_exec", name, conf))
    for name, conf in FILE_SINKS.items():
        if re.search(rf"\b{name}\s*\(", code):
            out.append(("file_write", name, conf))
    # preg_replace with /e modifier (deprecated RCE primitive)
    if re.search(r"preg_replace\s*\(\s*(['\"]).*?\1\s*[eimsuxADSUXJ]*e[eimsuxADSUXJ]*\1?", code) or re.search(
        r"preg_replace\s*\(\s*['\"][^'\"]*/[a-zA-Z]*e[a-zA-Z]*['\"]", code
    ):
        out.append(("code_exec", "preg_replace/e", 0.85))
    # variable-function call: $f(...) where $f may hold a sink name
    if re.search(r"\$\w+\s*\(", code):
        out.append(("code_exec", "variable_function", 0.55))
    return out


def find_tainted_input(code: str) -> list[str]:
    return [sg for sg in SUPERGLOBALS if sg in code]


class PhpAnalyzer(BaseAnalyzer):
    name = "static.php"
    handles = {"php"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        code = sample.text
        ref = f"sample:{sample.sha256}"
        items: list[EvidenceItem] = []

        layers, final_payload = deobfuscate(code)

        # One evidence item per unwrap layer — the explainable peel.
        for layer in layers:
            items.append(
                ctx.ev(
                    source="static.php",
                    artifact="string",
                    operation="decode",
                    subject={"analyzer": self.name},
                    object={"layer": layer["depth"], "function": layer["function"]},
                    details={
                        "wrapper": layer["wrapper"],
                        "decoded_preview": layer["after"],
                        "decoded_len": layer["after_len"],
                        "source_preview": layer["before"],
                    },
                    confidence=0.95,
                    evidence_refs=[ref, f"layer:{layer['depth']}"],
                )
            )

        if layers:
            items.append(
                ctx.ev(
                    source="static.php",
                    artifact="string",
                    operation="decode",
                    subject={"analyzer": self.name},
                    object={"artifact": "deobfuscated_payload"},
                    details={
                        "layers": len(layers),
                        "final_payload_preview": _clip(final_payload, 1000),
                        "final_payload_len": len(final_payload),
                    },
                    confidence=0.9,
                    evidence_refs=[ref],
                )
            )

        # Sinks — scan both the original and the fully-unwrapped payload.
        scanned = code if not layers else code + "\n" + final_payload
        for category, sink, conf in find_sinks(scanned):
            items.append(
                ctx.ev(
                    source="static.php",
                    artifact="api_call",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"sink": sink, "category": category},
                    details={
                        "note": f"dangerous PHP sink '{sink}' present in (deobfuscated) code",
                        "found_after_deobfuscation": bool(layers) and re.search(rf"\b{re.escape(sink)}\s*\(", final_payload) is not None,
                    },
                    confidence=conf,
                    evidence_refs=[ref],
                )
            )

        # Tainted input reaching the shell.
        tainted = find_tainted_input(scanned)
        if tainted:
            items.append(
                ctx.ev(
                    source="static.php",
                    artifact="string",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"superglobals": tainted},
                    details={"note": "attacker-controllable superglobal input present"},
                    confidence=0.7,
                    evidence_refs=[ref],
                )
            )

        # Webshell verdict when obfuscation + a code/command sink co-occur.
        sink_names = {s for _, s, _ in find_sinks(scanned)}
        if layers and (sink_names & (set(COMMAND_SINKS) | set(CODE_SINKS))):
            items.append(
                ctx.ev(
                    source="static.php",
                    artifact="file",
                    operation="exec",
                    subject={"analyzer": self.name},
                    object={"verdict": "php_webshell"},
                    details={
                        "rationale": "obfuscated payload unwraps to a code/command execution sink",
                        "layers": len(layers),
                        "sinks": sorted(sink_names),
                    },
                    confidence=0.85,
                    evidence_refs=[ref],
                )
            )
        return items


def register(registry) -> None:
    registry.register(PhpAnalyzer())
