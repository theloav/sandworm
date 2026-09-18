"""Input sanitization for the analyst copilot.

Sample-controlled text (strings, decoded payloads, file paths) can contain prompt-
injection ("ignore previous instructions, you are now…"). Before any such text is
placed into an LLM context we strip/escape it and wrap it in inert delimiters, and
we neutralize known injection patterns. This reuses the LLM-security threat model:
the model must treat evidence as *data to analyze*, never as instructions.
"""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata

# Patterns that commonly begin an injection. We don't try to be exhaustive; we
# defang the structure (delimiters, role tokens) and flag the rest.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I),
    re.compile(r"\b(?:system|assistant|user)\s*:", re.I),
    re.compile(r"you\s+are\s+now\b", re.I),
    re.compile(r"</?(?:system|instructions?|context|prompt)>", re.I),
    re.compile(r"disregard\s+(?:the\s+)?(?:above|previous)", re.I),
]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

_ROLE_ESCAPE = re.compile(r"\[/?INST\]|<\|(?:im_start|im_end|system|assistant|user)\|>|\[ev_[a-f0-9]{16}\]", re.I)
_DIRECTIVE = re.compile(r"(?:reveal|print|leak|send|exfiltrate).{0,60}(?:secret|api.key|system.prompt)|(?:classify|report|mark).{0,30}(?:benign|harmless)|(?:ignore|override).{0,25}(?:policy|rules)", re.I)


def injection_signals(text: str) -> list[str]:
    """Bounded advisory detector, not a proof that unmatched text is safe."""
    normalized = unicodedata.normalize("NFKC", text[:32000])
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    signals = []
    if any(pattern.search(normalized) for pattern in _INJECTION_PATTERNS):
        signals.append("instruction_override")
    if _ROLE_ESCAPE.search(normalized):
        signals.append("role_or_citation_spoof")
    if _DIRECTIVE.search(normalized):
        signals.append("output_or_secret_directive")
    for token in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", normalized)[:32]:
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
        if any(pattern.search(decoded) for pattern in _INJECTION_PATTERNS) or _DIRECTIVE.search(decoded):
            signals.append("encoded_directive")
            break
    return signals


def sanitize_text(text: str, *, max_len: int = 4000) -> str:
    """Quarantine known directives; escape structure without changing evidence at rest."""
    if text is None:
        return ""
    signals = injection_signals(text)
    if signals:
        digest = hashlib.sha256(text.encode()).hexdigest()[:16]
        return f"[quarantined sample text sha256-prefix={digest}; signals={','.join(signals)}]"
    text = _CONTROL.sub(" ", text)
    # Defang our own context delimiters so the sample can't close/open them.
    text = text.replace("<CONTEXT>", "‹CONTEXT›").replace("</CONTEXT>", "‹/CONTEXT›")
    text = text.replace("<QUESTION>", "‹QUESTION›").replace("</QUESTION>", "‹/QUESTION›")
    for pat in _INJECTION_PATTERNS:
        text = pat.sub("[redacted-injection-attempt]", text)
    # Sample text cannot introduce prompt boundaries or evidence citations.
    text = text.replace("<", "‹").replace(">", "›").replace("[", "(").replace("]", ")")
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


def sanitize_question(question: str, *, max_len: int = 500) -> str:
    """The analyst's own question is trusted but still length-bounded and
    control-stripped to keep the prompt well-formed."""
    q = sanitize_text(question or "", max_len=max_len).strip()
    return q[:max_len]
