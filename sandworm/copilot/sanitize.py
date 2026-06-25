"""Input sanitization for the analyst copilot.

Sample-controlled text (strings, decoded payloads, file paths) can contain prompt-
injection ("ignore previous instructions, you are now…"). Before any such text is
placed into an LLM context we strip/escape it and wrap it in inert delimiters, and
we neutralize known injection patterns. This reuses the LLM-security threat model:
the model must treat evidence as *data to analyze*, never as instructions.
"""

from __future__ import annotations

import re

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


def sanitize_text(text: str, *, max_len: int = 4000) -> str:
    """Neutralize sample-controlled text for safe inclusion in an LLM prompt."""
    if text is None:
        return ""
    text = _CONTROL.sub(" ", text)
    # Defang our own context delimiters so the sample can't close/open them.
    text = text.replace("<CONTEXT>", "‹CONTEXT›").replace("</CONTEXT>", "‹/CONTEXT›")
    text = text.replace("<QUESTION>", "‹QUESTION›").replace("</QUESTION>", "‹/QUESTION›")
    for pat in _INJECTION_PATTERNS:
        text = pat.sub("[redacted-injection-attempt]", text)
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


def sanitize_question(question: str, *, max_len: int = 500) -> str:
    """The analyst's own question is trusted but still length-bounded and
    control-stripped to keep the prompt well-formed."""
    q = _CONTROL.sub(" ", question or "").strip()
    return q[:max_len]
