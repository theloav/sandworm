"""Provider-agnostic LLM interface for the analyst copilot.

Supports OpenAI-compatible, Anthropic, and an offline ``mock`` provider. Defaults
to the mock so the whole system runs offline with no secrets. The copilot grounds
every answer in retrieved evidence (see ``copilot/graphrag.py``); the provider
only phrases the grounded facts.
"""

from __future__ import annotations

from typing import Protocol

from .config import Config, get_config


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str: ...


class MockProvider:
    """Deterministic, offline provider. Echoes a grounded, citation-preserving
    summary built from the prompt. Never invents facts — if the grounded context
    is empty it says so, which is exactly the behavior the grounding test wants."""

    name = "mock"

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:
        # The graphrag layer hands us a context block delimited by markers. We
        # extract it verbatim so the "answer" is provably derived from evidence.
        ctx = ""
        if "<CONTEXT>" in prompt and "</CONTEXT>" in prompt:
            ctx = prompt.split("<CONTEXT>", 1)[1].split("</CONTEXT>", 1)[0].strip()
        question = ""
        if "<QUESTION>" in prompt and "</QUESTION>" in prompt:
            question = prompt.split("<QUESTION>", 1)[1].split("</QUESTION>", 1)[0].strip()
        if not ctx:
            return (
                "No supporting evidence was found in the behavioral graph for "
                f"the question: {question!r}. I will not guess."
            )
        lines = [ln for ln in ctx.splitlines() if ln.strip()]
        summary = "Based on the retrieved evidence:\n" + "\n".join(f"- {ln}" for ln in lines[:12])
        summary += "\n\n(Answer grounded strictly in the cited evidence above.)"
        return summary


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client = None

    def _ensure(self):  # pragma: no cover - requires network/secret
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.config.llm_api_key)
        return self._client

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:  # pragma: no cover
        client = self._ensure()
        resp = client.messages.create(
            model=self.config.llm_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")


class OpenAICompatProvider:
    name = "openai"

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client = None

    def _ensure(self):  # pragma: no cover
        if self._client is None:
            import openai

            self._client = openai.OpenAI(api_key=self.config.llm_api_key)
        return self._client

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:  # pragma: no cover
        client = self._ensure()
        resp = client.chat.completions.create(
            model=self.config.llm_model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""


def get_provider(config: Config | None = None) -> LLMProvider:
    config = config or get_config()
    provider = config.llm_provider.lower()
    if provider == "anthropic":
        return AnthropicProvider(config)
    if provider in {"openai", "openai-compat"}:
        return OpenAICompatProvider(config)
    return MockProvider()
