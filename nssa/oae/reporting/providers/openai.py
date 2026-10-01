"""OpenAIProvider: the LLMProvider adapter for "openai", "openrouter" and "ollama".

Implements LLMProvider (nssa.oae.reporting.contracts) against the OpenAI Chat
Completions wire protocol, which OpenRouter and Ollama's OpenAI-compatible
endpoint also expose; build_llm_provider() differentiates them by
base_url/api_key. A different wire protocol gets its own adapter.

Structured output uses response_format={"type": "json_schema", ...}, without
"strict": strict mode needs an OpenAI-specific schema copy, and OpenRouter/
Ollama models vary in support. The shared parser
(_parsing.parse_enrichment_response()) is the safety net.

The 'openai' package is never imported here: the client is injected, so this
file is importable and testable with a fake client without the optional
dependency ("reporting-openai" extra).

The request/response shape was verified against openai 2.46.0; if the SDK
changes, only this file needs updating.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from nssa.oae.reporting.errors import LLMProviderError
from nssa.oae.reporting.models import EnrichmentResult
from nssa.oae.reporting.prompt import Prompt
from nssa.oae.reporting.providers._defaults import DEFAULT_MAX_OUTPUT_TOKENS
from nssa.oae.reporting.providers._parsing import parse_enrichment_response
from nssa.oae.reporting.providers._retry import with_retry
from nssa.oae.reporting.providers._schema import ENRICHMENT_RESULT_SCHEMA
from nssa.oae.reporting.providers._truncation import build_hint

# The schema is shared (providers._schema); only this response_format wrapper is OpenAI-specific.
_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "enrichment_result",
        "schema": ENRICHMENT_RESULT_SCHEMA,
        "strict": False,
    },
}

# Transient (retryable) exception class names, checked by name so the openai
# package need not be installed. Same set as AnthropicProvider.
_RETRYABLE_EXCEPTION_NAMES = frozenset({
    "RateLimitError", "APIConnectionError", "APITimeoutError", "InternalServerError",
})


def _is_retryable(exc: Exception) -> bool:
    return type(exc).__name__ in _RETRYABLE_EXCEPTION_NAMES


def _truncation_hint(finish_reason: str | None) -> str:
    """Like GeminiProvider's _truncation_hint(): detect an output-token cutoff
    from finish_reason ("length" here, "MAX_TOKENS" for Gemini). Message text
    is shared (providers._truncation).
    """
    if finish_reason == "length":
        return build_hint("finish_reason is 'length'", provider_class_name="OpenAIProvider")
    return ""


class OpenAIProvider:
    """client: an injected openai.OpenAI (or compatible
    .chat.completions.create(...)); build_llm_provider() chooses its
    base_url/api_key.

    provider_name: "openai", "openrouter" or "ollama", recorded in
    GenerationMetadata.provider so the report shows the real provenance.
    """

    def __init__(
        self,
        client: Any,
        *,
        model: str,
        provider_name: str = "openai",
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        temperature: float = 0.0,
        max_attempts: int = 3,
    ) -> None:
        self._client = client
        self._model = model
        self._provider_name = provider_name
        self._max_output_tokens = max_output_tokens
        self._temperature = temperature
        self._max_attempts = max_attempts

    def enrich(self, prompt: Prompt) -> EnrichmentResult:
        generated_at = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()

        def _call() -> Any:
            return self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": prompt.system},
                    {"role": "user", "content": prompt.user},
                ],
                temperature=self._temperature,
                max_completion_tokens=self._max_output_tokens,
                response_format=_RESPONSE_FORMAT,
            )

        try:
            response = with_retry(_call, is_retryable=_is_retryable, max_attempts=self._max_attempts)
        except Exception as exc:
            raise LLMProviderError(f"OpenAI-compatible request failed: {exc}") from exc

        latency_ms = (time.monotonic() - start) * 1000

        choices = getattr(response, "choices", None) or []
        if not choices:
            raise LLMProviderError("OpenAI-compatible response contained no choices")
        choice = choices[0]
        text = getattr(getattr(choice, "message", None), "content", None)
        if not text:
            hint = _truncation_hint(getattr(choice, "finish_reason", None))
            raise LLMProviderError(f"OpenAI-compatible response contained no message content{hint}")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            hint = _truncation_hint(getattr(choice, "finish_reason", None))
            raise LLMProviderError(f"OpenAI-compatible response was not valid JSON: {exc}{hint}") from exc

        usage = getattr(response, "usage", None)
        return parse_enrichment_response(
            data,
            provider=self._provider_name,
            model=self._model,
            prompt_version=prompt.prompt_version,
            generated_at=generated_at,
            latency_ms=latency_ms,
            input_tokens=getattr(usage, "prompt_tokens", None),
            output_tokens=getattr(usage, "completion_tokens", None),
        )
