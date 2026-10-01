"""AnthropicProvider: the LLMProvider adapter for the Anthropic Messages API.

Uses tool-use with a forced tool_choice to obtain structured output; only this
file knows the mechanism, and every adapter ends by calling
parse_enrichment_response() with a JSON-shaped object.

The 'anthropic' package is never imported here: the client is injected, so the
file is importable and testable with a fake client without the optional
dependency.
"""

from __future__ import annotations

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

_TOOL_NAME = "submit_enrichment_result"

# The schema is shared (providers._schema); only this tool-use wrapper
# (name/description) is Anthropic-specific. Forcing the tool call is what makes
# the output structured.
_TOOL_SCHEMA = {
    "name": _TOOL_NAME,
    "description": "Submit the structured enrichment result for the supplied findings.",
    "input_schema": ENRICHMENT_RESULT_SCHEMA,
}

# Transient (retryable) exception class names, checked by name so the anthropic
# package need not be installed.
_RETRYABLE_EXCEPTION_NAMES = frozenset({
    "RateLimitError", "APIConnectionError", "APITimeoutError",
    "InternalServerError", "OverloadedError",
})


def _is_retryable(exc: Exception) -> bool:
    return type(exc).__name__ in _RETRYABLE_EXCEPTION_NAMES


class AnthropicProvider:
    """client: an injected anthropic.Anthropic (or compatible .messages.create(...)),
    so tests can pass a fake client.
    """

    def __init__(
        self,
        client: Any,
        *,
        model: str,
        max_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        temperature: float | None = None,
        max_attempts: int = 3,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._max_attempts = max_attempts

    def enrich(self, prompt: Prompt) -> EnrichmentResult:
        generated_at = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()

        def _call() -> Any:
            kwargs: dict[str, Any] = {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": prompt.system,
                "messages": [{"role": "user", "content": prompt.user}],
                "tools": [_TOOL_SCHEMA],
                "tool_choice": {"type": "tool", "name": _TOOL_NAME},
            }
            # Omitted by default: current Claude models reject an explicit
            # temperature/top_p/top_k (400) while older ones accept it, and the
            # model string is auditor-supplied, so none is sent unless a caller
            # passes one.
            if self._temperature is not None:
                kwargs["temperature"] = self._temperature
            return self._client.messages.create(**kwargs)

        try:
            response = with_retry(_call, is_retryable=_is_retryable, max_attempts=self._max_attempts)
        except Exception as exc:
            raise LLMProviderError(f"Anthropic request failed: {exc}") from exc

        latency_ms = (time.monotonic() - start) * 1000

        tool_use_block = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use_block is None:
            hint = (
                build_hint("stop_reason is 'max_tokens'", provider_class_name="AnthropicProvider")
                if getattr(response, "stop_reason", None) == "max_tokens"
                else ""
            )
            raise LLMProviderError(f"Anthropic response contained no tool_use block{hint}")

        usage = getattr(response, "usage", None)
        return parse_enrichment_response(
            tool_use_block.input,
            provider="anthropic",
            model=self._model,
            prompt_version=prompt.prompt_version,
            generated_at=generated_at,
            latency_ms=latency_ms,
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
        )
