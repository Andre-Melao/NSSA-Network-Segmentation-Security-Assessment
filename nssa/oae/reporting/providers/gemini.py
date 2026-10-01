"""GeminiProvider: the LLMProvider adapter for Google Gemini.

Implements LLMProvider (nssa.oae.reporting.contracts) against the google-genai
SDK (google.genai.Client), using response_mime_type="application/json" +
response_json_schema for structured output. Only this file knows the
mechanism; every adapter ends by calling parse_enrichment_response().

The 'google.genai' package is never imported here: the client is injected, so
the file is importable and testable with a fake client without the optional
dependency. The request/response shape was verified against google-genai
2.12.1; if the SDK changes, only this file needs updating.
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


def _truncation_hint(response: Any) -> str:
    """Return a hint when finish_reason says output was cut off by max_output_tokens.

    Truncated structured output shows up as a JSONDecodeError or an empty
    response. Returns "" when finish_reason is unavailable or not MAX_TOKENS.
    Message text is shared (providers._truncation).
    """
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        return ""
    finish_reason = getattr(candidates[0], "finish_reason", None)
    if finish_reason is not None and str(finish_reason).endswith("MAX_TOKENS"):
        return build_hint("finish_reason is MAX_TOKENS", provider_class_name="GeminiProvider")
    return ""


def _is_retryable(exc: Exception) -> bool:
    """Server errors (5xx) and rate limiting (429) are retryable; other client errors are not.

    Checked by class name and the SDK's .code attribute, so the package need not
    be installed.
    """
    name = type(exc).__name__
    if name == "ServerError":
        return True
    code = getattr(exc, "code", None)
    return name in {"APIError", "ClientError"} and code == 429


class GeminiProvider:
    """client: an injected google.genai.Client (or compatible .models.generate_content(...))."""

    def __init__(
        self,
        client: Any,
        *,
        model: str,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        temperature: float = 0.0,
        max_attempts: int = 3,
    ) -> None:
        self._client = client
        self._model = model
        self._max_output_tokens = max_output_tokens
        self._temperature = temperature
        self._max_attempts = max_attempts

    def enrich(self, prompt: Prompt) -> EnrichmentResult:
        generated_at = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()

        def _call() -> Any:
            return self._client.models.generate_content(
                model=self._model,
                contents=prompt.user,
                config={
                    "system_instruction": prompt.system,
                    "temperature": self._temperature,
                    "max_output_tokens": self._max_output_tokens,
                    "response_mime_type": "application/json",
                    "response_json_schema": ENRICHMENT_RESULT_SCHEMA,
                },
            )

        try:
            response = with_retry(_call, is_retryable=_is_retryable, max_attempts=self._max_attempts)
        except Exception as exc:
            raise LLMProviderError(f"Gemini request failed: {exc}") from exc

        latency_ms = (time.monotonic() - start) * 1000

        text = getattr(response, "text", None)
        if not text:
            raise LLMProviderError(f"Gemini response contained no text output{_truncation_hint(response)}")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            hint = _truncation_hint(response)
            raise LLMProviderError(f"Gemini response was not valid JSON: {exc}{hint}") from exc

        usage = getattr(response, "usage_metadata", None)
        return parse_enrichment_response(
            data,
            provider="gemini",
            model=self._model,
            prompt_version=prompt.prompt_version,
            generated_at=generated_at,
            latency_ms=latency_ms,
            input_tokens=getattr(usage, "prompt_token_count", None),
            output_tokens=getattr(usage, "candidates_token_count", None),
        )
