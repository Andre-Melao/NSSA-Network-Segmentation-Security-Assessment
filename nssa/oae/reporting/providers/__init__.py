"""Factory for constructing an LLMProvider from an LLMAuth declaration.

Maps authentication.llm.provider to a concrete adapter and its construction.
Callers use build_llm_provider() rather than importing adapters, so a new
provider only touches this factory and its adapter module.
"""

from __future__ import annotations

import os

from nssa.oae.reporting.contracts import LLMProvider
from nssa.shared.authentication import LLMAuth


def build_llm_provider(llm_auth: LLMAuth) -> LLMProvider:
    """Construct the LLMProvider declared by *llm_auth*.

    Recognized names: "anthropic" and "gemini" (dedicated adapters) and
    "openai", "openrouter", "ollama" (all OpenAIProvider, differing in
    base_url/api_key; see providers.openai).

    Raises ValueError for a missing/unrecognized provider, a missing api_key or
    model, or an "env:VAR_NAME" api_key whose variable is unset. These are
    configuration errors, not runtime LLMProviderErrors.
    """
    if llm_auth.provider == "anthropic":
        return _build_anthropic_provider(llm_auth)
    if llm_auth.provider == "gemini":
        return _build_gemini_provider(llm_auth)
    if llm_auth.provider == "openai":
        return _build_openai_compatible_provider(llm_auth, provider_name="openai", default_base_url=None)
    if llm_auth.provider == "openrouter":
        return _build_openai_compatible_provider(
            llm_auth, provider_name="openrouter", default_base_url="https://openrouter.ai/api/v1",
        )
    if llm_auth.provider == "ollama":
        return _build_ollama_provider(llm_auth)
    raise ValueError(f"Unsupported LLM provider: {llm_auth.provider!r}")


def _resolve_secret(value: str) -> str:
    """Resolve a literal value or an "env:VAR_NAME" reference into a secret.

    "env:X" keeps the real key out of the (possibly shared) config file. An
    unset variable fails clearly instead of sending "env:X" to the API.
    """
    if not value.startswith("env:"):
        return value
    var_name = value[len("env:"):]
    resolved = os.environ.get(var_name)
    if not resolved:
        raise ValueError(
            f'authentication.llm.api_key references environment variable "{var_name}", which is not set'
        )
    return resolved


def _build_anthropic_provider(llm_auth: LLMAuth) -> LLMProvider:
    if not llm_auth.api_key:
        raise ValueError('authentication.llm.api_key is required for provider="anthropic"')
    if not llm_auth.model:
        raise ValueError('authentication.llm.model is required for provider="anthropic"')

    try:
        import anthropic
    except ImportError as exc:
        raise ImportError(
            "The 'anthropic' package is required for provider=\"anthropic\" -- "
            "install it via the 'reporting-anthropic' extra: pip install nssa[reporting-anthropic]"
        ) from exc

    from nssa.oae.reporting.providers.anthropic import AnthropicProvider

    api_key = _resolve_secret(llm_auth.api_key)
    client = anthropic.Anthropic(api_key=api_key)
    kwargs = {} if llm_auth.max_output_tokens is None else {"max_tokens": llm_auth.max_output_tokens}
    return AnthropicProvider(client, model=llm_auth.model, **kwargs)


def _build_gemini_provider(llm_auth: LLMAuth) -> LLMProvider:
    if not llm_auth.api_key:
        raise ValueError('authentication.llm.api_key is required for provider="gemini"')
    if not llm_auth.model:
        raise ValueError('authentication.llm.model is required for provider="gemini"')

    try:
        from google import genai
    except ImportError as exc:
        raise ImportError(
            "The 'google-genai' package is required for provider=\"gemini\" -- "
            "install it via the 'reporting-gemini' extra: pip install nssa[reporting-gemini]"
        ) from exc

    from nssa.oae.reporting.providers.gemini import GeminiProvider

    api_key = _resolve_secret(llm_auth.api_key)
    client = genai.Client(api_key=api_key)
    kwargs = {} if llm_auth.max_output_tokens is None else {"max_output_tokens": llm_auth.max_output_tokens}
    return GeminiProvider(client, model=llm_auth.model, **kwargs)


def _import_openai():
    try:
        import openai
    except ImportError as exc:
        raise ImportError(
            "The 'openai' package is required for provider=\"openai\"/\"openrouter\"/\"ollama\" "
            "-- install it via the 'reporting-openai' extra: pip install nssa[reporting-openai]"
        ) from exc
    return openai


def _build_openai_compatible_provider(
    llm_auth: LLMAuth, *, provider_name: str, default_base_url: str | None,
) -> LLMProvider:
    """Shared by provider="openai" and "openrouter": hosted services needing a real
    api_key, differing in base_url (None means the SDK's default). "ollama" uses
    _build_ollama_provider() instead (different api_key handling).
    """
    if not llm_auth.api_key:
        raise ValueError(f'authentication.llm.api_key is required for provider="{provider_name}"')
    if not llm_auth.model:
        raise ValueError(f'authentication.llm.model is required for provider="{provider_name}"')

    openai = _import_openai()
    from nssa.oae.reporting.providers.openai import OpenAIProvider

    api_key = _resolve_secret(llm_auth.api_key)
    client = openai.OpenAI(api_key=api_key, base_url=llm_auth.base_url or default_base_url)
    kwargs = {} if llm_auth.max_output_tokens is None else {"max_output_tokens": llm_auth.max_output_tokens}
    return OpenAIProvider(client, model=llm_auth.model, provider_name=provider_name, **kwargs)


def _build_ollama_provider(llm_auth: LLMAuth) -> LLMProvider:
    """provider="ollama": a local or reachable Ollama OpenAI-compatible endpoint.

    Ollama ignores api_key, but the authentication parser requires it whenever
    'llm' is declared, so any non-empty placeholder (e.g. "ollama") works.
    """
    if not llm_auth.model:
        raise ValueError('authentication.llm.model is required for provider="ollama"')

    openai = _import_openai()
    from nssa.oae.reporting.providers.openai import OpenAIProvider

    # Still resolved via _resolve_secret() in case Ollama sits behind real auth (e.g. a proxy).
    api_key = _resolve_secret(llm_auth.api_key) if llm_auth.api_key else "ollama"
    client = openai.OpenAI(api_key=api_key, base_url=llm_auth.base_url or "http://localhost:11434/v1")
    kwargs = {} if llm_auth.max_output_tokens is None else {"max_output_tokens": llm_auth.max_output_tokens}
    return OpenAIProvider(client, model=llm_auth.model, provider_name="ollama", **kwargs)
