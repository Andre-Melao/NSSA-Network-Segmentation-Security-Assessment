"""Parser for the 'authentication' section of an audit configuration.

Fast (single pass), fail-early, deterministic. Structural validation only; it
never resolves a credential reference (see nssa.shared.authentication).
"""

from __future__ import annotations

from typing import Any

from nssa.shared.authentication import Authentication, LLMAuth, SSHAuth


def parse_authentication(raw: dict[str, Any]) -> Authentication:
    """Parse an already-loaded 'authentication' dict into Authentication.

    Every field is optional; an empty dict gives an all-None/empty
    Authentication. Unknown sub-sections are kept verbatim in .extra.

    'ssh_profiles' is a named registry ({"name": {"username": ..., "private_key": ...}}).
    That a Probe's referenced profile exists is checked in parse_audit_config().
    """
    ssh_profiles: dict[str, SSHAuth] = {}
    if "ssh_profiles" in raw:
        profiles_raw = raw["ssh_profiles"]
        if not isinstance(profiles_raw, dict):
            raise AuthenticationValidationError(
                f"'ssh_profiles' must be a JSON object, got {type(profiles_raw).__name__}"
            )
        for profile_name, profile_data in profiles_raw.items():
            # Normalized case-insensitively, like a Probe's ssh_profile reference.
            normalized_name = profile_name.strip().lower()
            if normalized_name in ssh_profiles:
                raise AuthenticationValidationError(
                    f"Duplicate ssh_profiles entry '{normalized_name}' "
                    f"(profile names are matched case-insensitively)."
                )
            ssh_profiles[normalized_name] = _parse_ssh(profile_data, context=f"ssh_profiles.{profile_name}")

    llm = None
    if "llm" in raw:
        llm = _parse_llm(raw["llm"])

    # Stored as declared; validated only by the reporting layer.
    frameworks = raw.get("frameworks", ())

    extra = {k: v for k, v in raw.items() if k not in ("ssh_profiles", "llm", "frameworks")}

    return Authentication(ssh_profiles=ssh_profiles, llm=llm, frameworks=frameworks, extra=extra)


def _parse_ssh(data: Any, *, context: str = "ssh") -> SSHAuth:
    if not isinstance(data, dict):
        raise AuthenticationValidationError(
            f"'{context}' must be a JSON object, got {type(data).__name__}"
        )
    username = data.get("username")
    private_key = data.get("private_key")
    if username is not None and not isinstance(username, str):
        raise AuthenticationValidationError(
            f"'{context}.username' must be a string, got {type(username).__name__}"
        )
    if private_key is not None and not isinstance(private_key, str):
        raise AuthenticationValidationError(
            f"'{context}.private_key' must be a string, got {type(private_key).__name__}"
        )
    return SSHAuth(username=username, private_key=private_key)


def _parse_llm(data: Any) -> LLMAuth:
    if not isinstance(data, dict):
        raise AuthenticationValidationError(
            f"'llm' must be a JSON object, got {type(data).__name__}"
        )
    provider = data.get("provider")
    api_key = data.get("api_key")
    model = data.get("model")
    max_output_tokens = data.get("max_output_tokens")
    base_url = data.get("base_url")
    if provider is not None and not isinstance(provider, str):
        raise AuthenticationValidationError(
            f"'llm.provider' must be a string, got {type(provider).__name__}"
        )
    if api_key is not None and not isinstance(api_key, str):
        raise AuthenticationValidationError(
            f"'llm.api_key' must be a string, got {type(api_key).__name__}"
        )
    if model is not None and not isinstance(model, str):
        raise AuthenticationValidationError(
            f"'llm.model' must be a string, got {type(model).__name__}"
        )
    if base_url is not None and not isinstance(base_url, str):
        raise AuthenticationValidationError(
            f"'llm.base_url' must be a string, got {type(base_url).__name__}"
        )
    if max_output_tokens is not None:
        if not isinstance(max_output_tokens, int) or isinstance(max_output_tokens, bool):
            raise AuthenticationValidationError(
                f"'llm.max_output_tokens' must be an integer, got {type(max_output_tokens).__name__}"
            )
        if max_output_tokens <= 0:
            raise AuthenticationValidationError(
                f"'llm.max_output_tokens' must be a positive integer, got {max_output_tokens}"
            )
    # provider/api_key/model are optional individually, but a partial or empty
    # 'llm' section would otherwise only fail when enrichment is attempted, and
    # run_reporting() then degrades silently. Fail at config-load time instead.
    missing = [
        field for field, value in (("provider", provider), ("api_key", api_key), ("model", model))
        if not value
    ]
    if missing:
        raise AuthenticationValidationError(
            f"'llm' is declared but missing {missing} -- provider, api_key, and model "
            f"must all be given together, or 'llm' omitted entirely."
        )
    return LLMAuth(
        # Normalized case-insensitively; build_llm_provider() matches exactly.
        provider=provider.strip().lower() if provider is not None else None,
        api_key=api_key,
        model=model,
        max_output_tokens=max_output_tokens,
        base_url=base_url,
    )


class AuthenticationValidationError(Exception):
    """Raised when an 'authentication' section is structurally invalid."""
