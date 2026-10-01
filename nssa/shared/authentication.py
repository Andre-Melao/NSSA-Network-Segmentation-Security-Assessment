"""Authentication model.

Frozen dataclasses describing how the auditor's machine authenticates to
external systems (SSH targets, LLM providers, cloud APIs). Orthogonal to policy
and deployment.

Authentication must never be forwarded to an APU invocation; see
nssa.shared.audit_config.extract_runtime_configuration(), whose return type
has no field to carry it.

Field values are opaque strings: literal material or a reference (e.g. an
environment variable name) resolved elsewhere. This module only carries the
declared shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SSHAuth:
    """SSH authentication the auditor's machine uses to reach workloads.

    username     - optional SSH user (Host Mode's --ssh-user overrides it).
    private_key  - optional path to a private key file (never the key itself).
    """

    username: str | None = None
    private_key: str | None = None


@dataclass(frozen=True, slots=True)
class LLMAuth:
    """Authentication for the LLM enrichment layer (nssa.oae.reporting.providers).

    provider  - optional; one of "anthropic", "gemini", "openai", "openrouter",
                "ollama", used by build_llm_provider() to pick an adapter.
                openai/openrouter/ollama share OpenAIProvider (OpenAI-compatible
                endpoints) and differ only in client construction.
    api_key   - optional literal key or "env:VAR_NAME" reference, resolved by
                build_llm_provider() so shared configs hold no credential. For
                "ollama" any non-empty placeholder works.
    model     - optional provider-specific model id; validity is the adapter's concern.
    max_output_tokens - optional override of the adapters' default ceiling (8192).
                None means use the default. Raise it for reports with many
                findings, since output scales with finding count.
    base_url  - optional endpoint override for OpenAIProvider; ignored by
                "anthropic"/"gemini". None uses each provider's default (OpenAI,
                "https://openrouter.ai/api/v1", "http://localhost:11434/v1").
    """

    provider: str | None = None
    api_key: str | None = None
    model: str | None = None
    max_output_tokens: int | None = None
    base_url: str | None = None


@dataclass(frozen=True, slots=True)
class Authentication:
    """Every declared authentication mechanism for one audit configuration.

    ssh_profiles - named SSH identities used by nssa-run for automated Probes
                   (see SSHRunner); a Probe selects one by name via
                   ProbeConfig.ssh_profile. Empty if no SSH automation.
    llm          - see LLMAuth.
    frameworks   - frameworks the LLM enrichment is contextualised against
                   (e.g. ["pci_dss", "iso_27002"]); () if undeclared.
    extra        - any other sub-section, kept verbatim and not interpreted.
    """

    ssh_profiles: dict[str, SSHAuth] = field(default_factory=dict)
    llm: LLMAuth | None = None
    frameworks: Any = ()
    extra: dict[str, Any] = field(default_factory=dict)
