"""Exception hierarchy for the LLM enrichment layer.

Enrichment is additive, never a precondition for the OAE's own report, so
callers are expected to catch LLMProviderError/KnowledgeProviderError and
degrade gracefully with a reduced or absent EnrichmentResult.
"""

from __future__ import annotations


class EnrichmentError(Exception):
    """Base for every error nssa.oae.reporting raises."""


class LLMProviderError(EnrichmentError):
    """An LLMProvider could not produce an EnrichmentResult (network, auth, rate
    limit, invalid response, ...). The OAE report is already complete, so this
    must never block or corrupt it."""


class KnowledgeProviderError(EnrichmentError):
    """A KnowledgeProvider could not be queried. Non-fatal: callers may proceed
    with an empty KnowledgeBundle."""


class RenderError(EnrichmentError):
    """A Renderer could not produce output."""
