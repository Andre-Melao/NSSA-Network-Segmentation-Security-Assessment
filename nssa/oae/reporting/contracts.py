"""The pluggable interfaces of the LLM enrichment layer.

Three Protocols: LLMProvider, KnowledgeProvider and Renderer. Together with
Prompt and EnrichmentResult they are the hardest-to-change surface of the
package. ContextBuilder and PromptBuilder are not Protocols: each has one
canonical implementation.
"""

from __future__ import annotations

from typing import Protocol

from nssa.oae.reporting.context import KnowledgeBundle, OAEReport
from nssa.oae.reporting.models import EnrichmentResult
from nssa.oae.reporting.prompt import Prompt


class LLMProvider(Protocol):
    """Translates one Prompt into a provider request and the response into an EnrichmentResult.

    Never builds prompt text (PromptBuilder's job). Raises LLMProviderError on
    failure; never returns a partial or malformed EnrichmentResult.
    """

    def enrich(self, prompt: Prompt) -> EnrichmentResult: ...


class KnowledgeProvider(Protocol):
    """Supplies curated compliance knowledge for the frameworks an audit selected.

    One call per run, for all requested frameworks. Returns the complete curated
    knowledge base for each framework, never a subset chosen per finding:
    deciding which controls apply to a finding is the LLM's job (see
    PromptBuilder and FrameworkMapping). report is accepted for structural
    completeness only and must not be used to filter controls.

    Raises KnowledgeProviderError on failure; returns an empty KnowledgeBundle
    (never None) when nothing is curated for a framework.
    """

    def get_context(self, frameworks: tuple[str, ...], report: OAEReport) -> KnowledgeBundle: ...


class Renderer(Protocol):
    """Produces final report bytes by joining the deterministic report with optional enrichment.

    Never sees EnrichmentContext, KnowledgeBundle or Prompt. result is None when
    enrichment was skipped or failed; a Renderer must still produce a complete
    report from report alone. The join on finding_id happens inside the
    renderer. Raises RenderError on failure.

    policy_reference (optional) identifies the AuditConfiguration that produced
    *report* (e.g. its filename), passed to build_report_document().
    """

    @property
    def content_type(self) -> str: ...

    def render(
        self, report: OAEReport, result: EnrichmentResult | None, *, policy_reference: str | None = None,
    ) -> bytes: ...
