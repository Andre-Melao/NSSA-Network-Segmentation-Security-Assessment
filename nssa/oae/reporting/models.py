"""Output-side domain models for the LLM enrichment layer.

The shapes crossing the LLMProvider -> Renderer boundary: every provider adapter
produces an EnrichmentResult in exactly this shape, and every Renderer consumes
it without knowing the provider. Expected to change rarely. No dependency on
nssa.oae.reporting.context or .prompt.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FrameworkMapping:
    """One finding-to-control association, as decided by the LLM.

    Its existence is the outcome of the LLM's reasoning over the finding's
    evidence and the full curated knowledge base (see KnowledgeBundle); no
    code decides in advance that a finding relates to a control. A finding with
    no applicable control has an empty framework_mappings tuple.

    control_id/control_title must come from the curated KnowledgeSnippet(s),
    never be invented; rationale is the LLM-authored explanation.
    """

    framework: str
    control_id: str
    control_title: str | None
    rationale: str | None


@dataclass(frozen=True, slots=True)
class FindingEnrichment:
    """Additional LLM-authored information for one finding (not a copy of it).

    finding_id is the only link back to oae-report.json (matched against each
    entry's "id", e.g. "AF-0001"); a Renderer joins on it and handles ids that
    match nothing.

    title: short one-line headline of the finding, for scanning.
    summary: short (1-3 sentence) plain-English account of what the evidence
        shows (distinct from title and business_impact).

    Both are LLM-authored, since raw fields do not read as prose.
    """

    finding_id: str
    title: str
    summary: str
    business_impact: str
    mitigation_suggestions: tuple[str, ...]
    framework_mappings: tuple[FrameworkMapping, ...]


@dataclass(frozen=True, slots=True)
class GenerationMetadata:
    """Traceability for one EnrichmentResult: what produced it.

    generated_at (ISO-8601), latency_ms, input_tokens and output_tokens are
    optional and provider-reported; None when unavailable.
    """

    provider: str
    model: str
    prompt_version: str
    generated_at: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    """The full structured output of one LLMProvider.enrich() call (same shape for every provider)."""

    executive_summary: str
    finding_enrichments: tuple[FindingEnrichment, ...]
    metadata: GenerationMetadata
