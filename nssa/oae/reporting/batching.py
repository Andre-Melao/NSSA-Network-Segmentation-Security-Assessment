"""Bounded, size-aware batching for LLM enrichment requests.

Splits the finding list into batches sized to stay under the configured
output-token budget, so large audits do not exceed one response's limit. A
batch is a normal Prompt over a subset EnrichmentContext; PromptBuilder, the
LLMProvider Protocol, and EnrichmentResult are unchanged.

Size-aware, not token-accurate: no provider tokenizer is bundled (see
plan_batches()).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from nssa.oae.reporting.models import EnrichmentResult, GenerationMetadata

# ── Batch planning ───────────────────────────────────────────────────────

# Roughly constant per-finding OUTPUT cost (title, summary, impact, a short
# mitigation list, ~3 framework mappings). A flat estimate: output does not
# scale with a finding's input size.
ESTIMATED_OUTPUT_TOKENS_PER_FINDING = 350

# executive_summary is one additional, per-*request* (not per-finding) field.
ESTIMATED_EXECUTIVE_SUMMARY_TOKENS = 250

# Plan against a fraction of the budget to absorb estimation error and JSON overhead.
OUTPUT_BUDGET_SAFETY_FACTOR = 0.7

# Hard ceiling on findings per batch, independent of token math.
MAX_FINDINGS_PER_BATCH = 25


def plan_batches(
    findings: tuple[Mapping[str, Any], ...], *, max_output_tokens: int,
) -> list[tuple[Mapping[str, Any], ...]]:
    """Split *findings* into contiguous, size-bounded batches.

    Contiguous slicing preserves finding order. Returns [()] for empty
    *findings*, never [], so the executive_summary call still happens.
    """
    if not findings:
        return [()]

    effective_budget = max(
        ESTIMATED_OUTPUT_TOKENS_PER_FINDING,
        int(max_output_tokens * OUTPUT_BUDGET_SAFETY_FACTOR) - ESTIMATED_EXECUTIVE_SUMMARY_TOKENS,
    )
    per_batch = max(1, effective_budget // ESTIMATED_OUTPUT_TOKENS_PER_FINDING)
    per_batch = min(per_batch, MAX_FINDINGS_PER_BATCH)

    return [findings[i : i + per_batch] for i in range(0, len(findings), per_batch)]


# ── Batch outcomes and merging ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BatchOutcome:
    """The result of attempting to enrich one batch.

    finding_ids: findings the batch covered (diagnostics only).
    result is None when the batch's enrich() call raised an EnrichmentError;
    error then holds the reason. A failed batch never discards other batches.
    """

    finding_ids: tuple[str, ...]
    result: EnrichmentResult | None
    error: str | None = None


def sum_optional_int(values: list[int | None]) -> int | None:
    """Sum non-None values; None if all are None (provider reports no usage)."""
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def sum_optional_float(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def merge_batch_results(outcomes: list[BatchOutcome]) -> EnrichmentResult | None:
    """Combine every successful batch's EnrichmentResult into one.

    finding_enrichments are concatenated in batch order. A failed batch
    contributes nothing; its findings render with fallback text.

    executive_summary and metadata.{provider,model,prompt_version,generated_at}
    come from the first successful batch. That summary is only whole-audit when
    there was one batch; otherwise run_enrichment() replaces it with a dedicated
    synthesis. metadata.{input_tokens,output_tokens,latency_ms} are summed.

    Returns None only when every batch failed.
    """
    results: list[EnrichmentResult] = [o.result for o in outcomes if o.result is not None]
    if not results:
        return None

    first = results[0]
    finding_enrichments = tuple(fe for r in results for fe in r.finding_enrichments)

    metadata = GenerationMetadata(
        provider=first.metadata.provider,
        model=first.metadata.model,
        prompt_version=first.metadata.prompt_version,
        generated_at=first.metadata.generated_at,
        latency_ms=sum_optional_float([r.metadata.latency_ms for r in results]),
        input_tokens=sum_optional_int([r.metadata.input_tokens for r in results]),
        output_tokens=sum_optional_int([r.metadata.output_tokens for r in results]),
    )

    return EnrichmentResult(
        executive_summary=first.executive_summary,
        finding_enrichments=finding_enrichments,
        metadata=metadata,
    )
