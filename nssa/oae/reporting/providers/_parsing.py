"""Structured provider output -> EnrichmentResult: the shared parser.

Every adapter ends with a JSON-shaped object (from tool-use, JSON mode, a
response schema, ...); this module validates and converts it into the
EnrichmentResult dataclasses, so all adapters share validation and error
semantics.

No third-party validation dependency: hand-written checks, in the style of
authentication_parser. It validates shape, not truth: it never sees an
EnrichmentContext and does not check a control_id against what was curated.
"""

from __future__ import annotations

from typing import Any

from nssa.oae.reporting.errors import LLMProviderError
from nssa.oae.reporting.models import EnrichmentResult, FindingEnrichment, FrameworkMapping, GenerationMetadata


def parse_enrichment_response(
    data: Any,
    *,
    provider: str,
    model: str,
    prompt_version: str,
    generated_at: str | None = None,
    latency_ms: float | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> EnrichmentResult:
    """Validate and convert one parsed JSON object into an EnrichmentResult.

    Raises LLMProviderError (never a bare KeyError/TypeError/AttributeError) on
    any structural mismatch, so callers can degrade gracefully.
    """
    if not isinstance(data, dict):
        raise LLMProviderError(f"expected a JSON object, got {type(data).__name__}")

    executive_summary = _require_str(data, "executive_summary")

    findings_raw = data.get("findings")
    if not isinstance(findings_raw, list):
        raise LLMProviderError(f"'findings' must be a list, got {type(findings_raw).__name__}")

    finding_enrichments = tuple(
        _parse_finding_enrichment(entry, index=i) for i, entry in enumerate(findings_raw)
    )

    metadata = GenerationMetadata(
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        generated_at=generated_at,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    return EnrichmentResult(
        executive_summary=executive_summary,
        finding_enrichments=finding_enrichments,
        metadata=metadata,
    )


def _parse_finding_enrichment(entry: Any, *, index: int) -> FindingEnrichment:
    prefix = f"findings[{index}]"
    if not isinstance(entry, dict):
        raise LLMProviderError(f"{prefix}: expected an object, got {type(entry).__name__}")

    finding_id = _require_str(entry, "finding_id", prefix)
    title = _require_str(entry, "title", prefix)
    summary = _require_str(entry, "summary", prefix)
    business_impact = _require_str(entry, "business_impact", prefix)

    mitigation_raw = entry.get("mitigation_suggestions", [])
    if not isinstance(mitigation_raw, list) or not all(isinstance(m, str) for m in mitigation_raw):
        raise LLMProviderError(f"{prefix}.mitigation_suggestions must be a list of strings")

    mappings_raw = entry.get("framework_mappings", [])
    if not isinstance(mappings_raw, list):
        raise LLMProviderError(f"{prefix}.framework_mappings must be a list")

    framework_mappings = tuple(
        _parse_framework_mapping(m, prefix=f"{prefix}.framework_mappings[{j}]")
        for j, m in enumerate(mappings_raw)
    )

    return FindingEnrichment(
        finding_id=finding_id,
        title=title,
        summary=summary,
        business_impact=business_impact,
        mitigation_suggestions=tuple(mitigation_raw),
        framework_mappings=framework_mappings,
    )


def _parse_framework_mapping(entry: Any, *, prefix: str) -> FrameworkMapping:
    if not isinstance(entry, dict):
        raise LLMProviderError(f"{prefix}: expected an object, got {type(entry).__name__}")

    framework = _require_str(entry, "framework", prefix)
    control_id = _require_str(entry, "control_id", prefix)

    control_title = entry.get("control_title")
    if control_title is not None and not isinstance(control_title, str):
        raise LLMProviderError(f"{prefix}.control_title must be a string or null")

    rationale = entry.get("rationale")
    if rationale is not None and not isinstance(rationale, str):
        raise LLMProviderError(f"{prefix}.rationale must be a string or null")

    return FrameworkMapping(framework=framework, control_id=control_id, control_title=control_title, rationale=rationale)


def _require_str(data: dict, key: str, prefix: str = "") -> str:
    loc = f"{prefix}.{key}" if prefix else key
    value = data.get(key)
    if not isinstance(value, str):
        raise LLMProviderError(f"'{loc}' must be a string, got {type(value).__name__}")
    return value
