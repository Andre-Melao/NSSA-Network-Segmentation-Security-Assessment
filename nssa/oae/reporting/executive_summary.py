"""Whole-audit executive summary synthesis, separate from per-finding batching
(see nssa.oae.reporting.batching).

Each batch's enrich() call returns an executive_summary scoped to only that
batch's findings, which would misrepresent a partial view as the whole audit.
So per-finding enrichment is batched and the summary is synthesized here.

With exactly one batch, its executive_summary is already whole-audit and is
reused directly (no second call). With more than one, this module runs a second
enrich() call on a compact prompt: ReportStats (from report.py) plus a capped,
priority-ordered digest of findings, so it stays small regardless of audit size.

PromptBuilder is not used: aggregate statistics in, one narrative out is a
different request from per-finding enrichment. The call uses the same
LLMProvider Protocol and schema; the prompt asks for an empty "findings" array,
which the shared schema allows, so no adapter needs changes.
"""

from __future__ import annotations

import dataclasses
import logging

from nssa.oae.reporting.batching import sum_optional_float, sum_optional_int
from nssa.oae.reporting.contracts import LLMProvider
from nssa.oae.reporting.context import OAEReport
from nssa.oae.reporting.errors import EnrichmentError
from nssa.oae.reporting.models import EnrichmentResult, FindingEnrichment, GenerationMetadata
from nssa.oae.reporting.prompt import Prompt
from nssa.oae.reporting.report import compute_stats

# How many (priority-sorted) findings to list in the synthesis prompt: a sample,
# since ReportStats covers all of them. About one batch (MAX_FINDINGS_PER_BATCH),
# keeping the prompt a flat size.
MAX_FINDINGS_IN_DIGEST = 30

FALLBACK_EXECUTIVE_SUMMARY = (
    "An AI-generated executive summary could not be produced for this audit. "
    "Per-finding enrichment above (where available) and the deterministic "
    "statistics below are unaffected -- see each finding's own detail."
)

_SYSTEM_PROMPT = (
    "You are a network security compliance analyst. You write a concise "
    "executive summary synthesizing the highest-risk themes of a network "
    "segmentation audit, based on aggregate statistics and a "
    "representative, priority-ordered sample of the audit's own findings "
    "-- not the full evidence for every finding, which you are not shown "
    "here.\n\n"
    "- Use only the statistics and findings supplied to you below; never "
    "invent a finding, host, or number not present in what you were given.\n"
    "- The statistics already cover the entire audit, including findings "
    "not individually listed -- ground your synthesis in them, not only in "
    "the sample.\n"
    "- Do not recite exact counts (e.g. 'there are 12 critical findings') "
    "-- those are already shown separately as a deterministic summary. "
    "Focus on which risk themes and patterns matter most and why.\n"
    "- Always respond with a single, valid JSON object matching exactly "
    "the shape described in the user message -- never prose outside that "
    "JSON, never markdown code fences around it. The \"findings\" array "
    "must always be empty: you are synthesizing an overall summary here, "
    "not enriching individual findings."
)


def _digest_line(finding, enrichments_by_id: dict[str, FindingEnrichment]) -> str:
    """One compact line for the finding sample: severity plus the enrichment title
    if present, else the finding's raw destination string."""
    finding_id = finding.get("id", "unknown")
    severity = finding.get("severity", "unknown")
    enrichment = enrichments_by_id.get(finding_id)
    description = enrichment.title if enrichment is not None else finding.get("destination", "unknown")
    return f"- [{severity}] {finding_id}: {description}"


def build_prompt(report: OAEReport, finding_enrichments: tuple[FindingEnrichment, ...]) -> Prompt:
    """Build the compact, whole-audit synthesis prompt.

    finding_enrichments (merged per-finding output) is only used to prefer an
    enrichment's title over the destination string in the digest.
    """
    findings = report.findings
    stats = compute_stats(findings)
    enrichments_by_id = {fe.finding_id: fe for fe in finding_enrichments}

    lines = [
        f"Total findings: {stats.total}",
        "By severity: " + ", ".join(f"{level}={count}" for level, count in stats.by_severity),
        "By category: " + ", ".join(f"{category}={count}" for category, count in stats.by_category),
        "",
    ]

    sample = findings[:MAX_FINDINGS_IN_DIGEST]
    if sample:
        lines.append(f"The {len(sample)} highest-priority findings (of {stats.total} total), for context:")
        lines.extend(_digest_line(f, enrichments_by_id) for f in sample)
        remaining = stats.total - len(sample)
        if remaining > 0:
            lines.append(f"... and {remaining} more lower-priority finding(s) not listed individually.")
    else:
        lines.append("No findings.")

    lines.append("")
    lines.append(
        "Respond with a single JSON object -- no prose outside it, no markdown "
        "code fences -- with exactly this shape:\n\n"
        "{\n"
        '  "executive_summary": "<a concise synthesis of the assessment\'s '
        "highest-risk themes and overall significance across the ENTIRE "
        "audit, not just the sample above. Do not recite finding counts -- "
        'already shown separately. Focus on which patterns matter most and why>",\n'
        '  "findings": []\n'
        "}"
    )

    return Prompt(system=_SYSTEM_PROMPT, user="\n".join(lines), prompt_version="exec-summary-v1")


def synthesize(
    provider: LLMProvider,
    report: OAEReport,
    per_finding_result: EnrichmentResult,
    *,
    logger: logging.Logger,
) -> EnrichmentResult:
    """Replace per_finding_result's batch-scoped executive_summary with a
    whole-audit synthesis, or FALLBACK_EXECUTIVE_SUMMARY on failure.

    Never raises and never touches finding_enrichments. Token/latency metadata
    from this call is summed into the result's metadata (as in
    merge_batch_results()); on failure metadata is left unchanged.
    """
    prompt = build_prompt(report, per_finding_result.finding_enrichments)
    try:
        synthesis = provider.enrich(prompt)
    except EnrichmentError as exc:
        logger.warning(
            "Whole-audit executive summary synthesis failed (%s) -- falling back to a "
            "generic notice; per-finding enrichment above is unaffected.",
            exc,
        )
        return dataclasses.replace(per_finding_result, executive_summary=FALLBACK_EXECUTIVE_SUMMARY)

    merged_metadata = GenerationMetadata(
        provider=per_finding_result.metadata.provider,
        model=per_finding_result.metadata.model,
        prompt_version=per_finding_result.metadata.prompt_version,
        generated_at=per_finding_result.metadata.generated_at,
        latency_ms=sum_optional_float([per_finding_result.metadata.latency_ms, synthesis.metadata.latency_ms]),
        input_tokens=sum_optional_int([per_finding_result.metadata.input_tokens, synthesis.metadata.input_tokens]),
        output_tokens=sum_optional_int([per_finding_result.metadata.output_tokens, synthesis.metadata.output_tokens]),
    )
    return dataclasses.replace(
        per_finding_result, executive_summary=synthesis.executive_summary, metadata=merged_metadata,
    )
