"""ReportDocument and build_report_document(): the shared, deterministic
combination of OAEReport and EnrichmentResult that every renderer formats.

Every field is copied from OAEReport/EnrichmentResult, computed by a fixed
counting rule (ReportStats), or a fixed fallback string used when enrichment is
absent. Nothing is summarized or invented here. Findings are structured
(FindingSection) so renderers can use severity as a typed field.

ReportStats is computed here, not by the LLM. by_category is a best-effort
heuristic based on violated_rules[].rule_id naming and is approximate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from nssa.oae.reporting.context import OAEReport
from nssa.oae.reporting.models import EnrichmentResult, FindingEnrichment

_SEVERITY_ORDER = ("critical", "high", "medium", "low")

_CATEGORY_MANDATORY_TRANSIT = "Mandatory Transit Bypass"
_CATEGORY_GROUP_ISOLATION = "Group Isolation"
_CATEGORY_HOST_SCOPED = "Host-Scoped Access"
_CATEGORY_OTHER = "Other"


@dataclass(frozen=True, slots=True)
class ReportStats:
    """Deterministic counts from OAEReport.findings.

    by_severity lists critical/high/medium/low in order, even at zero; other
    severities go in an extra ("other", N) entry, so total equals the sum.
    by_category is most-common-first (ties alphabetical) and heuristic.
    """

    total: int
    by_severity: tuple[tuple[str, int], ...]
    by_category: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class FindingSection:
    """One finding, structured. Each *_body field is renderer-agnostic text
    ("- " bullets for lists).

    title: enrichment title, or a fixed template ("Unexpected reachability to
        <asset>") if absent.
    summary: enrichment summary, or a fixed fallback sentence.
    impacted_asset: the report's "destination", verbatim.
    violated_rule_ids: violated_rules[].rule_id, verbatim, in report order.
    compliance_control_ids: enrichment framework_mappings as
        "<framework>:<control_id>"; empty if none.

    policy_context is "" when there are no violated_rules; renderers should
    then omit that subsection.
    """

    finding_id: str
    title: str
    summary: str
    severity: str
    impacted_asset: str
    violated_rule_ids: tuple[str, ...]
    compliance_control_ids: tuple[str, ...]
    technical_evidence: str
    policy_context: str
    business_impact: str
    compliance_mappings: str
    recommended_mitigations: str


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Traceability section content, structured so renderers can show it as secondary.

    performed is False when enrichment was skipped or failed; every other field
    is then None. policy_reference identifies the AuditConfiguration (e.g. its
    basename), is independent of the LLM, and is None if not supplied.
    """

    performed: bool
    policy_reference: str | None = None
    provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    generated_at: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ReportDocument:
    """Everything a renderer needs (see build_report_document())."""

    executive_summary: str
    stats: ReportStats
    findings: tuple[FindingSection, ...]
    metadata: ReportMetadata


def build_report_document(
    report: OAEReport, result: EnrichmentResult | None, *, policy_reference: str | None = None,
) -> ReportDocument:
    """Combine *report* and *result* into a ReportDocument.

    result is None when enrichment was skipped or failed; fixed fallback text
    is used then. policy_reference is passed through verbatim into ReportMetadata.
    """
    findings = report.findings
    enrichments_by_id = (
        {fe.finding_id: fe for fe in result.finding_enrichments} if result is not None else {}
    )

    executive_summary = (
        result.executive_summary if result is not None
        else "AI enrichment was not available for this report; findings below reflect NSSA's own deterministic evidence only."
    )

    finding_sections = tuple(
        _build_finding_section(finding, enrichments_by_id.get(finding.get("id", "")), enrichment_attempted=result is not None)
        for finding in findings
    )

    return ReportDocument(
        executive_summary=executive_summary,
        stats=compute_stats(findings),
        findings=finding_sections,
        metadata=_build_metadata(result, policy_reference),
    )


def compute_stats(findings: tuple[Mapping[str, Any], ...]) -> ReportStats:
    """Deterministic finding counts; public so executive_summary reuses the same rule."""
    severity_counts = {level: 0 for level in _SEVERITY_ORDER}
    other_severity = 0
    category_counts: dict[str, int] = {}

    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            other_severity += 1
        category = _infer_category(finding)
        category_counts[category] = category_counts.get(category, 0) + 1

    by_severity = [(level, severity_counts[level]) for level in _SEVERITY_ORDER]
    if other_severity:
        by_severity.append(("other", other_severity))

    by_category = tuple(sorted(category_counts.items(), key=lambda kv: (-kv[1], kv[0])))

    return ReportStats(total=len(findings), by_severity=tuple(by_severity), by_category=by_category)


# Substring of nssa.oae.audit.summary._sentence()'s GROUP_ISOLATION_VIOLATION
# wording, a second signal (besides rule_id) for group isolation. Coupled to
# that phrasing; update both together.
_GROUP_ISOLATION_SUMMARY_MARKER = "violating the intended group isolation policy"


def _infer_category(finding: Mapping[str, Any]) -> str:
    """Best-effort category of a finding from violated_rules[] (approximate).

    Priority: mandatory-transit bypass, then group isolation (rule_id
    IMPLICIT_DEFAULT_DENY or the summary-text marker), then host-scoped.
    """
    violated_rules = finding.get("violated_rules") or []
    rule_ids = [r.get("rule_id", "") for r in violated_rules]
    summaries = [r.get("summary", "") for r in violated_rules]

    if any(rid.startswith("T") and rid[1:].isdigit() for rid in rule_ids):
        return _CATEGORY_MANDATORY_TRANSIT
    if any(rid == "IMPLICIT_DEFAULT_DENY" for rid in rule_ids):
        return _CATEGORY_GROUP_ISOLATION
    if any(_GROUP_ISOLATION_SUMMARY_MARKER in s for s in summaries):
        return _CATEGORY_GROUP_ISOLATION
    if rule_ids:
        return _CATEGORY_HOST_SCOPED
    return _CATEGORY_OTHER


def _build_finding_section(
    finding: Mapping[str, Any], enrichment: FindingEnrichment | None, *, enrichment_attempted: bool,
) -> FindingSection:
    return FindingSection(
        finding_id=finding.get("id", "unknown"),
        title=_title(finding, enrichment),
        summary=_summary_body(enrichment, enrichment_attempted=enrichment_attempted),
        severity=finding.get("severity", "unknown"),
        impacted_asset=_impacted_asset(finding),
        violated_rule_ids=_violated_rule_ids(finding),
        compliance_control_ids=_compliance_control_ids(enrichment),
        technical_evidence=_technical_evidence_body(finding),
        policy_context=_policy_context_body(finding),
        business_impact=_business_impact_body(enrichment, enrichment_attempted=enrichment_attempted),
        compliance_mappings=_compliance_mappings_body(enrichment, enrichment_attempted=enrichment_attempted),
        recommended_mitigations=_recommended_mitigations_body(enrichment, enrichment_attempted=enrichment_attempted),
    )


def _violated_rule_ids(finding: Mapping[str, Any]) -> tuple[str, ...]:
    violated_rules = finding.get("violated_rules") or []
    return tuple(r.get("rule_id", "unknown") for r in violated_rules)


def _compliance_control_ids(enrichment: FindingEnrichment | None) -> tuple[str, ...]:
    if enrichment is None:
        return ()
    return tuple(f"{m.framework}:{m.control_id}" for m in enrichment.framework_mappings)


def _impacted_asset(finding: Mapping[str, Any]) -> str:
    return finding.get("destination") or "Unknown asset"


def _title(finding: Mapping[str, Any], enrichment: FindingEnrichment | None) -> str:
    if enrichment is not None:
        return enrichment.title
    return f"Unexpected reachability to {_impacted_asset(finding)}"


def _technical_evidence_body(finding: Mapping[str, Any]) -> str:
    """destination/source_hosts/representative_paths as given by oae-report.json."""
    lines: list[str] = []

    destination = finding.get("destination")
    if destination:
        lines.append(f"- Destination: {destination}")
    destination_groups = finding.get("destination_groups")
    if destination_groups:
        lines.append(f"- Destination groups: {', '.join(destination_groups)}")

    source_hosts = finding.get("source_hosts")
    if source_hosts:
        lines.append(f"- Source hosts: {', '.join(source_hosts)}")
    source_groups = finding.get("source_groups")
    if source_groups:
        lines.append(f"- Source groups: {', '.join(source_groups)}")

    representative_paths = finding.get("representative_paths")
    if representative_paths:
        lines.append("- Representative paths:")
        lines.extend(f"  - {path}" for path in representative_paths)

    return "\n".join(lines) if lines else "No technical evidence recorded for this finding."


def _policy_context_body(finding: Mapping[str, Any]) -> str:
    """oae-report.json's "violated_rules"; "" when absent so the subsection is omitted."""
    violated_rules = finding.get("violated_rules")
    if not violated_rules:
        return ""
    return "\n".join(f"- {r.get('rule_id', 'unknown')}: {r.get('summary', '')}" for r in violated_rules)


def _summary_body(enrichment: FindingEnrichment | None, *, enrichment_attempted: bool) -> str:
    if enrichment is not None:
        return enrichment.summary
    if enrichment_attempted:
        return "The LLM did not return a summary for this finding."
    return "No AI-generated summary is available for this finding; see technical evidence below."


def _business_impact_body(enrichment: FindingEnrichment | None, *, enrichment_attempted: bool) -> str:
    if enrichment is not None:
        return enrichment.business_impact
    if enrichment_attempted:
        return "The LLM did not return an enrichment for this finding."
    return "No AI-generated business impact assessment is available for this finding."


def _compliance_mappings_body(enrichment: FindingEnrichment | None, *, enrichment_attempted: bool) -> str:
    if enrichment is None:
        return (
            "The LLM did not return an enrichment for this finding."
            if enrichment_attempted
            else "No AI enrichment was available to assess compliance impact for this finding."
        )
    if not enrichment.framework_mappings:
        return "No applicable control from the supplied knowledge base was confidently associated with this finding."

    lines = []
    for mapping in enrichment.framework_mappings:
        title = f" -- {mapping.control_title}" if mapping.control_title else ""
        lines.append(f"- {mapping.framework}:{mapping.control_id}{title}")
        if mapping.rationale:
            lines.append(f"  {mapping.rationale}")
    return "\n".join(lines)


def _recommended_mitigations_body(enrichment: FindingEnrichment | None, *, enrichment_attempted: bool) -> str:
    if enrichment is None:
        return (
            "The LLM did not return an enrichment for this finding."
            if enrichment_attempted
            else "No AI-generated mitigation suggestions are available for this finding."
        )
    if not enrichment.mitigation_suggestions:
        return "No specific mitigation suggestions were provided for this finding."
    return "\n".join(f"- {s}" for s in enrichment.mitigation_suggestions)


def _build_metadata(result: EnrichmentResult | None, policy_reference: str | None) -> ReportMetadata:
    if result is None:
        return ReportMetadata(performed=False, policy_reference=policy_reference)
    metadata = result.metadata
    return ReportMetadata(
        performed=True,
        policy_reference=policy_reference,
        provider=metadata.provider,
        model=metadata.model,
        prompt_version=metadata.prompt_version,
        generated_at=metadata.generated_at,
        latency_ms=metadata.latency_ms,
        input_tokens=metadata.input_tokens,
        output_tokens=metadata.output_tokens,
    )
