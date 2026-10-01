"""run_reporting(): the orchestration entry point the OAE calls.

Turns a just-produced OAE report bundle into auditor-facing deliverables
automatically (see nssa.oae.cli's hook after it writes the raw report JSON).
Always writes a deterministic audit-report.md; when the AuditConfiguration
declares authentication.llm, also runs LLM enrichment and writes
audit-report.md plus audit-report.html/audit-report.pdf.

This module only sequences ContextBuilder, PromptBuilder, build_llm_provider
and the renderers, and owns the file-writing and error-boundary policy.

Error boundary: reporting is additive and never a precondition for the audit.
EnrichmentError, a misconfigured authentication.llm (ValueError), and a missing
optional dependency (ImportError) are caught and logged as warnings. Any other
exception propagates, so real defects are not hidden.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nssa.oae.reporting.batching import BatchOutcome, merge_batch_results, plan_batches
from nssa.oae.reporting.context import ContextBuilder, EnrichmentContext, OAEReport
from nssa.oae.reporting.errors import EnrichmentError
from nssa.oae.reporting.executive_summary import synthesize as synthesize_executive_summary
from nssa.oae.reporting.html import HTMLRenderer
from nssa.oae.reporting.knowledge import LocalKnowledgeProvider
from nssa.oae.reporting.markdown import MarkdownRenderer
from nssa.oae.reporting.models import EnrichmentResult
from nssa.oae.reporting.pdf import PDFRenderer
from nssa.oae.reporting.prompt import PromptBuilder
from nssa.oae.reporting.providers import build_llm_provider
from nssa.oae.reporting.providers._defaults import DEFAULT_MAX_OUTPUT_TOKENS
from nssa.shared.audit_config import AuditConfiguration

DEFAULT_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge_base"


def run_reporting(
    report_bundle: dict[str, Any],
    audit_config: AuditConfiguration | None,
    reports_dir: Path,
    *,
    knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR,
    logger: logging.Logger | None = None,
    policy_reference: str | None = None,
) -> tuple[Path, ...]:
    """Write the auditor-facing report deliverables; return the paths written, in order.

    report_bundle is the dict nssa.oae.cli._build_report_bundle() produces,
    wrapped in-memory as an OAEReport. audit_config is None for a plain SPM
    (only audit-report.md is written, as when authentication.llm is absent).
    policy_reference (e.g. the filename) is forwarded verbatim to every renderer.
    """
    log = logger or logging.getLogger("nssa.oae.reporting")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report = OAEReport(raw=report_bundle)

    markdown_path = reports_dir / "audit-report.md"
    markdown_path.write_bytes(MarkdownRenderer().render(report, None, policy_reference=policy_reference))
    log.info("Deterministic Markdown report written to %s", markdown_path)
    written = (markdown_path,)

    llm_auth = audit_config.authentication.llm if audit_config and audit_config.authentication else None
    if llm_auth is None:
        return written

    try:
        return _run_enrichment_and_render(report, audit_config, reports_dir, knowledge_dir, log, policy_reference)
    except (EnrichmentError, ValueError, ImportError, OSError) as exc:
        log.warning(
            "AI-enriched reporting failed (%s) -- the deterministic audit-report-raw.json/audit-report.md "
            "above are still complete and unaffected.",
            exc,
        )
        return written


def run_enrichment(
    report: OAEReport,
    audit_config: AuditConfiguration,
    *,
    knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR,
    logger: logging.Logger | None = None,
) -> EnrichmentResult | None:
    """Build context, enrich findings in bounded batches, and merge the results.

    Splits the findings into batches (see nssa.oae.reporting.batching), calls
    the LLM provider declared in audit_config.authentication.llm once per
    batch, and merges the successful batches into one EnrichmentResult. With
    more than one batch, executive_summary is replaced by a dedicated
    whole-audit call (see nssa.oae.reporting.executive_summary).

    Returns None only when every batch failed (LLMProviderError/
    KnowledgeProviderError); failed batches' findings render with deterministic
    content.

    Raises ValueError/ImportError for a configuration problem (no
    authentication.llm, unsupported provider, missing api_key/model, missing
    SDK) before any batch is attempted. Callers decide whether that is fatal.
    """
    log = logger or logging.getLogger("nssa.oae.reporting")
    llm_auth = audit_config.authentication.llm if audit_config.authentication else None
    if llm_auth is None:
        raise ValueError("No authentication.llm declared in the AuditConfiguration.")

    provider = build_llm_provider(llm_auth)  # ValueError/ImportError -> caller's responsibility

    knowledge_provider = LocalKnowledgeProvider(knowledge_dir)
    context = ContextBuilder(knowledge_provider).build(report, audit_config)

    max_output_tokens = llm_auth.max_output_tokens or DEFAULT_MAX_OUTPUT_TOKENS
    batches = plan_batches(context.report.findings, max_output_tokens=max_output_tokens)

    log.info(
        "Requesting AI-enriched reporting from %s (model=%s) across %d batch(es) of findings...",
        llm_auth.provider, llm_auth.model, len(batches),
    )

    outcomes: list[BatchOutcome] = []
    for batch_findings in batches:
        finding_ids = tuple(str(f.get("id", "")) for f in batch_findings)
        batch_context = EnrichmentContext(
            report=OAEReport(raw={"audit_findings": batch_findings}),
            frameworks=context.frameworks,
            knowledge=context.knowledge,
        )
        prompt = PromptBuilder().build(batch_context)
        try:
            batch_result = provider.enrich(prompt)
            outcomes.append(BatchOutcome(finding_ids=finding_ids, result=batch_result))
        except EnrichmentError as exc:
            log.warning(
                "LLM enrichment failed for a batch covering %s (%s) -- these findings will "
                "render with NSSA's own deterministic content instead.",
                finding_ids, exc,
            )
            outcomes.append(BatchOutcome(finding_ids=finding_ids, result=None, error=str(exc)))

    result = merge_batch_results(outcomes)
    if result is None:
        log.warning("LLM enrichment failed for every batch -- rendering reports from OAE findings alone.")
        return None

    # A single batch's executive_summary is already whole-audit; reuse it. Only
    # with more than one batch is a dedicated synthesis call needed.
    if len(batches) > 1:
        result = synthesize_executive_summary(provider, context.report, result, logger=log)

    log.info(
        "Enrichment complete: %d/%d finding(s) enriched across %d batch(es).",
        len(result.finding_enrichments), len(context.report.findings), len(batches),
    )
    return result


def _run_enrichment_and_render(
    report: OAEReport,
    audit_config: AuditConfiguration,
    reports_dir: Path,
    knowledge_dir: Path,
    log: logging.Logger,
    policy_reference: str | None,
) -> tuple[Path, ...]:
    result = run_enrichment(report, audit_config, knowledge_dir=knowledge_dir, logger=log)

    # Overwrites the deterministic audit-report.md written earlier, leaving one final file.
    markdown_path = reports_dir / "audit-report.md"
    markdown_path.write_bytes(MarkdownRenderer().render(report, result, policy_reference=policy_reference))
    log.info("Markdown report written to %s", markdown_path)

    html_path = reports_dir / "audit-report.html"
    html_path.write_bytes(HTMLRenderer().render(report, result, policy_reference=policy_reference))
    log.info("HTML report written to %s", html_path)

    try:
        pdf_renderer = PDFRenderer()
    except ImportError as exc:
        log.warning(
            "Could not render audit-report.pdf (%s) -- audit-report.md/audit-report.html were still written.",
            exc,
        )
        return (markdown_path, html_path)

    pdf_path = reports_dir / "audit-report.pdf"
    pdf_path.write_bytes(pdf_renderer.render(report, result, policy_reference=policy_reference))
    log.info("PDF report written to %s", pdf_path)
    return (markdown_path, html_path, pdf_path)
