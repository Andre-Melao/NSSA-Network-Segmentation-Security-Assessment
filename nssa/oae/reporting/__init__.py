"""nssa.oae.reporting: the OAE's reporting subsystem.

Turns a deterministic OAE audit report into auditor-facing deliverables: always
a Markdown report (ReportDocument rendered as-is, no LLM), and, only when
authentication.llm is declared, an AI-enriched Markdown/HTML/PDF set produced by
ContextBuilder -> PromptBuilder -> LLMProvider -> build_report_document() ->
renderers. pipeline.run_reporting() is the entry point nssa.oae.cli calls.

The package consumes an already-produced report bundle (OAEReport) and joins
enrichment (EnrichmentResult) by finding_id at render time, never merging it
into the report.

Principles: NSSA produces the technical evidence; a KnowledgeProvider supplies
curated compliance knowledge; the LLM alone decides whether evidence supports a
control association (see FrameworkMapping). No component encodes a
finding-to-control mapping in software. ReportDocument is the one intermediate
representation every renderer formats; renderers never derive from each other's
output.
"""

from __future__ import annotations

from nssa.oae.reporting.context import (
    ContextBuilder,
    EnrichmentContext,
    KnowledgeBundle,
    KnowledgeSnippet,
    OAEReport,
)
from nssa.oae.reporting.contracts import KnowledgeProvider, LLMProvider, Renderer
from nssa.oae.reporting.errors import (
    EnrichmentError,
    KnowledgeProviderError,
    LLMProviderError,
    RenderError,
)
from nssa.oae.reporting.knowledge import LocalKnowledgeProvider
from nssa.oae.reporting.models import (
    EnrichmentResult,
    FindingEnrichment,
    FrameworkMapping,
    GenerationMetadata,
)
from nssa.oae.reporting.prompt import Prompt, PromptBuilder
from nssa.oae.reporting.providers import build_llm_provider
from nssa.oae.reporting.html import HTMLRenderer
from nssa.oae.reporting.markdown import MarkdownRenderer
from nssa.oae.reporting.pdf import PDFRenderer

__all__ = [
    "ContextBuilder",
    "EnrichmentContext",
    "KnowledgeBundle",
    "KnowledgeSnippet",
    "OAEReport",
    "KnowledgeProvider",
    "LLMProvider",
    "Renderer",
    "EnrichmentError",
    "KnowledgeProviderError",
    "LLMProviderError",
    "RenderError",
    "LocalKnowledgeProvider",
    "EnrichmentResult",
    "FindingEnrichment",
    "FrameworkMapping",
    "GenerationMetadata",
    "Prompt",
    "PromptBuilder",
    "build_llm_provider",
    "HTMLRenderer",
    "MarkdownRenderer",
    "PDFRenderer",
]
