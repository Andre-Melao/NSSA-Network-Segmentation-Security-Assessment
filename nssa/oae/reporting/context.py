"""Input-side domain models for the LLM enrichment layer, plus ContextBuilder.

OAEReport, KnowledgeSnippet, KnowledgeBundle and EnrichmentContext describe what
ContextBuilder assembles before a Prompt is built. EnrichmentContext is consumed
only by PromptBuilder, so it can gain fields without breaking an LLMProvider or
Renderer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    # Import-cycle guard: contracts.py imports from this module, so
    # KnowledgeProvider is imported here only under TYPE_CHECKING.
    from nssa.oae.reporting.contracts import KnowledgeProvider
    from nssa.shared.audit_config import AuditConfiguration


@dataclass(frozen=True, slots=True)
class OAEReport:
    """Thin, read-only wrapper around a parsed oae-report.json.

    Not a remodeling of the report schema (that stays nssa.oae's concern; see
    nssa.oae.cli._build_report_bundle()). It exists so other code avoids raw
    dict access; everything else stays reachable through .raw. Never copies,
    reshapes or validates the JSON.
    """

    raw: Mapping[str, Any]

    @classmethod
    def from_json(cls, data: bytes | str) -> "OAEReport":
        """Parse *data* (the raw bytes/text of oae-report.json) into an OAEReport."""
        return cls(raw=json.loads(data))

    @property
    def findings(self) -> tuple[Mapping[str, Any], ...]:
        """Each entry of the report's "audit_findings" array, as a raw mapping.

        An entry's identity field is "id" (e.g. "AF-0001"), not "finding_id"; see
        serialize_audit_finding(). FindingEnrichment is keyed by finding_id and
        matched against this "id" at render time.
        """
        return tuple(self.raw.get("audit_findings", ()))


@dataclass(frozen=True, slots=True)
class KnowledgeSnippet:
    """One piece of framework/control knowledge from a KnowledgeProvider (source-agnostic)."""

    framework: str
    control_id: str | None
    text: str
    source: str


@dataclass(frozen=True, slots=True)
class KnowledgeBundle:
    """Everything one KnowledgeProvider.get_context() call returns.

    Wraps snippets today; future fields (framework version, provenance, ...) are
    added here without changing the KnowledgeProvider Protocol.
    """

    snippets: tuple[KnowledgeSnippet, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class EnrichmentContext:
    """Everything PromptBuilder needs beyond the report itself.

    Carries the OAEReport by reference, not a copy. Consumed only by
    PromptBuilder.build(), so it can gain fields freely.
    """

    report: OAEReport
    frameworks: tuple[str, ...]
    knowledge: KnowledgeBundle


class ContextBuilder:
    """Assembles an EnrichmentContext from deterministic NSSA artefacts.

    Pure assembly: the report reference, the requested frameworks, and a
    KnowledgeBundle. Curating what reaches the LLM is PromptBuilder's job.
    """

    def __init__(self, knowledge_provider: "KnowledgeProvider") -> None:
        self._knowledge_provider = knowledge_provider

    def build(self, report: OAEReport, audit_configuration: "AuditConfiguration") -> EnrichmentContext:
        frameworks = self._requested_frameworks(audit_configuration)
        knowledge = self._knowledge_provider.get_context(frameworks, report)
        return EnrichmentContext(report=report, frameworks=frameworks, knowledge=knowledge)

    @staticmethod
    def _requested_frameworks(config: "AuditConfiguration") -> tuple[str, ...]:
        """Frameworks requested for enrichment (Authentication.frameworks); empty if undeclared."""
        if config.authentication is None:
            return ()
        raw = config.authentication.frameworks
        return tuple(raw)
