"""The canonical prompt shape and the component that builds it.

Prompt is the provider-agnostic type passed to LLMProvider.enrich(); each
adapter only translates it to its own request format. PromptBuilder is
deterministic and side-effect free: it only transforms an EnrichmentContext
into a Prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from nssa.oae.reporting.context import EnrichmentContext

# Bumped whenever the template changes; recorded in EnrichmentResult.metadata.
_PROMPT_VERSION = "v7"

_SYSTEM_PROMPT = (
    "You are a network security compliance analyst. You analyse technical "
    "network segmentation findings produced by an automated assessment tool "
    "and explain their business and compliance significance to a human "
    "auditor.\n\n"
    "You must follow these rules strictly, regardless of which compliance "
    "framework(s) are referenced in a given request -- new frameworks may "
    "be added over time without changing how you are expected to behave:\n"
    "- Use only the evidence supplied to you below; never invent findings, "
    "hosts, paths, rules, or evidence that was not given.\n"
    "- Use only the compliance framework knowledge supplied to you below; "
    "never invent a framework name, control identifier, or control title.\n"
    "- The supplied framework knowledge is a curated knowledge base, not a "
    "mapping already associated with any finding below -- for each finding, "
    "you must determine whether any of these controls applies, using only "
    "what the evidence objectively supports. Never associate a finding with "
    "a control merely because it appears similar or related; if none of the "
    "supplied controls confidently applies, say so explicitly rather than "
    "forcing an association.\n"
    "- When mapping a finding to compliance controls, be selective: include "
    "only the 2-3 controls most directly applicable to that specific "
    "finding, never every control that could plausibly relate. Do not reuse "
    "the same set of controls across unrelated findings merely because they "
    "share a network pattern -- select controls the way a human auditor "
    "would, favouring precision over exhaustive coverage.\n"
    "- Mitigation recommendations must be specific to the finding's actual "
    "policy context, never generic security advice. The supplied policy "
    "context (violated rules) already states what NSSA expects -- an "
    "authorised host, an authorised group, a mandatory transit path -- so "
    "phrase the recommendation in those exact terms: restore the intended "
    "policy, remove the specific unauthorised access, reinstate the "
    "expected isolation, enforce the mandatory transit path, or limit "
    "access to the specific hosts/segments the policy already authorises. "
    "Prefer 'restrict access to <destination> to <the host/group the "
    "policy context names as authorised>' over an unspecific 'configure "
    "firewall rules'.\n"
    "- Vary the business impact framing to fit what a finding's own "
    "evidence actually shows, rather than defaulting to the same generic "
    "phrase (e.g. 'unauthorized access', 'critical systems exposure') for "
    "every finding. Consider whether lateral movement, privilege "
    "escalation, credential compromise, payment data exposure, expansion "
    "of compliance scope, operational disruption, or increased attack "
    "surface genuinely fits this specific finding's evidence, and only use "
    "one if it does -- never force-fit a category that the evidence does "
    "not support.\n"
    "- For each finding, also provide a short, specific, one-line title, in "
    "the style of a vulnerability or issue title (e.g. 'Direct database "
    "access bypassing the authorised application tier') -- never a "
    "restatement of the destination address alone, and never a generic "
    "label like 'Policy Violation'. The title must accurately reflect what "
    "the evidence shows; never imply a fact the evidence does not "
    "support.\n"
    "- For each finding, also provide a short (1-3 sentence) plain-English "
    "summary of what the evidence shows -- distinct from the title (a "
    "headline) and from business_impact (why it matters): the summary "
    "answers 'what happened', in language a reader can act on before "
    "opening the finding's full technical detail. Do not repeat the title "
    "verbatim, and do not restate business impact here.\n"
    "- Never speculate about facts not present in the supplied evidence "
    "(e.g. root cause, intent, or organisational process).\n"
    "- When the supplied evidence or framework knowledge is insufficient to "
    "support a conclusion, state that limitation explicitly rather than "
    "filling the gap with a plausible-sounding guess.\n"
    "- Always respond with a single, valid JSON object matching exactly the "
    "shape described in the user message -- never prose outside that JSON, "
    "never markdown code fences around it."
)


@dataclass(frozen=True, slots=True)
class Prompt:
    """The canonical, provider-agnostic prompt: a system/user split.

    prompt_version identifies the template that produced it and is carried into
    EnrichmentResult.metadata for traceability.
    """

    system: str
    user: str
    prompt_version: str


class PromptBuilder:
    """Builds the one canonical Prompt from an EnrichmentContext.

    Concrete, not a Protocol; only depends on the context it is given. It
    renders a fixed subset of each finding's fields rather than forwarding
    oae-report.json verbatim. It never matches findings to controls: the
    framework knowledge is presented whole, and which control applies is left
    to the LLM.
    """

    def build(self, context: EnrichmentContext) -> Prompt:
        return Prompt(
            system=self._build_system(),
            user=self._build_user(context),
            prompt_version=_PROMPT_VERSION,
        )

    # ── system prompt ────────────────────────────────────────────────

    @staticmethod
    def _build_system() -> str:
        return _SYSTEM_PROMPT

    # ── user prompt ──────────────────────────────────────────────────

    def _build_user(self, context: EnrichmentContext) -> str:
        sections = [
            self._build_findings(context.report.findings),
            self._build_framework_knowledge(context),
            self._build_instructions(),
        ]
        return "\n\n".join(sections)

    def _build_findings(self, findings: tuple[Mapping[str, Any], ...]) -> str:
        if not findings:
            return "Findings: none."
        blocks = [self._build_finding(finding) for finding in findings]
        return "Findings:\n\n" + "\n\n".join(blocks)

    def _build_finding(self, finding: Mapping[str, Any]) -> str:
        """One finding's identity and technical evidence, as in oae-report.json.

        "destination" is already formatted (e.g. "db01 (10.10.40.10):5432/tcp"),
        so it is rendered as given.
        """
        lines = [f'### Finding {finding.get("id", "unknown")} (severity: {finding.get("severity", "unknown")})']

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

        policy = self._build_policy(finding)
        if policy:
            lines.append("")
            lines.append(policy)

        return "\n".join(lines)

    @staticmethod
    def _build_policy(finding: Mapping[str, Any]) -> str | None:
        """The policy context for one finding: its "violated_rules" (rule_id +
        summary), the field that explains why it is a finding.

        None when there are no violated_rules, so the section is omitted.
        """
        violated_rules = finding.get("violated_rules")
        if not violated_rules:
            return None
        lines = ["Policy context (violated rules):"]
        for rule in violated_rules:
            rule_id = rule.get("rule_id", "unknown")
            summary = rule.get("summary", "")
            lines.append(f"- {rule_id}: {summary}")
        return "\n".join(lines)

    @staticmethod
    def _build_framework_knowledge(context: EnrichmentContext) -> str:
        """The requested frameworks and the knowledge base already retrieved for them.

        Framed as a knowledge base to reason over, not a pre-selected mapping.
        Notes when a framework produced no knowledge, so the LLM states that
        limitation.
        """
        if not context.frameworks:
            return "Requested compliance frameworks: none."

        lines = [f"Requested compliance frameworks: {', '.join(context.frameworks)}."]
        if not context.knowledge.snippets:
            lines.append("No framework knowledge is available for these frameworks.")
            return "\n".join(lines)

        lines.append("")
        lines.append(
            "The following controls represent the curated subset of "
            "requirements, across the frameworks above, that NSSA is "
            "technically capable of assessing. This is a knowledge base, "
            "not a pre-selected mapping -- none of these controls has been "
            "associated with any finding below. For each finding, determine "
            "whether any of these controls applies, using only what the "
            "evidence objectively supports. Do not associate a finding with "
            "a control simply because it appears similar. If none of the "
            "supplied controls confidently applies to a finding, state "
            "explicitly that no applicable control from the provided "
            "knowledge base could be confidently associated with it."
        )
        for snippet in context.knowledge.snippets:
            label = f"{snippet.framework}:{snippet.control_id}" if snippet.control_id else snippet.framework
            lines.append(f"\n[{label}]\n{snippet.text.strip()}")
        return "\n".join(lines)

    @staticmethod
    def _build_instructions() -> str:
        """The expected output shape, described in words.

        The provider-agnostic baseline, self-sufficient even for providers
        without native structured output. It mirrors EnrichmentResult: one
        executive_summary and one "findings" entry per finding keyed by
        "finding_id". The summary focuses on synthesis, not counts, which the
        renderer computes deterministically.
        """
        return (
            "Respond with a single JSON object -- no prose outside it, no "
            "markdown code fences -- with exactly this shape:\n\n"
            "{\n"
            '  "executive_summary": "<a concise synthesis of the '
            'assessment'"'"'s highest-risk themes and overall significance. '
            'Do not recite finding counts or list every finding by id -- '
            'that information is already presented separately as a '
            'deterministic summary. Focus on which findings and patterns '
            'matter most and why>",\n'
            '  "findings": [\n'
            "    {\n"
            '      "finding_id": "<the exact \\"id\\" field of a finding '
            'above>",\n'
            '      "title": "<a short, specific, one-line title for this '
            'finding>",\n'
            '      "summary": "<a short, 1-3 sentence plain-English '
            'summary of what the evidence shows>",\n'
            '      "business_impact": "<string>",\n'
            '      "mitigation_suggestions": ["<string>", "..."],\n'
            '      "framework_mappings": [\n'
            "        {\n"
            '          "framework": "<one of the requested frameworks '
            'above>",\n'
            '          "control_id": "<control_id of a control from the '
            'supplied knowledge base>",\n'
            '          "control_title": "<title of that control, or '
            'null>",\n'
            '          "rationale": "<why this control applies to this '
            'finding>"\n'
            "        }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Include exactly one entry in \"findings\" for every finding "
            "listed above, in any order, with \"finding_id\" set to that "
            "finding's own \"id\" field. \"framework_mappings\" must be an "
            "empty array -- never omitted -- for a finding where no "
            "supplied control confidently applies. Limit "
            "\"framework_mappings\" to at most 2-3 entries: the controls "
            "most directly applicable to this specific finding, not every "
            "control that could plausibly relate to it."
        )
