"""HTMLRenderer: a standalone HTML security-report dashboard.

Formats the shared ReportDocument directly as HTML, not by parsing
MarkdownRenderer's output. Each major section is its own card in a dark
card-based layout.

The theme is dark-only, with no prefers-color-scheme query: WeasyPrint cannot
parse that media query, which made PDFs render light while browsers rendered
dark. One palette keeps HTML and PDF identical.

Findings are a two-tier disclosure: the card (id, severity, title, chips,
summary) is always visible, and the technical sections sit behind a native
<details> toggle (no JavaScript). WeasyPrint renders <details> expanded, so the
PDF shows everything.

Every interpolated value goes through html.escape(), without exception, since
bodies contain untrusted LLM-generated text. _render_field_body() converts the
fixed "- " bullet convention of report.py into <ul>/<li>.
"""

from __future__ import annotations

import html as html_lib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata as _importlib_metadata

from nssa.oae.reporting.context import OAEReport
from nssa.oae.reporting.icons import icon as _icon
from nssa.oae.reporting.models import EnrichmentResult
from nssa.oae.reporting.report import FindingSection, ReportDocument, ReportStats, build_report_document

_SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "other": "Other"}

# Inline SVG (nssa.oae.reporting.icons) instead of emoji, whose font coverage is
# unreliable across renderers. Colour is not passed: the icon inherits
# currentColor from a CSS-coloured ancestor.
_SEVERITY_ICONS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "other": "low"}

# CSS classes exist only for the four canonical severities; "other" gets no colour.
_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

# Em dash placeholder for an empty finding-attribute column, so the 4-column layout holds.
_NO_VALUE = '<span class="finding-attr-empty">—</span>'


def _tool_version() -> str:
    """The installed 'nssa' package version, or "unknown" if no metadata is available."""
    try:
        return _importlib_metadata.version("nssa")
    except _importlib_metadata.PackageNotFoundError:
        return "unknown"


def _format_timestamp(iso_string: str) -> str:
    """"19 Jul 2026 . 19:53 UTC" from an ISO-8601 string; returns the raw string if unparseable."""
    try:
        dt = datetime.fromisoformat(iso_string).astimezone(timezone.utc)
    except ValueError:
        return iso_string
    return f"{dt.strftime('%d %b %Y')} • {dt.strftime('%H:%M')} UTC"


@dataclass
class _Bullet:
    text: str
    continuations: list[str] = field(default_factory=list)
    nested: list[str] = field(default_factory=list)


class HTMLRenderer:
    """Implements Renderer (content_type "text/html"); deterministic for the same input."""

    @property
    def content_type(self) -> str:
        return "text/html"

    def render(
        self, report: OAEReport, result: EnrichmentResult | None, *, policy_reference: str | None = None,
    ) -> bytes:
        return self.render_html(report, result, policy_reference=policy_reference).encode("utf-8")

    def render_html(
        self, report: OAEReport, result: EnrichmentResult | None, *, policy_reference: str | None = None,
    ) -> str:
        """Same content as render(), as a str; reused by PDFRenderer."""
        document = build_report_document(report, result, policy_reference=policy_reference)
        body_html = "\n".join([
            self._render_header(document),
            self._render_stats_section(document.stats),
            self._render_executive_summary(document),
            self._render_findings_section(document.findings),
            self._render_metadata(document),
        ])
        return _DOCUMENT_TEMPLATE.format(body=body_html)

    # ── report header ────────────────────────────────────────────────

    def _render_header(self, document: ReportDocument) -> str:
        generated = _format_timestamp(document.metadata.generated_at) if document.metadata.generated_at else None
        info_rows = [
            self._info_row("Generated", generated),
            self._info_row("Policy Reference", document.metadata.policy_reference),
        ]

        return (
            '<div class="report-header">'
            '<div class="report-header-main">'
            '<div class="brand-mark">NSSA</div>'
            '<div class="report-title">Network Segmentation Security Assessment Report</div>'
            '<div class="report-subtitle">Assessment of network segmentation policy enforcement.</div>'
            "</div>"
            '<div class="info-panel">'
            '<div class="info-panel-title">Report Information</div>'
            f'<dl class="info-panel-list">{"".join(info_rows)}</dl>'
            "</div>"
            "</div>"
        )

    @staticmethod
    def _info_row(label: str, value: str | None) -> str:
        if not value:
            return ""
        return (
            f'<div class="info-row"><dt>{html_lib.escape(label)}</dt>'
            f"<dd>{html_lib.escape(value)}</dd></div>"
        )

    # ── section heading (page-level, not a card) ────────────────────

    @staticmethod
    def _render_section_heading(icon_name: str, title: str) -> str:
        return (
            '<div class="section-heading">'
            f'<span class="section-heading-icon">{_icon(icon_name, size=17)}</span>'
            f"<span>{html_lib.escape(title)}</span>"
            "</div>"
        )

    # ── statistics ───────────────────────────────────────────────────

    def _render_stats_section(self, stats: ReportStats) -> str:
        cells = [self._render_stat_card("total", "total", "Total Findings", stats.total)]
        for level, count in stats.by_severity:
            icon_name = _SEVERITY_ICONS.get(level, _SEVERITY_ICONS["other"])
            label = _SEVERITY_LABELS.get(level, level.title())
            cells.append(self._render_stat_card(level, icon_name, label, count))
        return (
            self._render_section_heading("stats", "Statistics")
            + f'<div class="stats-grid">{"".join(cells)}</div>'
        )

    @staticmethod
    def _render_stat_card(css_class: str, icon_name: str, label: str, value: int) -> str:
        known_class = css_class if css_class in _KNOWN_SEVERITIES or css_class == "total" else ""
        return (
            f'<div class="stat-card {known_class}">'
            f'<div class="stat-icon">{_icon(icon_name, size=19)}</div>'
            f'<div class="stat-label">{html_lib.escape(label)}</div>'
            f'<div class="stat-value">{value}</div>'
            "</div>"
        )

    # ── executive summary ───────────────────────────────────────────

    def _render_executive_summary(self, document: ReportDocument) -> str:
        return (
            '<div class="card">'
            f'<div class="card-title"><span class="card-title-icon">{_icon("summary", size=18)}</span>'
            "<span>Executive Summary</span></div>"
            f'<div class="card-body">{html_lib.escape(document.executive_summary)}</div>'
            "</div>"
        )

    # ── findings ─────────────────────────────────────────────────────

    def _render_findings_section(self, findings: tuple[FindingSection, ...]) -> str:
        heading = self._render_section_heading("findings", "Findings")
        if not findings:
            return heading + '<div class="card"><div class="card-body">No findings were identified during this audit.</div></div>'
        cards = "\n".join(self._render_finding_card(finding) for finding in findings)
        return heading + f'<div class="findings-list">{cards}</div>'

    def _render_finding_card(self, finding: FindingSection) -> str:
        css_class = finding.severity if finding.severity in _KNOWN_SEVERITIES else ""
        badge_label = html_lib.escape(_SEVERITY_LABELS.get(finding.severity, finding.severity.title()))
        severity_icon = _SEVERITY_ICONS.get(finding.severity, _SEVERITY_ICONS["other"])

        # Structured columns for scanning before expanding. Labels match the
        # Technical Details sections word for word. Category is not shown (see
        # FindingSection).
        rule_chips = "".join(f'<span class="rule-chip">{html_lib.escape(r)}</span>' for r in finding.violated_rule_ids) or _NO_VALUE
        control_chips = "".join(f'<span class="control-chip">{html_lib.escape(c)}</span>' for c in finding.compliance_control_ids) or _NO_VALUE
        attributes = (
            self._render_attribute("asset", "Impacted Asset", html_lib.escape(finding.impacted_asset))
            + self._render_attribute("policy_context", "Violated Policy Rules", rule_chips)
            + self._render_attribute("compliance", "Affected Compliance Controls", control_chips)
            + self._render_attribute(severity_icon, "Severity", f'<span class="badge {css_class}">{badge_label}</span>')
        )

        detail_sections = self._render_detail_section("technical_evidence", "Technical Evidence", finding.technical_evidence)
        if finding.policy_context:
            detail_sections += self._render_detail_section("policy_context", "Violated Policy Rules", finding.policy_context)
        detail_sections += self._render_detail_section("business_impact", "Business Impact", finding.business_impact)
        detail_sections += self._render_detail_section("compliance", "Affected Compliance Controls", finding.compliance_mappings)
        detail_sections += self._render_detail_section("mitigations", "Recommended Mitigations", finding.recommended_mitigations)

        return (
            f'<div class="finding-card {css_class}">'
            f'<span class="finding-id">{html_lib.escape(finding.finding_id)}</span>'
            f'<div class="finding-title">{html_lib.escape(finding.title)}</div>'
            f'<div class="finding-summary">{html_lib.escape(finding.summary)}</div>'
            '<div class="finding-divider"></div>'
            f'<div class="finding-attributes">{attributes}</div>'
            '<details class="tech-details">'
            '<summary class="tech-details-toggle">'
            '<span class="chevron">▸</span><span>Show Technical Details</span>'
            "</summary>"
            f'<div class="tech-details-body">{detail_sections}</div>'
            "</details>"
            "</div>"
        )

    @staticmethod
    def _render_attribute(icon_name: str, label: str, value_html: str) -> str:
        return (
            '<div class="finding-attr">'
            f'<div class="finding-attr-label">{_icon(icon_name, size=12)}<span>{html_lib.escape(label)}</span></div>'
            f'<div class="finding-attr-value">{value_html}</div>'
            "</div>"
        )

    @staticmethod
    def _render_detail_section(icon_name: str, label: str, body: str) -> str:
        return (
            '<div class="detail-section">'
            f'<div class="detail-section-title"><span>{_icon(icon_name, size=14)}</span><span>{html_lib.escape(label)}</span></div>'
            f"{_render_field_body(body)}"
            "</div>"
        )

    # ── report metadata (de-emphasised, always last) ────────────────

    def _render_metadata(self, document: ReportDocument) -> str:
        metadata = document.metadata
        tool_version_item = f"<span>Tool version: {html_lib.escape(_tool_version())}</span>"
        if not metadata.performed:
            return (
                '<details class="metadata-toggle">'
                "<summary>Report generation details</summary>"
                '<div class="metadata-provenance">All findings and technical evidence in this report '
                "were generated by NSSA from observed network behaviour. AI enrichment was not "
                "performed for this report -- no LLM-added content (summaries, business impact, "
                "compliance mappings, mitigations) is present.</div>"
                f'<div class="metadata-block">{tool_version_item}</div>'
                "</details>"
            )

        parts = [
            f"Provider: {html_lib.escape(metadata.provider or '')}",
            f"Model: {html_lib.escape(metadata.model or '')}",
            f"Prompt version: {html_lib.escape(metadata.prompt_version or '')}",
        ]
        if metadata.generated_at:
            parts.append(f"Generated at: {html_lib.escape(_format_timestamp(metadata.generated_at))}")
        if metadata.latency_ms is not None:
            parts.append(f"Latency: {metadata.latency_ms:.0f} ms")
        if metadata.input_tokens is not None or metadata.output_tokens is not None:
            parts.append(f"Tokens: {metadata.input_tokens or 0} in / {metadata.output_tokens or 0} out")

        items = "".join(f"<span>{p}</span>" for p in parts) + tool_version_item
        return (
            '<details class="metadata-toggle">'
            "<summary>Report generation details</summary>"
            '<div class="metadata-provenance">All findings and technical evidence in this report were '
            "generated by NSSA from observed network behaviour. Only the executive summary, each "
            "finding's summary, business impact assessment, compliance mappings, and mitigation "
            f"suggestions were added by the model below.</div>"
            f'<div class="metadata-block">{items}</div>'
            "</details>"
        )


def _parse_bullets(text: str) -> list[_Bullet] | None:
    """Recognise report.py's "- " bullet convention; None for plain prose (no top-level "- " line)."""
    lines = text.split("\n")
    if not any(line.startswith("- ") for line in lines):
        return None

    bullets: list[_Bullet] = []
    for line in lines:
        if line.startswith("- "):
            bullets.append(_Bullet(text=line[2:]))
        elif line.startswith("  - ") and bullets:
            bullets[-1].nested.append(line[4:])
        elif line.strip() and bullets:
            bullets[-1].continuations.append(line.strip())
    return bullets


def _render_field_body(text: str) -> str:
    if not text:
        return ""
    bullets = _parse_bullets(text)
    if bullets is None:
        return f"<p>{html_lib.escape(text)}</p>"

    items = []
    for bullet in bullets:
        item_html = html_lib.escape(bullet.text)
        item_html += "".join(f'<div class="bullet-note">{html_lib.escape(c)}</div>' for c in bullet.continuations)
        if bullet.nested:
            item_html += "<ul>" + "".join(f"<li>{html_lib.escape(n)}</li>" for n in bullet.nested) + "</ul>"
        items.append(f"<li>{item_html}</li>")
    return "<ul>" + "".join(items) + "</ul>"


_DOCUMENT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Segmentation Security Assessment Report</title>
<style>
""" + """
:root {{
  --bg:            #0B0F17;
  --surface:       #131A26;
  --surface-2:     #1B2434;
  --border:        #26314A;
  --text:          #E7ECF7;
  --text-muted:    #97A3BF;
  --text-micro:    #6B7794;
  --accent:        #5B8DFF;
  --accent-bg:     #16233D;
  --mono-bg:       #1B2434;

  --critical:        #FF6785;
  --critical-bg:     #2B0F1B;
  --critical-border: #5A2438;

  --high:          #FFA24E;
  --high-bg:       #2B1A0A;
  --high-border:   #5A3A14;

  --medium:        #FFD666;
  --medium-bg:     #2A230A;
  --medium-border: #574813;

  --low:           #4ADE9B;
  --low-bg:        #0C2A1E;
  --low-border:    #16523A;

  --rule-chip:            #E3A64B;
  --rule-chip-bg:         #2A2008;
  --rule-chip-border:     #574417;
  --control-chip:         #4FD1B8;
  --control-chip-bg:      #0B2622;
  --control-chip-border:  #164A40;

  --radius:        14px;
  --font-body:     system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
  --font-mono:     ui-monospace, 'SF Mono', 'Cascadia Code', Consolas, 'Liberation Mono', monospace;
}}

* , *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  font-size: 15px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}}
.dashboard {{ max-width: 1120px; margin: 0 auto; padding: 40px 28px 100px; display: flex; flex-direction: column; gap: 26px; }}

/* ── report header ─────────────────────────────────────────── */
.report-header {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 32px;
  flex-wrap: wrap;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 34px 38px;
}}
.report-header-main {{ min-width: 280px; flex: 1 1 460px; }}
.brand-mark {{
  font-family: var(--font-mono);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.2em;
  color: var(--accent);
  margin-bottom: 12px;
}}
.report-title {{ font-size: 25px; font-weight: 800; letter-spacing: -0.01em; line-height: 1.3; margin-bottom: 14px; }}
.report-subtitle {{ font-size: 14.5px; color: var(--text-muted); max-width: 52ch; line-height: 1.6; }}

.info-panel {{
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 24px;
  min-width: 240px;
  flex: 0 1 280px;
}}
.info-panel-title {{
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-micro);
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 1px solid var(--border);
}}
.info-panel-list {{ display: flex; flex-direction: column; gap: 8px; }}
.info-row {{ display: flex; justify-content: space-between; gap: 16px; font-size: 12.5px; }}
.info-row dt {{ color: var(--text-micro); }}
.info-row dd {{ color: var(--text); font-family: var(--font-mono); text-align: right; }}

/* ── section heading (page-level) ─────────────────────────────── */
.section-heading {{
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
}}
.section-heading-icon {{ font-size: 17px; }}

/* ── cards (generic) ──────────────────────────────────────────── */
.card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 26px 28px;
}}
.card-title {{ display: flex; align-items: center; gap: 10px; font-size: 16px; font-weight: 700; margin-bottom: 14px; }}
.card-title-icon {{ font-size: 18px; }}
.card-body {{ font-size: 14.5px; color: var(--text-muted); line-height: 1.75; }}

/* ── statistics ────────────────────────────────────────────────── */
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 14px;
}}
.stat-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-top: 3px solid var(--border);
  border-radius: 12px;
  padding: 20px 20px 18px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}}
.stat-icon {{ font-size: 19px; }}
.stat-label {{
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-muted);
}}
.stat-value {{ font-size: 36px; font-weight: 800; font-variant-numeric: tabular-nums; line-height: 1; letter-spacing: -0.02em; }}
.stat-card.total     {{ border-top-color: var(--accent); }}
.stat-card.total     .stat-value, .stat-card.total     .stat-icon {{ color: var(--accent); }}
.stat-card.critical  {{ border-top-color: var(--critical); }}
.stat-card.critical  .stat-value, .stat-card.critical  .stat-icon {{ color: var(--critical); }}
.stat-card.high      {{ border-top-color: var(--high); }}
.stat-card.high      .stat-value, .stat-card.high      .stat-icon {{ color: var(--high); }}
.stat-card.medium    {{ border-top-color: var(--medium); }}
.stat-card.medium    .stat-value, .stat-card.medium    .stat-icon {{ color: var(--medium); }}
.stat-card.low       {{ border-top-color: var(--low); }}
.stat-card.low       .stat-value, .stat-card.low       .stat-icon {{ color: var(--low); }}

/* ── findings ──────────────────────────────────────────────────── */
.findings-list {{ display: flex; flex-direction: column; gap: 16px; }}
.finding-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 4px solid var(--border);
  border-radius: var(--radius);
  padding: 24px 28px;
  break-inside: avoid;
  page-break-inside: avoid;
}}
.finding-card.critical {{ border-left-color: var(--critical); }}
.finding-card.high     {{ border-left-color: var(--high); }}
.finding-card.medium   {{ border-left-color: var(--medium); }}
.finding-card.low      {{ border-left-color: var(--low); }}

.finding-id {{ font-family: var(--font-mono); font-size: 12px; letter-spacing: 0.05em; color: var(--text-micro); display: block; margin-bottom: 8px; }}
.finding-title {{ font-size: 19px; font-weight: 700; line-height: 1.35; margin-bottom: 10px; }}

.badge {{
  display: inline-block;
  font-size: 10px;
  font-family: var(--font-mono);
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 3px 9px;
  border-radius: 4px;
}}
.badge.critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }}
.badge.high     {{ background: var(--high-bg);     color: var(--high);     border: 1px solid var(--high-border); }}
.badge.medium   {{ background: var(--medium-bg);   color: var(--medium);   border: 1px solid var(--medium-border); }}
.badge.low      {{ background: var(--low-bg);      color: var(--low);      border: 1px solid var(--low-border); }}

.finding-divider {{ height: 1px; background: var(--border); margin-bottom: 18px; }}
.finding-summary {{ font-size: 14.5px; color: var(--text); line-height: 1.65; margin-bottom: 16px; }}

/* ── finding attributes: structured columns, replacing the earlier
   inline chip row -- see _render_finding_card()'s own comment for why
   Category never reappears here. ─────────────────────────────────── */
.finding-attributes {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 18px;
  margin-bottom: 4px;
}}
.finding-attr-label {{
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--text-micro);
  margin-bottom: 8px;
}}
.finding-attr-value {{ display: flex; flex-wrap: wrap; gap: 6px; font-size: 13px; color: var(--text); }}
.finding-attr-empty {{ color: var(--text-micro); font-family: var(--font-mono); }}
.rule-chip, .control-chip {{
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  border-radius: 4px;
  padding: 3px 8px;
}}
.rule-chip {{ color: var(--rule-chip); background: var(--rule-chip-bg); border: 1px solid var(--rule-chip-border); }}
.control-chip {{ color: var(--control-chip); background: var(--control-chip-bg); border: 1px solid var(--control-chip-border); }}

.tech-details-toggle {{
  cursor: pointer;
  list-style: none;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 12.5px;
  font-weight: 700;
  color: var(--accent);
}}
.tech-details-toggle::-webkit-details-marker {{ display: none; }}
.tech-details-toggle::marker {{ content: ""; }}
.tech-details-toggle .chevron {{ display: inline-block; transition: transform 0.15s ease; }}
.tech-details[open] .tech-details-toggle .chevron {{ transform: rotate(90deg); }}

.tech-details-body {{ margin-top: 18px; }}
.detail-section {{ padding-top: 16px; }}
.detail-section + .detail-section {{ border-top: 1px solid var(--border); margin-top: 16px; }}
.detail-section-title {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11.5px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 10px;
}}
.detail-section .card-body,
.detail-section p {{ font-size: 13.5px; color: var(--text-muted); line-height: 1.6; margin: 0; }}
.detail-section ul {{ list-style: none; padding-left: 0; font-size: 13.5px; color: var(--text-muted); line-height: 1.6; }}
.detail-section ul ul {{ padding-left: 18px; margin-top: 4px; }}
.detail-section li {{ position: relative; padding-left: 14px; margin-bottom: 6px; }}
.detail-section li::before {{ content: "\\2013"; position: absolute; left: 0; color: var(--text-micro); }}
.detail-section .bullet-note {{ padding-left: 14px; margin-top: 2px; color: var(--text-micro); font-size: 12.5px; }}

/* ── report metadata (de-emphasised, always last) ─────────────── */
.metadata-toggle {{ padding-top: 6px; }}
.metadata-toggle summary {{
  cursor: pointer;
  list-style: none;
  font-size: 11px;
  font-family: var(--font-mono);
  letter-spacing: 0.06em;
  color: var(--text-micro);
}}
.metadata-toggle summary::-webkit-details-marker {{ display: none; }}
.metadata-toggle summary::marker {{ content: ""; }}
.metadata-provenance {{
  margin-top: 12px;
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.6;
  max-width: 70ch;
}}
.metadata-block {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px 18px;
  margin-top: 12px;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-micro);
}}

@media (max-width: 720px) {{
  .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
  .report-header {{ flex-direction: column; }}
  .finding-attributes {{ grid-template-columns: repeat(2, 1fr); }}
}}

@media print {{
  .tech-details-toggle .chevron {{ display: none; }}
  .tech-details-toggle {{ cursor: default; }}
  .metadata-toggle summary {{ cursor: default; }}
}}
""" + """
</style>
</head>
<body>
<div class="dashboard">
{body}
</div>
</body>
</html>
"""
