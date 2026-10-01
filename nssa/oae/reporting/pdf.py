"""PDFRenderer: a static, print-optimised audit document.

Renders from the same ReportDocument as HTMLRenderer but builds independent
markup: HTML is for interactive exploration, this is a linear, paginated,
printable document with nothing collapsed.

No flexbox or CSS grid is used in the page flow: WeasyPrint fragments a flex
child across a page break incorrectly and silently drops the rest of an
oversized finding. Findings are plain block boxes (break-inside: avoid) and the
statistics are a plain <table>.

The background is light by design (legibility, ink, scanning); severity colours
are accents tuned for white. Icons are inline SVGs with colour passed
explicitly, since WeasyPrint does not inherit CSS `color` into
stroke="currentColor".

weasyprint is imported in __init__, so nssa.oae.reporting stays importable
without it (see the "reporting-pdf" extra).
"""

from __future__ import annotations

import html as html_lib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata as _importlib_metadata

from nssa.oae.reporting.context import OAEReport
from nssa.oae.reporting.errors import RenderError
from nssa.oae.reporting.icons import icon
from nssa.oae.reporting.models import EnrichmentResult
from nssa.oae.reporting.report import FindingSection, ReportDocument, ReportStats, build_report_document

_SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "other": "Other"}
_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

# Hex values tuned for contrast against a WHITE page (not the dark HTML palette).
_SEVERITY_COLOR = {
    "critical": "#B0123A",
    "high": "#B65C00",
    "medium": "#93720A",
    "low": "#157A4F",
    "other": "#55607A",
}
_TEXT_MUTED = "#55607A"

# Em dash placeholder for an empty attribute column (see html.py _NO_VALUE; not imported).
_NO_VALUE = '<span class="attr-empty">—</span>'


def _tool_version() -> str:
    """The installed 'nssa' package version (duplicated from html.py; renderers do not share code)."""
    try:
        return _importlib_metadata.version("nssa")
    except _importlib_metadata.PackageNotFoundError:
        return "unknown"


def _format_timestamp(iso_string: str) -> str:
    """See html.py _format_timestamp() (duplicated, not imported)."""
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


class PDFRenderer:
    """Implements Renderer (content_type "application/pdf").

    Renders from the shared ReportDocument. The HTML is deterministic, but the
    PDF bytes are not byte-identical across calls: WeasyPrint's font subsetting
    embeds a timestamp. The content is unaffected.
    """

    def __init__(self) -> None:
        try:
            import weasyprint
        except ImportError as exc:
            raise ImportError(
                "The 'weasyprint' package is required to render PDF reports -- "
                "install it via the 'reporting-pdf' extra: pip install nssa[reporting-pdf]"
            ) from exc
        self._weasyprint = weasyprint

    @property
    def content_type(self) -> str:
        return "application/pdf"

    def render(
        self, report: OAEReport, result: EnrichmentResult | None, *, policy_reference: str | None = None,
    ) -> bytes:
        document = build_report_document(report, result, policy_reference=policy_reference)
        html_string = _render_print_html(document)
        try:
            return self._weasyprint.HTML(string=html_string).write_pdf()
        except Exception as exc:
            raise RenderError(f"Could not render PDF: {exc}") from exc


def _render_print_html(document: ReportDocument) -> str:
    body = "\n".join([
        _render_header(document),
        _render_stats_table(document.stats),
        _render_executive_summary(document),
        _render_findings(document.findings),
        _render_metadata(document),
    ])
    return _DOCUMENT_TEMPLATE.format(body=body)


def _render_header(document: ReportDocument) -> str:
    meta_parts = []
    if document.metadata.generated_at:
        meta_parts.append(f"Generated: {html_lib.escape(_format_timestamp(document.metadata.generated_at))}")
    if document.metadata.policy_reference:
        meta_parts.append(f"Policy Reference: {html_lib.escape(document.metadata.policy_reference)}")
    meta_html = f'<div class="header-meta">{" &nbsp;&middot;&nbsp; ".join(meta_parts)}</div>' if meta_parts else ""
    return (
        '<div class="header">'
        '<div class="brand">NSSA</div>'
        "<h1>Network Segmentation Security Assessment Report</h1>"
        '<div class="subtitle">Assessment of network segmentation policy enforcement.</div>'
        f"{meta_html}"
        "</div>"
    )


def _render_stats_table(stats: ReportStats) -> str:
    cells = [_stat_cell("total", "Total", stats.total, color=_TEXT_MUTED)]
    for level, count in stats.by_severity:
        label = _SEVERITY_LABELS.get(level, level.title())
        color = _SEVERITY_COLOR.get(level, _SEVERITY_COLOR["other"])
        cells.append(_stat_cell(level, label, count, color=color))
    return f'<table class="stats-table"><tr>{"".join(cells)}</tr></table>'


def _stat_cell(css_class: str, label: str, value: int, *, color: str) -> str:
    icon_name = css_class if css_class in _KNOWN_SEVERITIES else "total"
    return (
        f'<td class="stat {css_class}">'
        f'<div class="stat-icon">{icon(icon_name, size=15, color=color)}</div>'
        f'<div class="stat-label">{html_lib.escape(label)}</div>'
        f'<div class="stat-value" style="color:{color}">{value}</div>'
        "</td>"
    )


def _render_executive_summary(document: ReportDocument) -> str:
    return (
        '<div class="section">'
        f'<div class="section-title">{icon("summary", size=13, color=_TEXT_MUTED)} Executive Summary</div>'
        f'<div class="section-body">{html_lib.escape(document.executive_summary)}</div>'
        "</div>"
    )


def _render_findings(findings: tuple[FindingSection, ...]) -> str:
    header = f'<div class="section-title">{icon("findings", size=13, color=_TEXT_MUTED)} Findings</div>'
    if not findings:
        return header + '<div class="section-body">No findings were identified during this audit.</div>'
    cards = "\n".join(_render_finding(f) for f in findings)
    return header + cards


def _render_finding(finding: FindingSection) -> str:
    css_class = finding.severity if finding.severity in _KNOWN_SEVERITIES else ""
    color = _SEVERITY_COLOR.get(finding.severity, _SEVERITY_COLOR["other"])
    badge_label = html_lib.escape(_SEVERITY_LABELS.get(finding.severity, finding.severity.title()))

    # Structured columns as in HTMLRenderer, in a <table> (not grid) for
    # pagination safety. Labels match the Technical Details sections.
    rule_chips = "".join(f'<span class="rule-chip">{html_lib.escape(r)}</span>' for r in finding.violated_rule_ids) or _NO_VALUE
    control_chips = "".join(f'<span class="control-chip">{html_lib.escape(c)}</span>' for c in finding.compliance_control_ids) or _NO_VALUE
    severity_value = f'<span class="badge" style="color:{color};border-color:{color}">{badge_label}</span>'
    attributes = (
        '<table class="finding-attributes"><tr>'
        f'{_attr_cell("Impacted Asset", html_lib.escape(finding.impacted_asset))}'
        f'{_attr_cell("Violated Policy Rules", rule_chips)}'
        f'{_attr_cell("Affected Compliance Controls", control_chips)}'
        f'{_attr_cell("Severity", severity_value)}'
        "</tr></table>"
    )

    details = _detail_section("technical_evidence", "Technical Evidence", finding.technical_evidence)
    if finding.policy_context:
        details += _detail_section("policy_context", "Violated Policy Rules", finding.policy_context)
    details += _detail_section("business_impact", "Business Impact", finding.business_impact)
    details += _detail_section("compliance", "Affected Compliance Controls", finding.compliance_mappings)
    details += _detail_section("mitigations", "Recommended Mitigations", finding.recommended_mitigations)

    return (
        f'<div class="finding {css_class}">'
        f'<span class="finding-id">{html_lib.escape(finding.finding_id)}</span>'
        f'<div class="finding-title">{html_lib.escape(finding.title)}</div>'
        f'<div class="finding-summary">{html_lib.escape(finding.summary)}</div>'
        f"{attributes}"
        f"{details}"
        "</div>"
    )


def _attr_cell(label: str, value_html: str) -> str:
    return (
        '<td class="attr-cell">'
        f'<div class="attr-label">{html_lib.escape(label)}</div>'
        f'<div class="attr-value">{value_html}</div>'
        "</td>"
    )


def _detail_section(icon_name: str, label: str, body: str) -> str:
    return (
        '<div class="detail">'
        f'<div class="detail-title">{icon(icon_name, size=11, color=_TEXT_MUTED)} {html_lib.escape(label)}</div>'
        f'<div class="detail-body">{_render_field_body(body)}</div>'
        "</div>"
    )


def _render_metadata(document: ReportDocument) -> str:
    metadata = document.metadata
    tool_version_part = f"Tool version: {html_lib.escape(_tool_version())}"
    if not metadata.performed:
        return (
            '<div class="metadata">'
            "<div>All findings and technical evidence in this report were generated by NSSA from "
            "observed network behaviour. AI enrichment was not performed for this report -- no "
            "LLM-added content (summaries, business impact, compliance mappings, mitigations) is "
            "present.</div>"
            f'<div class="metadata-fields">{tool_version_part}</div>'
            "</div>"
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
    parts.append(tool_version_part)

    return (
        '<div class="metadata">'
        "<div>All findings and technical evidence in this report were generated by NSSA from "
        "observed network behaviour. Only the executive summary, each finding's summary, business "
        "impact assessment, compliance mappings, and mitigation suggestions were added by the "
        "model below.</div>"
        f'<div class="metadata-fields">{" &nbsp;&middot;&nbsp; ".join(parts)}</div>'
        "</div>"
    )


def _parse_bullets(text: str) -> list[_Bullet] | None:
    """Recognise report.py's "- " bullet convention (duplicated from html.py); None for plain prose."""
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
<title>Network Segmentation Security Assessment Report</title>
<style>
""" + """
@page {{
  size: A4;
  margin: 20mm 18mm 22mm;
  @bottom-right {{
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'DejaVu Sans Mono', monospace;
    font-size: 9px;
    color: #9098AC;
  }}
}}

* , *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: #FFFFFF;
  color: #1A2233;
  font-family: 'DejaVu Sans', Helvetica, Arial, sans-serif;
  font-size: 10.5pt;
  line-height: 1.5;
}}

/* No flexbox, no CSS grid, anywhere in this stylesheet -- see this
   module's own docstring for why that is load-bearing for correct
   pagination, not a style preference. */

.header {{ border-bottom: 2px solid #1A2233; padding-bottom: 10pt; margin-bottom: 16pt; }}
.brand {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 9pt; font-weight: bold; letter-spacing: 0.15em; color: #2454C7; margin-bottom: 6pt; }}
.header h1 {{ font-size: 18pt; font-weight: bold; margin-bottom: 6pt; }}
.header .subtitle {{ font-size: 9.5pt; color: #55607A; margin-bottom: 8pt; }}
.header .header-meta {{ font-size: 8.5pt; color: #808AA0; font-family: 'DejaVu Sans Mono', monospace; }}

.stats-table {{ width: 100%; border-collapse: collapse; margin-bottom: 18pt; table-layout: fixed; }}
.stats-table td.stat {{ border: 1px solid #E1E4EA; padding: 8pt 10pt; width: 20%; vertical-align: top; }}
.stat-icon {{ margin-bottom: 4pt; }}
.stat-label {{ font-size: 7.5pt; font-weight: bold; letter-spacing: 0.06em; text-transform: uppercase; color: #55607A; margin-bottom: 3pt; }}
.stat-value {{ font-size: 18pt; font-weight: bold; }}

.section {{ margin-bottom: 16pt; }}
.section-title {{
  font-size: 10pt; font-weight: bold; letter-spacing: 0.04em; text-transform: uppercase;
  color: #1A2233; border-bottom: 1px solid #E1E4EA; padding-bottom: 4pt; margin-bottom: 8pt;
}}
.section-title svg {{ vertical-align: -2pt; margin-right: 3pt; }}
.section-body {{ font-size: 10pt; color: #303A50; }}

.finding {{
  border: 1px solid #E1E4EA;
  border-left: 3pt solid #C7CCDA;
  border-radius: 2pt;
  padding: 10pt 14pt;
  margin-bottom: 12pt;
  break-inside: avoid;
  page-break-inside: avoid;
}}
.finding.critical {{ border-left-color: #B0123A; }}
.finding.high     {{ border-left-color: #B65C00; }}
.finding.medium   {{ border-left-color: #93720A; }}
.finding.low      {{ border-left-color: #157A4F; }}

.badge {{
  display: inline-block;
  font-size: 7.5pt; font-weight: bold; letter-spacing: 0.06em; text-transform: uppercase;
  border: 1px solid currentColor; border-radius: 2pt; padding: 1pt 6pt;
}}
.finding-id {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt; color: #808AA0; display: block; margin-bottom: 4pt; }}
.finding-title {{ font-size: 12.5pt; font-weight: bold; margin: 0 0 7pt; }}

.finding-summary {{ font-size: 10pt; color: #1A2233; padding-bottom: 10pt; margin-bottom: 10pt; border-bottom: 1px solid #EEF0F4; }}

/* Structured finding attributes -- a <table>, not CSS grid (see this
   module's own docstring for why grid/flex are avoided entirely). */
.finding-attributes {{ width: 100%; border-collapse: collapse; margin-bottom: 10pt; table-layout: fixed; }}
.attr-cell {{ vertical-align: top; padding: 0 10pt 0 0; width: 25%; }}
.attr-label {{
  font-size: 7pt; font-weight: bold; letter-spacing: 0.06em; text-transform: uppercase;
  color: #808AA0; margin-bottom: 4pt;
}}
.attr-value {{ font-size: 9pt; color: #1A2233; }}
.attr-empty {{ color: #9098AC; font-family: 'DejaVu Sans Mono', monospace; }}
.rule-chip, .control-chip {{
  display: inline-block; font-family: 'DejaVu Sans Mono', monospace; font-size: 8pt;
  border: 1px solid #E1E4EA; border-radius: 2pt; padding: 1pt 5pt; margin: 0 3pt 3pt 0;
}}
.rule-chip {{ color: #8A5A12; background: #FBF1E0; border-color: #E9D2A0; }}
.control-chip {{ color: #0F6F5C; background: #E6F5F1; border-color: #BFE3D8; }}

.detail {{ margin-top: 8pt; }}
.detail-title {{
  font-size: 8pt; font-weight: bold; letter-spacing: 0.05em; text-transform: uppercase;
  color: #55607A; margin-bottom: 4pt;
}}
.detail-title svg {{ vertical-align: -1.5pt; margin-right: 3pt; }}
.detail-body {{ font-size: 9.5pt; color: #303A50; }}
.detail-body p {{ margin: 0; }}
.detail-body ul {{ list-style: none; padding-left: 0; }}
.detail-body ul ul {{ padding-left: 14pt; margin-top: 3pt; }}
.detail-body li {{ position: relative; padding-left: 11pt; margin-bottom: 4pt; }}
.detail-body li::before {{ content: "\\2013"; position: absolute; left: 0; color: #9098AC; }}
.detail-body .bullet-note {{ padding-left: 11pt; margin-top: 2pt; color: #808AA0; font-size: 8.5pt; }}

.metadata {{ margin-top: 20pt; padding-top: 8pt; border-top: 1px solid #E1E4EA; font-size: 8pt; color: #9098AC; }}
.metadata-fields {{ margin-top: 5pt; font-family: 'DejaVu Sans Mono', monospace; }}
""" + """
</style>
</head>
<body>
{body}
</body>
</html>
"""
