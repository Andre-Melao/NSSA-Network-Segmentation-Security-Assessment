"""A small, self-authored, inline SVG icon set shared by html.py and pdf.py.

Replaces emoji glyphs, which rendered blank in WeasyPrint's PDF output (font
coverage for emoji is unreliable across browsers/PDF engines/OSes). The icons
are hand-drawn, stroke-based, on a 24x24 viewBox with stroke="currentColor" so
they take the surrounding colour, and need no icon font or CDN.

ICONS maps a stable name to the icon's inner markup (no <svg> wrapper); icon()
returns a ready-to-embed <svg> element.
"""

from __future__ import annotations

ICONS: dict[str, str] = {
    # Severity / stat glyphs: distinct shapes (not only colour) so they stay
    # legible in black-and-white print and for colour-blind readers.
    "critical": (
        '<polygon points="7.86,2 16.14,2 22,7.86 22,16.14 16.14,22 7.86,22 2,16.14 2,7.86"/>'
        '<line x1="12" y1="7.5" x2="12" y2="13"/><line x1="12" y1="16.5" x2="12" y2="16.51"/>'
    ),
    "high": (
        '<path d="M12 2 L23 21 H1 Z" stroke-linejoin="round"/>'
        '<line x1="12" y1="9" x2="12" y2="14"/><line x1="12" y1="17" x2="12" y2="17.01"/>'
    ),
    "medium": (
        '<polygon points="12,2 22,12 12,22 2,12"/>'
        '<line x1="12" y1="8" x2="12" y2="13"/><line x1="12" y1="16" x2="12" y2="16.01"/>'
    ),
    "low": '<circle cx="12" cy="12" r="9"/><line x1="8" y1="12" x2="16" y2="12"/>',
    "total": '<line x1="6" y1="20" x2="6" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="18" y1="20" x2="18" y2="14"/>',
    # Section / concept glyphs.
    "stats": '<line x1="6" y1="20" x2="6" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="18" y1="20" x2="18" y2="14"/>',
    "summary": (
        '<rect x="6" y="4" width="12" height="18" rx="1"/><rect x="9" y="2" width="6" height="4" rx="1"/>'
        '<line x1="8" y1="11" x2="16" y2="11"/><line x1="8" y1="15" x2="16" y2="15"/><line x1="8" y1="19" x2="13" y2="19"/>'
    ),
    "findings": '<circle cx="10" cy="10" r="7"/><line x1="20.5" y1="20.5" x2="15.2" y2="15.2"/>',
    "asset": (
        '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/>'
        '<line x1="7" y1="7.5" x2="7.01" y2="7.5"/><line x1="7" y1="16.5" x2="7.01" y2="16.5"/>'
    ),
    "technical_evidence": '<polyline points="2,12 7,12 10,4 14,20 17,12 22,12" stroke-linejoin="round"/>',
    "policy_context": (
        '<path d="M6 2h9l5 5v15a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z" stroke-linejoin="round"/>'
        '<path d="M15 2v5h5" stroke-linejoin="round"/>'
        '<line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>'
    ),
    "business_impact": (
        '<polyline points="2,18 9,11 13,15 22,5" stroke-linejoin="round" stroke-linecap="round"/>'
        '<polyline points="15,5 22,5 22,12" stroke-linejoin="round" stroke-linecap="round"/>'
    ),
    "compliance": (
        '<line x1="12" y1="3" x2="12" y2="21"/><line x1="5" y1="7" x2="19" y2="7"/>'
        '<path d="M5 7 L2 14 a3 3 0 0 0 6 0 Z" stroke-linejoin="round"/>'
        '<path d="M19 7 L16 14 a3 3 0 0 0 6 0 Z" stroke-linejoin="round"/>'
        '<line x1="8" y1="21" x2="16" y2="21"/>'
    ),
    "mitigations": (
        '<path d="M14.7 6.3a4 4 0 1 0-5.4 5.4L2 19l3 3 7.3-7.3a4 4 0 0 0 5.4-5.4l-2.8 2.8-2-2z" '
        'stroke-linejoin="round"/>'
    ),
    "info": '<circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="8.01"/><line x1="12" y1="11" x2="12" y2="16"/>',
}


def icon(name: str, *, size: int = 16, color: str | None = None, css_class: str | None = None) -> str:
    """One <svg> element for ICONS[name], *size* px square, stroke-only.

    Raises KeyError for an unknown name (a programming error).

    color, if given, is set as an inline style on the <svg> itself: WeasyPrint
    resolves stroke="currentColor" against the SVG's own color and ignores one
    inherited from an HTML ancestor (icons would render black in the PDF while
    looking right in a browser). Callers needing a specific colour must pass it.
    """
    inner = ICONS[name]
    class_attr = f' class="{css_class}"' if css_class else ""
    style_attr = f' style="color:{color}"' if color else ""
    return (
        f'<svg{class_attr}{style_attr} width="{size}" height="{size}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true">{inner}</svg>'
    )
