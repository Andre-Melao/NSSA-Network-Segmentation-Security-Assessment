"""LocalKnowledgeProvider: the simplest KnowledgeProvider.

Reads one structured JSON file per requested framework from a local directory
(see knowledge_base/pci_dss.json for the shape). A stand-in until RAG/enterprise
providers exist (see contracts.KnowledgeProvider).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from nssa.oae.reporting.context import KnowledgeBundle, KnowledgeSnippet, OAEReport
from nssa.oae.reporting.errors import KnowledgeProviderError

# Spelling variants mapped to the canonical framework id (knowledge_base/ filename
# stem). Keys pass through _normalize_key(), so only different wordings need entries.
_FRAMEWORK_ALIASES: dict[str, str] = {
    "pci": "pci_dss",
    "pci dss": "pci_dss",
    "iso27002": "iso_27002",
    "iso 27002": "iso_27002",
    "iso iec 27002": "iso_27002",
    "nist": "nist_csf",
    "nist csf": "nist_csf",
    "nist csf 2.0": "nist_csf",
    "cis": "cis_control",
    "cis control": "cis_control",
    "cis controls": "cis_control",
    "cis controls v8": "cis_control",
}


def _normalize_key(value: str) -> str:
    """Lowercase and collapse whitespace/hyphens/slashes/underscores to one space ("PCI-DSS" -> "pci dss")."""
    return re.sub(r"[\s\-/_]+", " ", value.strip().lower()).strip()


def normalize_framework_name(name: str) -> str:
    """Resolve *name* to a canonical framework id via _FRAMEWORK_ALIASES.

    Unknown names fall through to the normalized, underscore-joined form;
    callers validate against the files on disk.
    """
    key = _normalize_key(name)
    return _FRAMEWORK_ALIASES.get(key, key.replace(" ", "_"))


class LocalKnowledgeProvider:
    """Reads '<knowledge_dir>/<framework>.json' for each requested framework.

    Each file is a curated set of segmentation-relevant controls. One
    KnowledgeSnippet(framework, control_id, text, source) is produced per
    control, grouped by framework in request order.

    Deterministic: the same directory and frameworks give the same
    KnowledgeBundle. Requested names are normalized (see
    normalize_framework_name()) and matched against the files present. An
    unresolved name or a malformed file (invalid JSON, a control without
    control_id) raises KnowledgeProviderError; the former lists the available
    frameworks.

    Each framework file is read at most once per instance, cached by canonical
    name (so "PCI" and "pci_dss" share one entry).

    report is accepted for the KnowledgeProvider Protocol but unused: every
    curated control is returned, and the LLM decides which apply to which
    finding.
    """

    def __init__(self, knowledge_dir: Path) -> None:
        self._knowledge_dir = knowledge_dir
        self._cache: dict[str, tuple[KnowledgeSnippet, ...]] = {}

    def get_context(self, frameworks: tuple[str, ...], report: OAEReport) -> KnowledgeBundle:
        snippets: list[KnowledgeSnippet] = []
        for framework in frameworks:
            snippets.extend(self._load(framework))
        return KnowledgeBundle(snippets=tuple(snippets))

    def _load(self, framework: str) -> tuple[KnowledgeSnippet, ...]:
        canonical = normalize_framework_name(framework)
        if canonical not in self._cache:
            self._cache[canonical] = self._read(canonical, requested_as=framework)
        return self._cache[canonical]

    def _available_frameworks(self) -> list[str]:
        if not self._knowledge_dir.is_dir():
            return []
        return sorted(p.stem for p in self._knowledge_dir.glob("*.json"))

    def _read(self, framework: str, *, requested_as: str) -> tuple[KnowledgeSnippet, ...]:
        path = self._knowledge_dir / f"{framework}.json"
        try:
            raw_text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            available = self._available_frameworks()
            requested_note = f" (normalized to '{framework}')" if requested_as != framework else ""
            raise KnowledgeProviderError(
                f"Unknown compliance framework '{requested_as}'{requested_note}. "
                f"Supported frameworks: {available}"
            ) from None
        except OSError as exc:
            raise KnowledgeProviderError(
                f"could not read knowledge file for '{framework}' at {path}: {exc}"
            ) from exc

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise KnowledgeProviderError(f"invalid JSON in knowledge file {path}: {exc}") from exc

        name = data.get("name", framework)
        version = data.get("version", "")
        controls = data.get("controls", [])

        snippets = []
        for index, control in enumerate(controls):
            control_id = control.get("control_id")
            if not control_id:
                raise KnowledgeProviderError(
                    f"{path}: controls[{index}] has no 'control_id' -- every curated control must be citable"
                )
            snippets.append(KnowledgeSnippet(
                framework=framework,
                control_id=control_id,
                text=self._render_control_text(name, version, control),
                source=f"local:{framework}.json#{control_id}",
            ))
        return tuple(snippets)

    @staticmethod
    def _render_control_text(name: str, version: str, control: dict[str, Any]) -> str:
        """Collapse one curated control into KnowledgeSnippet.text.

        Only fields that serve the prompt are included: title/summary,
        nssa_relevance, and limitations. The other curation/maintenance
        fields stay in the file but are not rendered.
        """
        header = f"{name} v{version} {control['control_id']} -- {control.get('title', '')}".strip()
        parts = [header, control.get("summary", "")]
        if control.get("nssa_relevance"):
            parts.append(f"Relevance to network segmentation assessment: {control['nssa_relevance']}")
        limitations = control.get("limitations")
        if limitations:
            parts.append("Limitations: " + " ".join(limitations))
        return "\n\n".join(part for part in parts if part)
