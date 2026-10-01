"""The JSON Schema describing EnrichmentResult's wire shape.

Shared by every provider adapter that declares a structured-output schema
(Anthropic input_schema, Gemini response_json_schema, OpenAI response_format).
It is defined once so adapters cannot drift from each other or from
parse_enrichment_response(); field names mirror EnrichmentResult/
FindingEnrichment/FrameworkMapping.

Nullable fields (control_title/rationale) use "anyOf": [{"type": "string"},
{"type": "null"}] rather than "type": ["string", "null"], since the former is
the form documented as supported by every provider checked so far.
"""

from __future__ import annotations

from typing import Any

ENRICHMENT_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "title": {"type": "string"},
                    "summary": {"type": "string"},
                    "business_impact": {"type": "string"},
                    "mitigation_suggestions": {"type": "array", "items": {"type": "string"}},
                    "framework_mappings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "framework": {"type": "string"},
                                "control_id": {"type": "string"},
                                "control_title": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                                "rationale": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                            },
                            "required": ["framework", "control_id"],
                        },
                    },
                },
                "required": ["finding_id", "title", "summary", "business_impact", "mitigation_suggestions", "framework_mappings"],
            },
        },
    },
    "required": ["executive_summary", "findings"],
}
