"""Criticality helpers shared across APU and OAE."""

from __future__ import annotations

CRITICALITY_LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")

# Planning score used by APU ranking and lateral budget selection.
CRITICALITY_SCORE: dict[str, int] = {
    "low": 10,
    "medium": 30,
    "high": 45,
    "critical": 85,
}


def normalize_criticality(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in CRITICALITY_LEVELS:
        raise ValueError(
            f"Invalid criticality '{value}'. Expected one of {CRITICALITY_LEVELS}"
        )
    return normalized


def criticality_score(value: str | None) -> int:
    if value is None:
        return 0
    normalized = value.strip().lower()
    return CRITICALITY_SCORE.get(normalized, 0)
