"""Priority ordering for AuditFindings: which exposed service to look at first.

Priority is hierarchical: the destination's criticality is the dominant key,
so all Critical findings precede High ones. Within a band, secondary factors
order findings:

  priority = band_base + secondary_score x BAND_WIDTH

  Bands: critical [0.75, 1.00), high [0.50, 0.75), medium [0.25, 0.50),
         low [0.00, 0.25)

severity is the destination's criticality label, not a risk estimate.

Secondary factors:
  Diversity - distinct (src_segment, via_hop, intermediates) exposure contexts.
  Amplitude - distinct source segments (20 hosts from one segment is one change).
  Quality   - OPEN edges are stronger evidence than filtered ones.

FindingType and source criticality are deliberately absent; classification
already decided why a path is a violation.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Callable, Protocol

from nssa.oae.audit.models import AuditFinding, RawFinding
from nssa.shared.contracts import ProbeState

_BAND_WIDTH = 0.25    # priority range per criticality level
_BAND_EPSILON = 1e-9  # keeps max(band_n) below min(band_n+1)

_CRITICALITY_BANDS: dict[str, tuple[float, str]] = {
    "critical": (0.75, "critical"),
    "high":     (0.50, "high"),
    "medium":   (0.25, "medium"),
    "low":      (0.00, "low"),
}

_STATE_SCORES: dict[ProbeState, float] = {
    ProbeState.OPEN:          1.00,
    ProbeState.CLOSED:        0.60,
    ProbeState.OPEN_FILTERED: 0.30,
}


# ── Protocol ──────────────────────────────────────────────────────────────────


class ScoringFactor(Protocol):
    """A secondary ordering dimension within a criticality band."""

    weight: float

    def score(self, finding: AuditFinding) -> float:
        """Return a contribution in [0.0, 1.0]."""
        ...


# ── Secondary factor implementations ─────────────────────────────────────────


def exposure_mechanism(r: RawFinding) -> tuple[str, str, str | None]:
    """Abstract the exposure mechanism of one reachability path.

    The fingerprint is (src_segment, access_type, via_hop); paths through
    HA-equivalent intermediates share it.

    access_type: "direct" (hop_count == 0), "single_hop", "multi_hop", or
    "bypass" (via_hop set; the bypassed host is in the fingerprint).
    """
    if r.via_hop is not None:
        return (r.src_segment, "bypass", r.via_hop)
    if r.hop_count == 0:
        return (r.src_segment, "direct", None)
    if r.hop_count == 1:
        return (r.src_segment, "single_hop", None)
    return (r.src_segment, "multi_hop", None)


@dataclass
class ReachabilityDiversityFactor:
    """Rank findings with more independent exposure mechanisms higher.

    Counts distinct exposure_mechanism() fingerprints across raw_findings.
    Ceiling (default 6) is a heuristic: beyond it, exposure is maximal.
    """

    weight: float = 0.40
    ceiling: int = 6

    def score(self, finding: AuditFinding) -> float:
        mechanisms = {exposure_mechanism(r) for r in finding.raw_findings}
        return min(len(mechanisms) / self.ceiling, 1.0)


@dataclass
class TrustBoundaryCountFactor:
    """Rank exposure spanning more trust segments higher.

    Ceiling (default 4) is a heuristic for typical trust zones in enterprise
    segmentation.
    """

    weight: float = 0.35
    ceiling: int = 4

    def score(self, finding: AuditFinding) -> float:
        return min(len(finding.source_groups) / self.ceiling, 1.0)


@dataclass
class EvidenceQualityFactor:
    """Rank better-confirmed reachability higher; uses the best state across raw_findings."""

    weight: float = 0.25

    def score(self, finding: AuditFinding) -> float:
        if not finding.raw_findings:
            return 0.0
        return max(
            _STATE_SCORES.get(r.observed_state, 0.0)
            for r in finding.raw_findings
        )


# ── Default secondary factor list ─────────────────────────────────────────────


DEFAULT_SECONDARY_FACTORS: list[ScoringFactor] = [
    ReachabilityDiversityFactor(),
    TrustBoundaryCountFactor(),
    EvidenceQualityFactor(),
]


# ── Pipeline stage ────────────────────────────────────────────────────────────


def score_priority(
    finding: AuditFinding,
    *,
    segment_criticality: Callable[[str], str] | None = None,
    secondary_factors: list[ScoringFactor] | None = None,
) -> AuditFinding:
    """Enrich an AuditFinding with priority and severity (returns a new AuditFinding).

    severity: the destination's criticality label.
    priority: band_base + secondary_score x BAND_WIDTH.
    segment_criticality: callable resolving dst_ip to a criticality label
        (e.g. SegmentationPolicy.criticality_for_ip). Keyed by IP because
        dst_segment is None for multi-group destinations. Defaults to "low".
    """
    active = secondary_factors if secondary_factors is not None else DEFAULT_SECONDARY_FACTORS

    # Determine criticality band from the destination workload.
    label = segment_criticality(finding.dst_ip) if segment_criticality is not None else None
    band_base, severity = _CRITICALITY_BANDS.get(label or "low", (0.0, "low"))

    # Secondary score within the band.
    total_weight = sum(f.weight for f in active)
    secondary = (
        sum(f.weight * f.score(finding) for f in active) / total_weight
        if total_weight > 0.0
        else 0.0
    )

    return dataclasses.replace(
        finding,
        priority=band_base + secondary * (_BAND_WIDTH - _BAND_EPSILON),
        severity=severity,
    )
