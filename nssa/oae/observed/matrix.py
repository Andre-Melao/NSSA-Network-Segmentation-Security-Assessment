from __future__ import annotations

from dataclasses import dataclass, field
from nssa.shared.contracts import ProbeState


ObservedKey = tuple[str, int, str]


@dataclass(slots=True)
class ObservedEdge:
    """Observed result metadata for one source toward one destination key."""

    state: ProbeState
    detail: str | None = None
    strategy: str | None = None
    context: str | None = None
    rtt_ms: float | None = None
    timestamp: float | None = None
    service: str | None = None
    service_banner: str | None = None


@dataclass(slots=True)
class ObservedMatrix:
    """Observed host-level connectivity evidence indexed by destination tuple.

    Maps each (dst_ip, dst_port, proto) to source hosts and all observed
    evidence edges (supports multiple runs/probes per source).
    """

    data: dict[ObservedKey, dict[str, list[ObservedEdge]]] = field(default_factory=dict)


def get_edges(matrix: ObservedMatrix, key: ObservedKey, src_ip: str) -> list[ObservedEdge]:
    """Return all observed edges for one source and destination tuple."""
    return matrix.data.get(key, {}).get(src_ip, [])


def get_open_sources(matrix: ObservedMatrix, key: ObservedKey) -> set[str]:
    """Return source IPs with at least one OPEN observation for a key."""
    return {
        src_ip
        for src_ip, edges in matrix.data.get(key, {}).items()
        if any(edge.state == ProbeState.OPEN for edge in edges)
    }
