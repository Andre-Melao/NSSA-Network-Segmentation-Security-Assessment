"""Global test-ordering engine: priority calculation only.

Assigns a single integer priority to any test ("which test runs first?").

Inputs: strategy (policy_validation vs discovery), context
(transitive_rule_bypass / segment_level / inter_segment / ...), port (risk
weight), sensitivity (destination criticality), host_score and pivot_score
(from DiscoveryContext).

Does not generate candidates, choose execution mode, or filter hosts.
"""

from __future__ import annotations

from nssa.shared.criticality import criticality_score
from nssa.shared.policy import SegmentationPolicy

def priority(
    port: int = 0,
    *,
    strategy: str,
    context: str,
    dst_segment: str | None,
    sensitivity_fn,
    host_score: float = 0.0,
    pivot_score: float = 0.0,
) -> int:
    strategy_weight = {
        "policy_validation": 25,
        "discovery": 10,
    }.get(strategy, 0)
    context_weight = {
        "transitive_rule_bypass": 40,
        "host_constrained": 25,
        "segment_level": 10,
        "inter_segment": 10,
        "intra_segment": 3,
    }.get(context, 0)
    critical_ports = {22, 445, 3389, 5432, 3306, 1433, 1521}
    high_ports = {88, 389, 636}
    if port in critical_ports:
        port_weight = 50
    elif port in high_ports:
        port_weight = 30
    else:
        port_weight = 10

    return int(strategy_weight + context_weight + port_weight + sensitivity_fn(dst_segment) + host_score + pivot_score)


def segment_sensitivity(
    segment_name: str | None,
    *,
    sensitivity_by_segment: dict[str, int],
) -> int:
    if not segment_name:
        return 0

    return sensitivity_by_segment.get(segment_name, 0)


def build_segment_sensitivity_index(policy: SegmentationPolicy) -> dict[str, int]:
    return {
        segment.name: criticality_score(segment.criticality)
        for segment in policy.segments
    }
