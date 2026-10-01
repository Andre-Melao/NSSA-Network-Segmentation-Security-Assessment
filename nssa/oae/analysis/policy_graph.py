"""Declared-reachability graph derived purely from the SPM's direct rules.

No observation is involved: every edge exists because a direct `rules` entry
authorises it, expanded to concrete server IPs via resolve_principal_ips(). It
has the same ObservedGraph/GraphEdge shape as the observed graph, so it feeds
build_reachability_index() and classify_reachability_index() unchanged.

Purpose: catch mandatory-transit bypasses implied by composing direct rules
(e.g. "users -> web01" + "dmz -> payapi01" contradicts "users -> payapi01 via
app01"), which Representative Observation cannot see because only APU sensors
emit probes.

classify_reachability_index() is reused unmodified, so its ECM-fallback path
also flags arbitrary composed paths; that is outside this graph's purpose. The
caller (nssa.oae.engine.evaluate) keeps only MANDATORY_TRANSIT_PATH_BYPASS
candidates from this pass.

Entry point: build_policy_graph()
"""

from __future__ import annotations

from nssa.oae.observed.graph import ObservedGraph, build_graph
from nssa.oae.observed.matrix import ObservedEdge, ObservedMatrix
from nssa.shared.contracts import ProbeState
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.reachability import resolve_principal_ips


def build_policy_graph(policy: SegmentationPolicy) -> ObservedGraph:
    """Compose policy.rules into an ObservedGraph, no observation involved.

    Each direct rule contributes one edge per (resolved src IP, resolved dst IP,
    port), marked state=OPEN and strategy="declared_policy" (non-empirical).
    Reuses build_graph() on an ObservedMatrix assembled from the policy.
    """
    matrix = ObservedMatrix()

    for rule in policy.rules:
        src_ips = resolve_principal_ips(policy, rule.src)
        dst_ips = resolve_principal_ips(policy, rule.dst)
        proto = rule.proto.lower()

        for dst_ip in dst_ips:
            for port in rule.ports:
                key = (dst_ip, port, proto)
                for src_ip in src_ips:
                    matrix.data.setdefault(key, {}).setdefault(src_ip, []).append(
                        ObservedEdge(
                            state=ProbeState.OPEN,
                            strategy="declared_policy",
                            detail=f"declared by {rule.rule_id}",
                        )
                    )

    return build_graph(matrix)
