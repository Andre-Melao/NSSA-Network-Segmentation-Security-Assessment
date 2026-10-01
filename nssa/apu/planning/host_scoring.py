"""SPM-derived discovery context: topology metrics only.

Computes structural importance scores from the Segmentation Policy Model graph;
no probing, external data, candidate generation, filtering, or execution
decisions.

  host_scores  - structural importance (rule participation, transitivity,
                 cross-segment centrality).
  pivot_scores - usefulness as a lateral pivot (outbound fan-out + transitive
                 relay participation).

plan_discovery_phase passes these into priority() for topology-aware ordering.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field

from nssa.shared.models import Server
from nssa.shared.policy import SegmentationPolicy

logger = logging.getLogger(__name__)

# ── Weights ────────────────────────────────────────────────────────────────────

TRANSITIVE_PARTICIPATION_WEIGHT: float = 2.0
RULE_PARTICIPATION_WEIGHT: float = 1.0

# ── Model ──────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class DiscoveryContext:
    """Topology-derived host importance scores for discovery planning.

    host_scores: IP -> structural importance. pivot_scores: IP -> pivot
    potential. host_breakdowns/pivot_breakdowns hold per-component details.
    All values come from the SPM graph; pivot_scores and breakdowns default to
    empty dicts.
    """

    host_scores: dict[str, float]
    pivot_scores: dict[str, float] = field(default_factory=dict)
    host_breakdowns: dict[str, dict[str, float]] = field(default_factory=dict)
    pivot_breakdowns: dict[str, dict[str, float]] = field(default_factory=dict)


# ── Public API ─────────────────────────────────────────────────────────────────

def build_discovery_context(policy: SegmentationPolicy) -> DiscoveryContext:
    """Build a discovery context from the SPM topology."""
    host_scores, host_breakdowns = _compute_host_scores(policy)
    pivot_scores, pivot_breakdowns = _compute_pivot_scores(policy)

    for ip, score in sorted(host_scores.items(), key=lambda x: -x[1]):
        logger.debug("discovery host score: ip=%s score=%g", ip, score)

    return DiscoveryContext(
        host_scores=host_scores,
        pivot_scores=pivot_scores,
        host_breakdowns=host_breakdowns,
        pivot_breakdowns=pivot_breakdowns,
    )


def explain_host_scores(
    policy: SegmentationPolicy,
) -> dict[str, dict[str, float]]:
    """Return per-component score breakdown for every host IP.

    Keys per host: rule_participation, transitive, cross_segment.
    Values sum to host_scores[ip].
    """
    _, breakdowns = _compute_host_scores(policy)
    return breakdowns


def explain_pivot_scores(
    policy: SegmentationPolicy,
) -> dict[str, dict[str, float]]:
    """Return per-component pivot breakdown for every host IP.

    Keys per host: outbound_fan_out, transitive_via.
    Values sum to pivot_scores[ip].
    """
    _, breakdowns = _compute_pivot_scores(policy)
    return breakdowns


# ── Host scoring ───────────────────────────────────────────────────────────────

def _compute_host_scores(
    policy: SegmentationPolicy,
) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    """Compute total scores and per-component breakdowns for all hosts.

    Returns (totals, breakdowns) where breakdowns[ip] maps component name
    to its individual contribution.
    """
    totals: dict[str, float] = {srv.ip: 0.0 for srv in policy.servers}
    breakdowns: dict[str, dict[str, float]] = {
        srv.ip: {
            "rule_participation": 0.0,
            "transitive": 0.0,
            "cross_segment": 0.0,
        }
        for srv in policy.servers
    }
    srv_by_name: dict[str, Server] = {srv.name: srv for srv in policy.servers}
    srv_by_ip: dict[str, Server] = {srv.ip: srv for srv in policy.servers}

    # dst_ip → set of source segment names that reach this host across segments
    dst_source_segments: dict[str, set[str]] = defaultdict(set)

    for rule in policy.rules:
        # Signal: rule participation (+1 per server explicitly named)
        for endpoint in (rule.src, rule.dst):
            srv = srv_by_name.get(endpoint)
            if srv is not None:
                totals[srv.ip] += RULE_PARTICIPATION_WEIGHT
                breakdowns[srv.ip]["rule_participation"] += RULE_PARTICIPATION_WEIGHT

        # Signal: cross-segment centrality — accumulate source segments per dst host
        src_seg = policy.endpoint_segment(rule.src)
        if src_seg is not None:
            for dst_ip in policy.resolve_dst_ips(rule):
                dst_srv = srv_by_ip.get(dst_ip)
                if dst_srv is not None and src_seg not in dst_srv.groups:
                    dst_source_segments[dst_ip].add(src_seg)

    for tr in policy.mandatory_transit_paths:
        # Collect hosts that directly participate in this transitive rule
        transitive_ips: set[str] = set()

        srv = srv_by_name.get(tr.via)
        if srv is not None:
            transitive_ips.add(srv.ip)
            totals[srv.ip] += RULE_PARTICIPATION_WEIGHT
            breakdowns[srv.ip]["rule_participation"] += RULE_PARTICIPATION_WEIGHT

        for endpoint in (tr.src, tr.dst):
            srv = srv_by_name.get(endpoint)
            if srv is not None:
                transitive_ips.add(srv.ip)
                totals[srv.ip] += RULE_PARTICIPATION_WEIGHT
                breakdowns[srv.ip]["rule_participation"] += RULE_PARTICIPATION_WEIGHT

        # Signal: transitive participation bonus per rule
        for ip in transitive_ips:
            totals[ip] += TRANSITIVE_PARTICIPATION_WEIGHT
            breakdowns[ip]["transitive"] += TRANSITIVE_PARTICIPATION_WEIGHT

        # Signal: cross-segment centrality for transitive destinations
        src_seg = policy.endpoint_segment(tr.src)
        if src_seg is not None:
            for dst_srv in _servers_for_endpoint(policy, tr.dst):
                if src_seg not in dst_srv.groups:
                    dst_source_segments[dst_srv.ip].add(src_seg)

    # Apply cross-segment bonus: +1 per distinct source segment
    for ip, source_segs in dst_source_segments.items():
        bonus = float(len(source_segs))
        totals[ip] += bonus
        breakdowns[ip]["cross_segment"] += bonus

    return totals, breakdowns


# ── Pivot scoring ──────────────────────────────────────────────────────────────

def _compute_pivot_scores(
    policy: SegmentationPolicy,
) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    """Compute pivot scores and per-component breakdowns for all hosts.

    pivot_score = outbound_fan_out + 2 * transitive_via_count

    outbound_fan_out: distinct destination segments reachable through this
        server (from its segment via direct rules, or as a transitive via-hop).
    transitive_via_count: transitive rules naming this server as a via-hop.

    Returns (pivot_scores, pivot_breakdowns). O(R + T*V_avg + N): the indices
    are built in one pass over the rules before iterating hosts.
    """
    # Pass 1 — O(R): segment → set of reachable destination segments via direct rules.
    # Only cross-segment destinations (src_seg != dst_seg) contribute to fan_out.
    seg_reachable: dict[str, set[str]] = defaultdict(set)
    for rule in policy.rules:
        src_seg = policy.endpoint_segment(rule.src)   # O(1)
        dst_seg = policy.endpoint_segment(rule.dst)   # O(1)
        if src_seg and dst_seg and src_seg != dst_seg:
            seg_reachable[src_seg].add(dst_seg)

    # Pass 2 — O(T * V_avg): server name → (via_count, extra reachable dst segments).
    # Only transitive rules where this server is a named via-hop contribute.
    server_via_count: dict[str, int] = defaultdict(int)
    server_via_segs: dict[str, set[str]] = defaultdict(set)
    for tr in policy.mandatory_transit_paths:
        server_via_count[tr.via] += 1
        if tr.dst:
            server_via_segs[tr.via].add(tr.dst)

    # Pass 3 — O(N): assign scores to each server using the pre-built indices.
    pivot_scores: dict[str, float] = {}
    pivot_breakdowns: dict[str, dict[str, float]] = {}

    for server in policy.servers:
        # Union over all of the server's groups, not one.
        reachable: set[str] = set()
        for g in server.groups:
            reachable |= seg_reachable.get(g, set())

        via_count = server_via_count.get(server.name, 0)
        for dst_seg in server_via_segs.get(server.name, ()):
            if dst_seg not in server.groups:
                reachable.add(dst_seg)

        outbound = len(reachable)
        pivot = float(outbound + 2 * via_count)
        pivot_scores[server.ip] = pivot
        pivot_breakdowns[server.ip] = {
            "outbound_fan_out": float(outbound),
            "transitive_via": float(via_count),
        }

    return pivot_scores, pivot_breakdowns


# ── Helpers ────────────────────────────────────────────────────────────────────

def _servers_for_endpoint(
    policy: SegmentationPolicy,
    endpoint: str,
) -> tuple[Server, ...]:
    server = policy.get_server(endpoint)
    if server is not None:
        return (server,)
    return tuple(policy.servers_in(endpoint))


# ── Debug CLI ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    """Inspect SPM-derived discovery context without running the planner."""
    parser = argparse.ArgumentParser(
        description="Print SPM-derived discovery host scores as JSON.",
    )
    parser.add_argument("spm", help="Path to the Segmentation Policy Model JSON.")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Log per-host scores to stderr.",
    )
    parser.add_argument(
        "-b",
        "--breakdown",
        action="store_true",
        help="Include per-component score breakdown in output.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    from nssa.shared.spm_parser import load_spm

    policy = load_spm(args.spm)
    ctx = build_discovery_context(policy)

    if args.breakdown:
        output = {
            "host_scores": {
                ip: {
                    "total": score,
                    **ctx.host_breakdowns.get(ip, {}),
                }
                for ip, score in sorted(ctx.host_scores.items(), key=lambda x: -x[1])
            },
            "pivot_scores": {
                ip: {
                    "total": ctx.pivot_scores.get(ip, 0.0),
                    **ctx.pivot_breakdowns.get(ip, {}),
                }
                for ip in sorted(ctx.host_scores, key=lambda x: -ctx.pivot_scores.get(x, 0.0))
            },
        }
    else:
        output = {
            "host_scores": {
                ip: score
                for ip, score in sorted(ctx.host_scores.items(), key=lambda x: -x[1])
            },
            "pivot_scores": {
                ip: ctx.pivot_scores.get(ip, 0.0)
                for ip in sorted(ctx.pivot_scores, key=lambda x: -ctx.pivot_scores[x])
            },
        }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
