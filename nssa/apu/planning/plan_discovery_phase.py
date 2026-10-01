"""Discovery phase planning: host selection only.

Decides which hosts to explore and in what order. Port strategy (TCP top-ports,
UDP, service detection) is the executor's job.

  generate_lateral_discovery_tests - one TestCase per host, ranked by priority(),
    emitted with scan_mode="host_scan" (full top-ports scan).
  generate_safety_net_tests - single tcp/22 liveness probes for hosts not yet
    covered (scan_mode="single_probe").

Does not iterate ports, choose TCP vs UDP, know Nmap parameters, or alter
ObservedEdge, the OAE, or the Audit Layer.
"""

from __future__ import annotations

from collections.abc import Callable

from nssa.apu.planning.host_scoring import DiscoveryContext
from nssa.apu.planning.planner import TestCase
from nssa.shared.models import Server
from nssa.shared.policy import SegmentationPolicy


# ── Internal helpers ──


def _topology_scores(host: Server, ctx: DiscoveryContext | None) -> tuple[float, float]:
    """Return (host_score, pivot_score) for a host, both 0.0 when no context."""
    if ctx is None:
        return 0.0, 0.0
    return ctx.host_scores.get(host.ip, 0.0), ctx.pivot_scores.get(host.ip, 0.0)


def _dominant_group(groups: tuple[str, ...], segment_sensitivity_fn) -> str | None:
    """Representative group for scoring a multi-group host: the most sensitive one.

    Scoring only (see priority.py), never authorization. None if no groups.
    """
    if not groups:
        return None
    return max(groups, key=segment_sensitivity_fn)


def _host_candidate(
    host: Server,
    context: str,
    score: Callable[..., int],
    discovery_context: DiscoveryContext | None,
    segment_sensitivity_fn,
) -> tuple[float, Server, str]:
    """Compute one scored candidate tuple for a host. No port information."""
    h, p = _topology_scores(host, discovery_context)
    dst_segment = _dominant_group(host.groups, segment_sensitivity_fn)
    return (
        float(score(strategy="discovery", context=context, dst_segment=dst_segment, host_score=h, pivot_score=p)),
        host,
        context,
    )


# ── Lateral discovery ──


def generate_lateral_discovery_tests(
    *,
    policy: SegmentationPolicy,
    config,
    groups: tuple[str, ...],
    src_ip: str,
    score: Callable[..., int],
    segment_sensitivity_fn,
    discovery_context: DiscoveryContext | None = None,
) -> list[TestCase]:
    """Select hosts to explore laterally, one TestCase per host.

    The TestCase has no meaningful port; the executor picks ports for
    scan_mode="host_scan".

    Intra- and inter-segment coverage are gated independently:
    enable_lateral_discovery ("--discovery") enables both, while
    enable_intra_segment_discovery alone (set only by the Host Mode fan-out)
    still gives intra-segment candidates and withholds inter-segment ones.
    """
    intra_enabled = config.enable_lateral_discovery or config.enable_intra_segment_discovery
    inter_enabled = config.enable_lateral_discovery
    if not intra_enabled and not inter_enabled:
        return []

    vantage_groups = tuple(groups)
    vantage_group_set = set(vantage_groups)

    policy_destination_ips = _policy_destination_ips(policy)

    # "Intra" means same-zone: the host's groups intersect the vantage's.
    intra_hosts = [
        h for h in policy.servers if h.ip != src_ip and set(h.groups) & vantage_group_set
    ] if intra_enabled else []
    inter_hosts = [
        h
        for h in policy.servers
        if not (set(h.groups) & vantage_group_set) and h.ip not in policy_destination_ips
    ] if inter_enabled else []

    candidates: list[tuple[float, Server, str]] = [
        *(
            _host_candidate(host, "intra_segment", score, discovery_context, segment_sensitivity_fn)
            for host in intra_hosts
        ),
        *(
            _host_candidate(host, "inter_segment", score, discovery_context, segment_sensitivity_fn)
            for host in inter_hosts
        ),
    ]

    budget = _adjust_budget(
        _lateral_budget(max((segment_sensitivity_fn(g) for g in vantage_groups), default=0)),
        len(candidates),
    )

    return _select_top_hosts(candidates, budget)


def _select_top_hosts(
    candidates: list[tuple[float, Server, str]],
    budget: int,
) -> list[TestCase]:
    """Return up to *budget* hosts by descending score (IP breaks ties)."""
    if not candidates:
        return []

    ordered = sorted(candidates, key=lambda c: (-c[0], c[1].ip))

    return [
        TestCase(
            dst_ip=host.ip,
            # dst_port is unused for host_scan tasks; 0 is a placeholder.
            dst_port=0,
            proto="tcp",
            strategy="discovery",
            context=context,
            priority=int(score_val),
            scan_mode="host_scan",
        )
        for score_val, host, context in ordered[:budget]
    ]


# ── Safety net ──


def generate_safety_net_tests(
    *,
    policy: SegmentationPolicy,
    config,
    src_ip: str,
    groups: tuple[str, ...],
    tested_ips: set[str],
) -> list[TestCase]:
    """Port-22 liveness probe for every declared server not already covered by a policy test.

    Gated by the same independent intra-/inter-segment opt-ins as
    generate_lateral_discovery_tests(), since it is discovery evidence
    (strategy="discovery"); otherwise "discovery disabled" would still produce
    UNDECLARED_CONNECTIVITY findings.
    """
    intra_enabled = config.enable_lateral_discovery or config.enable_intra_segment_discovery
    inter_enabled = config.enable_lateral_discovery
    if not intra_enabled and not inter_enabled:
        return []

    vantage_group_set = set(groups)
    tests: list[TestCase] = []
    all_ips = {s.ip for s in policy.servers if s.ip != src_ip}

    for ip in sorted(all_ips - tested_ips):
        # groups_for_ip(), not segment_for_ip(), which is None for multi-group
        # destinations and would always classify them as inter_segment.
        ip_groups = set(policy.groups_for_ip(ip))
        is_intra = bool(ip_groups & vantage_group_set)
        if is_intra and not intra_enabled:
            continue
        if not is_intra and not inter_enabled:
            continue
        tests.append(
            TestCase(
                dst_ip=ip,
                dst_port=22,
                proto="tcp",
                strategy="discovery",
                context="intra_segment" if is_intra else "inter_segment",
                priority=1,
            )
        )

    return tests


# ── Budget helpers ──


def _lateral_budget(segment_sensitivity_score: int) -> int:
    if segment_sensitivity_score >= 50:
        return 40
    if segment_sensitivity_score >= 25:
        return 15
    return 5


def _adjust_budget(base: int, num_hosts: int) -> int:
    if num_hosts > 100:
        return max(5, int(base * 0.5))
    if num_hosts > 50:
        return max(5, int(base * 0.75))
    return base


# ── Policy destination helpers ──


def _policy_destination_ips(policy: SegmentationPolicy) -> set[str]:
    destination_ips: set[str] = set()

    for rule in policy.rules:
        destination_ips.update(policy.resolve_dst_ips(rule))

    for tr in policy.mandatory_transit_paths:
        dst_servers = policy.servers_in(tr.dst)
        if not dst_servers:
            srv = policy.get_server(tr.dst)
            if srv:
                dst_servers = [srv]

        for srv in dst_servers:
            destination_ips.add(srv.ip)

    return destination_ips
