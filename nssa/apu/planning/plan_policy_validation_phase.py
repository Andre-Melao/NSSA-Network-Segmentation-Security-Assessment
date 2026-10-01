from __future__ import annotations

from collections.abc import Callable

from nssa.apu.planning.planner import TestCase
from nssa.shared.reachability import ExpectedConnectivity, ExpectedConnectivityModel
from nssa.shared.policy import SegmentationPolicy

def generate_direct_rule_tests(
    *,
    reachability: ExpectedConnectivityModel,
    groups: tuple[str, ...],
    src_ip: str,
    score: Callable[..., int],
    is_host_mode: bool = False,
) -> list[TestCase]:
    """Generate forbidden-tuple policy_validation tests for one vantage.

    is_host_mode: when True, src_ip is the exact declared workload, so the
    own-group skip in entries_to_probe_for_groups() is dropped (authorization
    checks still apply). Default False is Representative Mode behaviour.
    """
    vantage_groups = tuple(groups)
    tests: list[TestCase] = []

    for ck, entry in reachability.entries_to_probe_for_groups(
        vantage_groups, src_ip, exclude_own_group=not is_host_mode
    ):
        context = _policy_scope_context(vantage_groups, entry)
        tests.append(
            TestCase(
                dst_ip=ck.dst_ip,
                dst_port=ck.dst_port,
                proto=ck.proto,
                strategy="policy_validation",
                context=context,
                priority=score(
                    port=ck.dst_port,
                    strategy="policy_validation",
                    context=context,
                    dst_segment=entry.dst_group,
                ),
            )
        )

    tests.sort(key=lambda t: (t.dst_ip, t.dst_port, t.proto))
    return tests


def generate_transitive_rule_tests(
    *,
    policy: SegmentationPolicy,
    groups: tuple[str, ...],
    score: Callable[..., int],
) -> list[TestCase]:
    vantage_group_set = set(groups)
    tests: list[TestCase] = []

    for tr in policy.mandatory_transit_paths:
        if policy.get_segment(tr.src) is None:
            continue
        # Skip a bypass test from the vantage itself if it shares a group with the
        # mandatory transit (it may be that host) or is in the destination's
        # group. groups_for_workload() is () for a via naming a group, which is
        # then its own identity (as in resolve_principal_ips()/_resolve_via_hop()).
        via_groups = set(policy.groups_for_workload(tr.via)) or {tr.via}
        if vantage_group_set & via_groups:
            continue
        if tr.dst in vantage_group_set:
            continue

        dst_servers = policy.servers_in(tr.dst)
        if not dst_servers:
            srv = policy.get_server(tr.dst)
            if srv:
                dst_servers = [srv]

        for srv in dst_servers:
            for port in tr.ports:
                tests.append(
                    TestCase(
                        dst_ip=srv.ip,
                        dst_port=port,
                        proto=tr.proto,
                        strategy="policy_validation",
                        context="transitive_rule_bypass",
                        priority=score(
                            port=port,
                            strategy="policy_validation",
                            context="transitive_rule_bypass",
                            dst_segment=srv.segment,
                        ),
                    )
                )

    return tests

def _policy_scope_context(groups: tuple[str, ...], entry: ExpectedConnectivity) -> str:
    if any(g in entry.allowed_hosts_by_group for g in groups):
        return "host_constrained"
    return "segment_level"
