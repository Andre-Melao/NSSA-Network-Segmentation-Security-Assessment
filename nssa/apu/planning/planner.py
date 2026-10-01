from __future__ import annotations
from dataclasses import dataclass


LATERAL_PORTS: frozenset[int] = frozenset({22, 80, 443, 3389, 445})


@dataclass(slots=True, frozen=True)
class TestCase:
    dst_ip: str
    dst_port: int
    proto: str
    strategy: str
    context: str
    priority: int
    scan_mode: str = "single_probe"  # "host_scan" | "single_probe"


# TestCase must be defined above before these submodules are imported:
# plan_policy_validation_phase.py and plan_discovery_phase.py both import
# TestCase back from this module, so this is a deliberate circular-import
# resolution order, not disorganized placement. Do not move to file top.
from nssa.apu.planning.host_scoring import DiscoveryContext
from nssa.apu.planning.plan_policy_validation_phase import (
    generate_direct_rule_tests,
    generate_transitive_rule_tests,
)
from nssa.apu.planning.plan_discovery_phase import (
    generate_lateral_discovery_tests,
    generate_safety_net_tests,
)
from nssa.apu.planning.priority import priority
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.reachability import ExpectedConnectivityModel


def generate_tests(
    *,
    policy: SegmentationPolicy,
    reachability: ExpectedConnectivityModel,
    config,
    groups: tuple[str, ...],
    src_ip: str,
    segment_sensitivity_fn,
    discovery_context: DiscoveryContext | None = None,
    is_host_mode: bool = False,
) -> list[TestCase]:
    """Generate policy-derived forbidden reachability tests only.

    is_host_mode -- forwarded to generate_direct_rule_tests() only (see its
    own docstring); no other phase's own-group handling changes. Default
    False reproduces today's exact behavior for every existing caller.
    """
    vantage_groups = tuple(groups)
    seen: set[tuple[str, int, str]] = set()
    tests: list[TestCase] = []
    key_to_index: dict[tuple[str, int, str], int] = {}

    def score(*, port: int = 0, strategy: str, context: str, dst_segment: str | None, host_score: float = 0.0, pivot_score: float = 0.0) -> int:
        return priority(
            port,
            strategy=strategy,
            context=context,
            dst_segment=dst_segment,
            sensitivity_fn=segment_sensitivity_fn,
            host_score=host_score,
            pivot_score=pivot_score,
        )

    def add_candidate(
        *,
        dst_ip: str,
        dst_port: int,
        proto: str,
        strategy: str,
        context: str,
        priority_value: int,
        scan_mode: str = "single_probe",
    ) -> bool:
        key = (dst_ip, dst_port, proto)

        if key in seen:
            idx = key_to_index[key]
            if priority_value > tests[idx].priority:
                tests[idx] = TestCase(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto=proto,
                    strategy=strategy,
                    context=context,
                    priority=priority_value,
                    scan_mode=scan_mode,
                )
            return False

        seen.add(key)
        key_to_index[key] = len(tests)
        tests.append(
            TestCase(
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                strategy=strategy,
                context=context,
                priority=priority_value,
                scan_mode=scan_mode,
            )
        )
        return True

    def add_candidate_from_test(candidate: TestCase) -> bool:
        return add_candidate(
            dst_ip=candidate.dst_ip,
            dst_port=candidate.dst_port,
            proto=candidate.proto,
            strategy=candidate.strategy,
            context=candidate.context,
            priority_value=candidate.priority,
            scan_mode=candidate.scan_mode,
        )

    for candidate in generate_direct_rule_tests(
        reachability=reachability,
        groups=vantage_groups,
        src_ip=src_ip,
        score=score,
        is_host_mode=is_host_mode,
    ):
        add_candidate_from_test(candidate)

    for candidate in generate_transitive_rule_tests(
        policy=policy,
        groups=vantage_groups,
        score=score,
    ):
        add_candidate_from_test(candidate)

    for candidate in generate_lateral_discovery_tests(
        policy=policy,
        config=config,
        groups=vantage_groups,
        src_ip=src_ip,
        score=score,
        segment_sensitivity_fn=segment_sensitivity_fn,
        discovery_context=discovery_context,
    ):
        add_candidate_from_test(candidate)

    for candidate in generate_safety_net_tests(
        policy=policy,
        config=config,
        src_ip=src_ip,
        groups=vantage_groups,
        tested_ips={t.dst_ip for t in tests},
    ):
        add_candidate_from_test(candidate)

    tests.sort(key=lambda t: (-t.priority, t.dst_ip, t.dst_port, t.proto))
    return tests
