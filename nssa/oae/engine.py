"""OAE evaluation pipeline.

Turns observed connectivity and a segmentation policy into AuditFindings in
three stages: reachability (reverse BFS, also run over a declared-only Policy
Graph), classification against the ECM/TCM, and audit enrichment.

Entry points: OAEEngine (ingestion + evaluation) and evaluate().
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from nssa.oae.analysis.finding import (
    FindingCandidate,
    FindingType,
    PolicyFinding,
    _group_label,
    aggregate_candidates,
    classify_reachability_index,
    exclude_intra_zone_candidates,
)
from nssa.oae.analysis.policy_graph import build_policy_graph
from nssa.oae.analysis.reachability import ReachabilityIndex, build_reachability_index
from nssa.oae.audit import build_audit_findings
from nssa.oae.audit.models import AuditFinding
from nssa.oae.observed.graph import ObservedGraph, build_graph
from nssa.oae.observed.ingest import build_observed_matrix
from nssa.oae.observed.matrix import ObservedMatrix
from nssa.shared.deployment import Deployment
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.reachability import (
    ExpectedConnectivityModel,
    TransitConstraintModel,
    build_expected_connectivity,
    build_transit_constraint_model,
    resolve_principal_ips,
)

if TYPE_CHECKING:
    from nacl.signing import VerifyKey


@dataclass(slots=True)
class OAEAnalysisResult:
    """Output of the OAE pipeline.

    graph              - observed connectivity graph.
    policy_findings    - one per failed policy control (inter-zone only;
                         intra-zone observations are excluded upstream).
    audit_findings     - enriched inter-zone exposures, one per exposed
                         (dst_ip, dst_port, proto) service, with stable
                         "AF-000N" ids. `reason` is metadata only.
    violation_targets  - destination IPs present in at least one AuditFinding.
    pivots             - intermediate hosts in multi-hop reachability paths.
    host_names         - IP -> display name mapping used by every AuditFinding.
    """

    graph: ObservedGraph
    policy_findings: list[PolicyFinding]
    audit_findings: list[AuditFinding]
    violation_targets: set[str]
    pivots: set[str]
    host_names: dict[str, str]


def _classify_graph(
    graph: ObservedGraph,
    *,
    ecm: ExpectedConnectivityModel,
    transitive: TransitConstraintModel,
    policy: SegmentationPolicy,
    extra_destinations: set[str],
    individually_observed_ips: set[str] | None = None,
    directly_refuted_tuples: set[tuple[str, str, int, str]] | None = None,
    probe_groups: dict[str, tuple[str, ...]] | None = None,
) -> list[FindingCandidate]:
    """Run Reachability + Classification (stages 1-2) against one graph.

    Shared by the observed graph and the Policy Graph; only the graph differs.
    """
    destinations = (
        {e.dst_ip for e in graph.edges}
        | {ck.dst_ip for ck in ecm.entries}
        | {ck.dst_ip for ck in transitive.entries}
        | extra_destinations
    )

    reachability_index: ReachabilityIndex = build_reachability_index(
        graph, destinations=destinations
    )

    # Bypass indices for TCM validation: one per transitive rule, with the
    # rule's transit host(s) excluded from traversal. A bypass must avoid ALL
    # resolved via IPs.
    bypass_indices: dict[str, ReachabilityIndex] = {}
    for rule in policy.mandatory_transit_paths:
        via_ips = resolve_principal_ips(policy, rule.via)
        if not via_ips:
            continue
        bypass_indices[rule.rule_id] = build_reachability_index(
            graph, destinations=destinations, excluded_hosts=set(via_ips),
        )

    return classify_reachability_index(
        reachability_index,
        ecm=ecm,
        transitive=transitive,
        policy=policy,
        bypass_indices=bypass_indices,
        individually_observed_ips=individually_observed_ips,
        directly_refuted_tuples=directly_refuted_tuples,
        probe_groups=probe_groups,
    )


def evaluate(
    *,
    policy: SegmentationPolicy | None,
    observed: ObservedMatrix,
    individually_observed_ips: set[str] | None = None,
    directly_refuted_tuples: set[tuple[str, str, int, str]] | None = None,
    probe_groups: dict[str, tuple[str, ...]] | None = None,
) -> OAEAnalysisResult:
    """Run the OAE pipeline end-to-end.

    Returns an OAEAnalysisResult with AuditFindings sorted by descending
    priority. When policy is None only the graph is built.

    individually_observed_ips - IPs observed as themselves (Host Mode).
    directly_refuted_tuples   - (src_ip, dst_ip, port, proto) refuted by a
                                direct probe; see classify_reachability_evidence().
    probe_groups              - {probe.ip: probe.groups} from the Deployment,
                                used to resolve a sensor's groups without CIDRs.
    """
    # Coalesced once so downstream code always receives a real set.
    individually_observed_ips = individually_observed_ips or frozenset()
    directly_refuted_tuples = directly_refuted_tuples or frozenset()

    graph = build_graph(observed)

    if policy is None:
        return OAEAnalysisResult(
            graph=graph,
            policy_findings=[],
            audit_findings=[],
            violation_targets=set(),
            pivots=set(),
            host_names={},
        )

    # Criticality is looked up by dst_ip since dst_segment is None for
    # multi-group destinations.
    def segment_criticality(ip: str) -> str:
        return policy.criticality_for_ip(ip, probe_groups=probe_groups)

    host_names = {s.ip: s.name for s in policy.servers}

    # A sensor IP that is not a declared SPM host is labelled
    # "probe-<group(s)>"; a declared host keeps its real name.
    sensor_ips = {e.src_ip for e in graph.edges}
    for ip in sensor_ips:
        if ip not in host_names:
            groups = policy.resolved_groups_for_ip(ip, probe_groups=probe_groups)
            if groups:
                host_names[ip] = f"probe-{_group_label(groups)}"

    ecm = build_expected_connectivity(policy)
    # probe_groups lets a Representative probe's IP stand in for its groups when
    # resolving a transit path's src principal.
    transitive = build_transit_constraint_model(policy, probe_groups=probe_groups)

    # Policy destinations are always in scope, probed or not.
    policy_destinations = (
        {ck.dst_ip for ck in ecm.entries} | {ck.dst_ip for ck in transitive.entries}
    )

    # ── Stage 1-2: Reachability + Classification, observed graph ─────────────
    observed_candidates = _classify_graph(
        graph, ecm=ecm, transitive=transitive, policy=policy,
        extra_destinations=policy_destinations,
        individually_observed_ips=individually_observed_ips,
        directly_refuted_tuples=directly_refuted_tuples,
        probe_groups=probe_groups,
    )

    # ── Stage 1-2 again: Policy Graph ────────────────────────────────────────
    #
    # Same machinery over a graph built only from the SPM's direct rules, to
    # catch bypasses the policy implies by composition. Only
    # MANDATORY_TRANSIT_PATH_BYPASS candidates are kept; the ECM-fallback
    # findings are discarded.
    policy_graph = build_policy_graph(policy)
    policy_candidates = _classify_graph(
        policy_graph, ecm=ecm, transitive=transitive, policy=policy,
        extra_destinations=policy_destinations,
        individually_observed_ips=individually_observed_ips,
        directly_refuted_tuples=directly_refuted_tuples,
        probe_groups=probe_groups,
    )
    policy_candidates = [
        c for c in policy_candidates if c.finding_type == FindingType.MANDATORY_TRANSIT_PATH_BYPASS
    ]

    # Scope the Policy Graph pass to this run's coverage: drop candidates whose
    # violated rule's own src shares no group with any host that sent or
    # received a probe (covered_groups). rule_src_groups resolves each rule's
    # src like generate_transitive_rule_tests() does (a server's groups, or
    # the group name). c.src_segment is not used, as it may combine groups.
    rule_src_groups: dict[str, set[str]] = {
        tr.rule_id: set(policy.groups_for_workload(tr.src)) or {tr.src}
        for tr in policy.mandatory_transit_paths
    }
    covered_groups = {
        g for ip in sensor_ips for g in policy.resolved_groups_for_ip(ip, probe_groups=probe_groups)
    }
    policy_candidates = [
        c for c in policy_candidates
        if any(rule_src_groups.get(rule_id, set()) & covered_groups for rule_id in c.violated_rule_ids)
    ]

    # The Policy Graph is declarative, so it never names a specific host as the
    # origin. Collapse only the origin (src_ip and shortest_path[0]) to
    # "probe-<segment>"; the rest of the path is genuine evidence.
    collapsed: list[FindingCandidate] = []
    seen_origins: set[tuple] = set()
    for c in policy_candidates:
        edge = dataclasses.replace(
            c.observed_edge,
            src_ip=f"probe-{c.src_segment}",
            shortest_path=(f"probe-{c.src_segment}",) + c.observed_edge.shortest_path[1:],
        )
        # Candidates collapsed to the same origin are indistinguishable; keep one.
        key = (c.src_segment, edge.dst_ip, edge.port, edge.proto, edge.shortest_path, c.via_hop)
        if key in seen_origins:
            continue
        seen_origins.add(key)
        collapsed.append(dataclasses.replace(c, observed_edge=edge))
    policy_candidates = collapsed

    # Drop a synthetic "probe-<segment>" candidate when an individually
    # observed host confirmed the same bypass. Identity is (violated_rule_ids,
    # dst_ip, port, proto). No-op without individually_observed_ips.
    observed_bypass_keys = {
        (c.violated_rule_ids, c.observed_edge.dst_ip, c.observed_edge.port, c.observed_edge.proto)
        for c in observed_candidates
        if c.finding_type == FindingType.MANDATORY_TRANSIT_PATH_BYPASS
        and c.observed_edge.src_ip in individually_observed_ips
    }
    policy_candidates = [
        c for c in policy_candidates
        if (c.violated_rule_ids, c.observed_edge.dst_ip, c.observed_edge.port, c.observed_edge.proto)
        not in observed_bypass_keys
    ]

    # ── Stage 2 (cont.): merge, then zone filter ─────────────────────────────
    #
    # From here, candidates from either graph are treated identically.
    candidates = exclude_intra_zone_candidates(
        observed_candidates + policy_candidates,
        individually_observed_ips=individually_observed_ips,
    )
    policy_findings = aggregate_candidates(candidates)

    # ── Stage 3: Audit ────────────────────────────────────────────────────────

    audit_findings = build_audit_findings(
        policy_findings,
        host_names=host_names,
        segment_criticality=segment_criticality,
    )

    # ── Derived metrics ───────────────────────────────────────────────────────

    violation_targets = {af.dst_ip for af in audit_findings}

    pivots: set[str] = set()
    for af in audit_findings:
        for rf in af.raw_findings:
            if rf.hop_count > 0:
                pivots.update(rf.shortest_path[1:-1])

    return OAEAnalysisResult(
        graph=graph,
        policy_findings=policy_findings,
        audit_findings=audit_findings,
        violation_targets=violation_targets,
        pivots=pivots,
        host_names=host_names,
    )


class OAEEngine:
    """Coordinates the OAE workflow for one assessment.

    ingest() validates the signed evidence into an ObservedMatrix; evaluate()
    runs the analysis. Ingest side outputs (individually observed sources,
    directly refuted tuples) are kept between the two steps.
    """

    def __init__(
        self,
        policy: SegmentationPolicy,
        *,
        deployment: Deployment | None = None,
        expected_deployment_hash: str | None = None,
    ) -> None:
        self.policy = policy
        self.deployment = deployment
        self.expected_deployment_hash = expected_deployment_hash
        self.probe_groups: dict[str, tuple[str, ...]] | None = (
            {p.ip: p.groups for p in deployment.probes if p.ip and p.groups}
            if deployment is not None else None
        )
        self.individually_observed_ips: set[str] = set()
        self.directly_refuted_tuples: set[tuple[str, str, int, str]] = set()

    def ingest(
        self,
        *,
        result_files: list[Path],
        spm_path: Path,
        verify_keys: dict[str, "VerifyKey"],
    ) -> ObservedMatrix:
        return build_observed_matrix(
            result_files=result_files,
            spm_path=spm_path,
            verify_keys=verify_keys,
            policy=self.policy,
            deployment=self.deployment,
            expected_deployment_hash=self.expected_deployment_hash,
            individually_observed_ips=self.individually_observed_ips,
            directly_refuted_tuples=self.directly_refuted_tuples,
        )

    def evaluate(self, observed: ObservedMatrix) -> OAEAnalysisResult:
        return evaluate(
            policy=self.policy,
            observed=observed,
            individually_observed_ips=self.individually_observed_ips,
            directly_refuted_tuples=self.directly_refuted_tuples,
            probe_groups=self.probe_groups,
        )

    def run(
        self,
        *,
        result_files: list[Path],
        spm_path: Path,
        verify_keys: dict[str, "VerifyKey"],
    ) -> OAEAnalysisResult:
        return self.evaluate(
            self.ingest(result_files=result_files, spm_path=spm_path, verify_keys=verify_keys)
        )
