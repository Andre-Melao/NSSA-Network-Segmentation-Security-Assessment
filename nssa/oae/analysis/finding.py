"""Finding classification and aggregation.

Pipeline: ReachabilityEvidence -> FindingCandidate -> PolicyFinding.

The ECM is the source of truth for direct authorization. The APU context hint
is only a hint, except "transitive_rule_bypass", which is authoritative.
Evidence under a mandatory transit rule is checked against the TCM first; a
compliant route is not a finding. A confirmed bypass is also evaluated against
the ECM, since route compliance and endpoint authorization are independent.

Aggregation keys:

  GROUP_ISOLATION_VIOLATION     -> (type, src_segment, dst_segment)
  HOST_SCOPED_ACCESS_VIOLATION  -> (type, src_segment, dst_ip, dst_port)
  MANDATORY_TRANSIT_PATH_BYPASS -> (type, src_segment, via_hop, dst_segment)
  UNDECLARED_CONNECTIVITY       -> (type, src_segment, dst_ip)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from nssa.oae.analysis.reachability import ReachabilityEvidence, ReachabilityIndex
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.reachability import (
    ExpectedConnectivityModel,
    TransitConstraintModel,
    resolve_principal_ips,
)


# ── Taxonomy ──────────────────────────────────────────────────────────────────


class FindingType(str, Enum):
    GROUP_ISOLATION_VIOLATION = "group_isolation_violation"
    HOST_SCOPED_ACCESS_VIOLATION = "host_scoped_access_violation"
    MANDATORY_TRANSIT_PATH_BYPASS = "mandatory_transit_path_bypass"
    UNDECLARED_CONNECTIVITY = "undeclared_connectivity"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"    # expectativa explícita na política foi violada
    UNDECLARED = "undeclared"  # conectividade observada não coberta por qualquer regra


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    """One classified observed edge, not yet aggregated."""

    finding_type: FindingType
    confidence: Confidence
    observed_edge: ReachabilityEvidence
    src_segment: str
    dst_segment: str | None
    violated_rule_ids: frozenset[str]
    via_hop: str | None = None                       # MANDATORY_TRANSIT_PATH_BYPASS only
    authorized_src_ips: frozenset[str] = frozenset() # HOST_SCOPED only: IPs that ARE permitted
    authorized_groups: frozenset[str] = frozenset()  # GROUP_ISOLATION only: groups that ARE authorized


@dataclass(slots=True, frozen=True)
class PolicyFinding:
    """Aggregated finding keyed by failed control; unused scope fields are None."""

    finding_type: FindingType
    confidence: Confidence
    src_segment: str
    dst_segment: str | None   # GROUP_ISOLATION, MANDATORY_TRANSIT_PATH_BYPASS
    dst_ip: str | None        # HOST_SCOPED_ACCESS, UNDECLARED_CONNECTIVITY
    dst_port: int | None      # HOST_SCOPED_ACCESS only
    via_hop: str | None       # MANDATORY_TRANSIT_PATH_BYPASS only
    rule_ids: frozenset[str]
    evidence: tuple[FindingCandidate, ...]


# ── Aggregation ───────────────────────────────────────────────────────────────


def _control_key(candidate: FindingCandidate) -> tuple:
    t = candidate.finding_type
    s = candidate.src_segment
    e = candidate.observed_edge
    if t == FindingType.GROUP_ISOLATION_VIOLATION:
        return (t, s, candidate.dst_segment)
    if t == FindingType.HOST_SCOPED_ACCESS_VIOLATION:
        return (t, s, e.dst_ip, e.port)
    if t == FindingType.MANDATORY_TRANSIT_PATH_BYPASS:
        return (t, s, candidate.via_hop, candidate.dst_segment)
    # UNDECLARED_CONNECTIVITY
    return (t, s, e.dst_ip)


def aggregate_candidates(candidates: list[FindingCandidate]) -> list[PolicyFinding]:
    """Aggregate candidates into one PolicyFinding per failed control key."""
    groups: dict[tuple, list[FindingCandidate]] = defaultdict(list)
    for c in candidates:
        groups[_control_key(c)].append(c)

    findings: list[PolicyFinding] = []
    for group in groups.values():
        first = group[0]
        t = first.finding_type
        e = first.observed_edge
        all_rule_ids = frozenset().union(*(c.violated_rule_ids for c in group))

        if t == FindingType.GROUP_ISOLATION_VIOLATION:
            findings.append(PolicyFinding(
                finding_type=t,
                confidence=Confidence.CONFIRMED,
                src_segment=first.src_segment,
                dst_segment=first.dst_segment,
                dst_ip=None,
                dst_port=None,
                via_hop=None,
                rule_ids=all_rule_ids,
                evidence=tuple(group),
            ))

        elif t == FindingType.HOST_SCOPED_ACCESS_VIOLATION:
            findings.append(PolicyFinding(
                finding_type=t,
                confidence=Confidence.CONFIRMED,
                src_segment=first.src_segment,
                dst_segment=first.dst_segment,
                dst_ip=e.dst_ip,
                dst_port=e.port,
                via_hop=None,
                rule_ids=all_rule_ids,
                evidence=tuple(group),
            ))

        elif t == FindingType.MANDATORY_TRANSIT_PATH_BYPASS:
            findings.append(PolicyFinding(
                finding_type=t,
                confidence=Confidence.CONFIRMED,
                src_segment=first.src_segment,
                dst_segment=first.dst_segment,
                dst_ip=None,
                dst_port=None,
                via_hop=first.via_hop,
                rule_ids=all_rule_ids,
                evidence=tuple(group),
            ))

        else:  # UNDECLARED_CONNECTIVITY
            findings.append(PolicyFinding(
                finding_type=t,
                confidence=Confidence.UNDECLARED,
                src_segment=first.src_segment,
                dst_segment=first.dst_segment,
                dst_ip=e.dst_ip,
                dst_port=None,
                via_hop=None,
                rule_ids=frozenset(),
                evidence=tuple(group),
            ))

    return findings


# ── Observation-scope filtering ─────────────────────────────────────────────────

def exclude_intra_zone_candidates(
    candidates: list[FindingCandidate],
    individually_observed_ips: "frozenset[str] | set[str]" = frozenset(),
) -> list[FindingCandidate]:
    """Drop candidates whose source and destination share a segment.

    A zone-level (Representative) probe cannot support a verdict on intra-zone
    policy. Candidates whose src_ip is in *individually_observed_ips* are kept.
    Dropped candidates still remain in the ObservedGraph and ReachabilityIndex.
    """
    return [
        c for c in candidates
        if c.src_segment != c.dst_segment or c.observed_edge.src_ip in individually_observed_ips
    ]


# ── Reachability pipeline ─────────────────────────────────────────────────────


def _group_label(groups: tuple[str, ...]) -> str:
    """Collapse a group set to one display string (sorted, "+"-joined; "" if empty)."""
    if not groups:
        return ""
    if len(groups) == 1:
        return groups[0]
    return "+".join(sorted(groups))


def classify_reachability_evidence(
    evidence: ReachabilityEvidence,
    *,
    ecm: ExpectedConnectivityModel,
    transitive: TransitConstraintModel,
    policy: SegmentationPolicy,
    individually_observed_ips: "frozenset[str] | set[str]" = frozenset(),
    directly_refuted_tuples: "frozenset[tuple[str, str, int, str]] | set[tuple[str, str, int, str]]" = frozenset(),
    probe_groups: "dict[str, tuple[str, ...]] | None" = None,
) -> FindingCandidate | None:
    """Classify one ReachabilityEvidence entry against the ECM and APU hints.

    Every state (OPEN, OPEN_FILTERED, CLOSED) proves network-level reachability.
    Handles the APU transitive_rule_bypass hint, then the ECM check. Returns
    None for authorized connections or unknown source segments.

    When inferred (hop_count > 0) evidence is contradicted by a direct
    policy_validation probe of the same tuple that came back FILTERED, the
    direct observation wins (individually_observed_ips/directly_refuted_tuples).
    """
    # Authorization scope is the union of all the source's groups: declared
    # membership, then probe_groups, then CIDR fallback.
    src_groups = policy.resolved_groups_for_ip(evidence.src_ip, probe_groups=probe_groups)
    if not src_groups:
        return None

    # A direct refutation of this tuple outranks an inferred path. Skipped for
    # direct observations, representative sensors, and self-probes
    # (shortest_path[-2] == dst_ip).
    directly_refuted = (
        evidence.hop_count > 0
        and evidence.src_ip in individually_observed_ips
        and evidence.shortest_path[-2] != evidence.dst_ip
        and (evidence.src_ip, evidence.dst_ip, evidence.port, evidence.proto) in directly_refuted_tuples
    )

    # Case 1: APU transitive-bypass hint (fallback when TCM intent is absent).
    if evidence.context == "transitive_rule_bypass":
        rule_ids = _transitive_rule_ids(transitive, policy, src_groups, evidence)
        via_hop = _resolve_via_hop(policy, src_groups, evidence)
        dst_segment = _resolve_dst_segment(policy, ecm, evidence)
        return FindingCandidate(
            finding_type=FindingType.MANDATORY_TRANSIT_PATH_BYPASS,
            confidence=Confidence.CONFIRMED,
            observed_edge=evidence,
            src_segment=_group_label(src_groups),
            dst_segment=dst_segment,
            violated_rule_ids=rule_ids,
            via_hop=via_hop,
        )

    # Cases 2–5 — ECM is the source of truth.
    entry = ecm.get(evidence.dst_ip, evidence.port, evidence.proto)

    if entry is None:
        return FindingCandidate(
            finding_type=FindingType.UNDECLARED_CONNECTIVITY,
            confidence=Confidence.UNDECLARED,
            observed_edge=evidence,
            src_segment=_group_label(src_groups),
            dst_segment=policy.segment_for_ip(evidence.dst_ip),
            violated_rule_ids=frozenset(),
        )

    # ANY group authorizes (see ExpectedConnectivity.allows_any()).
    if entry.allows_any(groups=src_groups, src_ip=evidence.src_ip):
        return None

    dst_segment = entry.dst_group

    if directly_refuted:
        return None

    # Host-scoped rule ids/hosts across all of src_groups.
    rule_ids, authorized_hosts = entry.host_scoped_context(groups=src_groups)
    if authorized_hosts:
        return FindingCandidate(
            finding_type=FindingType.HOST_SCOPED_ACCESS_VIOLATION,
            confidence=Confidence.CONFIRMED,
            observed_edge=evidence,
            src_segment=_group_label(src_groups),
            dst_segment=dst_segment,
            violated_rule_ids=rule_ids,
            authorized_src_ips=authorized_hosts,
        )

    # Host Mode intra-group check: a source verified as itself that shares a
    # group with the destination, with no explicit authorization above, is
    # undeclared intra-group connectivity, not a group-boundary crossing. Rules
    # granting other groups access INTO this group do not apply to it.
    # Host Mode only; Representative intra-zone evidence is excluded elsewhere.
    if evidence.src_ip in individually_observed_ips:
        dst_groups = policy.resolved_groups_for_ip(evidence.dst_ip, probe_groups=probe_groups)
        if set(src_groups) & set(dst_groups):
            return FindingCandidate(
                finding_type=FindingType.UNDECLARED_CONNECTIVITY,
                confidence=Confidence.UNDECLARED,
                observed_edge=evidence,
                src_segment=_group_label(src_groups),
                dst_segment=dst_segment,
                violated_rule_ids=frozenset(),
            )

    # Cite the rules governing this (dst_ip, port, proto) for other groups;
    # none covered the observer. IMPLICIT_DEFAULT_DENY (summary.py) covers the
    # empty case.
    relevant_rule_ids = (
        frozenset().union(*entry.rule_ids_by_group.values())
        if entry.rule_ids_by_group else frozenset()
    )
    return FindingCandidate(
        finding_type=FindingType.GROUP_ISOLATION_VIOLATION,
        confidence=Confidence.CONFIRMED,
        observed_edge=evidence,
        src_segment=_group_label(src_groups),
        dst_segment=dst_segment,
        violated_rule_ids=relevant_rule_ids,
        authorized_groups=frozenset(entry.allowed_groups),
    )


def _find_bypass_evidence(
    evidence: ReachabilityEvidence,
    rule_ids: frozenset[str],
    bypass_indices: dict[str, ReachabilityIndex],
) -> ReachabilityEvidence | None:
    """Return bypass-path evidence from the first confirming bypass index.

    The bypass index is built with the mandatory transit host(s) excluded.
    Returns None when no bypass path exists (source is compliant). Rule IDs are
    checked in sorted order for determinism.
    """
    for rule_id in sorted(rule_ids):
        bypass_index = bypass_indices.get(rule_id)
        if bypass_index is None:
            continue
        dst_sources = bypass_index.get(evidence.dst_ip)
        if dst_sources is not None:
            bypass_ev = dst_sources.get((evidence.src_ip, evidence.port, evidence.proto))
            if bypass_ev is not None:
                return bypass_ev
    return None


def classify_reachability_index(
    index: ReachabilityIndex,
    *,
    ecm: ExpectedConnectivityModel,
    transitive: TransitConstraintModel,
    policy: SegmentationPolicy,
    bypass_indices: dict[str, ReachabilityIndex],
    individually_observed_ips: "frozenset[str] | set[str]" = frozenset(),
    directly_refuted_tuples: "frozenset[tuple[str, str, int, str]] | set[tuple[str, str, int, str]]" = frozenset(),
    probe_groups: "dict[str, tuple[str, ...]] | None" = None,
) -> list[FindingCandidate]:
    """Classify all entries in a ReachabilityIndex against the authorization model.

    TCM intent is checked for every entry, including direct (hop_count=0)
    connections: a source present in the bypass index reaches the destination
    without the required transit, so it is a bypass. A confirmed bypass is
    also classified against the ECM (skipped if its context is
    "transitive_rule_bypass", which would duplicate the finding). Compliant
    TCM paths never reach that check. Non-TCM entries go through
    classify_reachability_evidence().
    """
    candidates: list[FindingCandidate] = []

    for dst_ip, sources in index.items():
        for (src_ip, port, proto), evidence in sources.items():

            # TCM check (all entries, hop_count-agnostic).
            if transitive.has_intent(src_ip, dst_ip, port, proto):
                rule_ids = frozenset(transitive.mtp_ids(src_ip, dst_ip, port, proto))
                bypass_ev = _find_bypass_evidence(evidence, rule_ids, bypass_indices)
                if bypass_ev is None:
                    continue  # no bypass path found → source is compliant

                # Use the bypass-index evidence so the auditor sees the actual
                # bypass route. resolved_groups_for_ip() covers sources outside
                # the SPM (CIDR fallback); () yields "".
                src_groups = policy.resolved_groups_for_ip(src_ip, probe_groups=probe_groups)
                via_hop = _resolve_via_hop(policy, src_groups, bypass_ev)
                dst_segment = _resolve_dst_segment(policy, ecm, bypass_ev)
                candidates.append(FindingCandidate(
                    finding_type=FindingType.MANDATORY_TRANSIT_PATH_BYPASS,
                    confidence=Confidence.CONFIRMED,
                    observed_edge=bypass_ev,
                    src_segment=_group_label(src_groups),
                    dst_segment=dst_segment,
                    violated_rule_ids=rule_ids,
                    via_hop=via_hop,
                ))

                # Also evaluate the ECM: transit and endpoint authorization are
                # independent controls. Skipped for "transitive_rule_bypass"
                # context (it would duplicate the finding above).
                if bypass_ev.context != "transitive_rule_bypass":
                    ecm_candidate = classify_reachability_evidence(
                        bypass_ev, ecm=ecm, transitive=transitive, policy=policy,
                        individually_observed_ips=individually_observed_ips,
                        directly_refuted_tuples=directly_refuted_tuples,
                        probe_groups=probe_groups,
                    )
                    if ecm_candidate is not None:
                        candidates.append(ecm_candidate)
                continue

            # Non-TCM entries: ECM + context-hint classification.
            candidate = classify_reachability_evidence(
                evidence, ecm=ecm, transitive=transitive, policy=policy,
                individually_observed_ips=individually_observed_ips,
                directly_refuted_tuples=directly_refuted_tuples,
                probe_groups=probe_groups,
            )
            if candidate is not None:
                candidates.append(candidate)

    return candidates


# ── Private helpers ───────────────────────────────────────────────────────────


def _transitive_rule_ids(
    transitive: TransitConstraintModel,
    policy: SegmentationPolicy,
    src_groups: tuple[str, ...],
    edge: ReachabilityEvidence,
) -> frozenset[str]:
    """Return rule IDs for a transitive bypass finding.

    Uses the transitive model (indexed by src_ip), falling back to scanning
    policy rules by group membership if the probe IP is not a declared server.
    """
    rule_ids = transitive.mtp_ids(edge.src_ip, edge.dst_ip, edge.port, edge.proto)
    if rule_ids:
        return frozenset(rule_ids)

    # Fallback for vantage hosts not in the SPM server list.
    # resolve_principal_ips() because servers_in() omits multi-group rule.dst.
    result: set[str] = set()
    for rule in policy.mandatory_transit_paths:
        if rule.src not in src_groups:
            continue
        if rule.ports and edge.port not in rule.ports:
            continue
        if rule.proto and rule.proto.lower() != edge.proto.lower():
            continue
        dst_ips = set(resolve_principal_ips(policy, rule.dst))
        if edge.dst_ip in dst_ips:
            result.add(rule.rule_id)
    return frozenset(result)


def _resolve_via_hop(
    policy: SegmentationPolicy,
    src_groups: tuple[str, ...],
    edge: ReachabilityEvidence,
) -> str | None:
    """Return the IP of the mandatory transit server violated by edge.

    Falls back to the host name if the policy server record is not found.
    """
    for rule in policy.mandatory_transit_paths:
        if rule.src not in src_groups:
            continue
        if rule.ports and edge.port not in rule.ports:
            continue
        if rule.proto and rule.proto.lower() != edge.proto.lower():
            continue
        dst_ips = set(resolve_principal_ips(policy, rule.dst))
        if edge.dst_ip in dst_ips:
            via_server = policy.get_server(rule.via)
            if via_server is not None:
                return via_server.ip
            return rule.via  # fallback: group/segment name when via is not a declared server
    return None


def _resolve_dst_segment(
    policy: SegmentationPolicy,
    ecm: ExpectedConnectivityModel,
    edge: ReachabilityEvidence,
) -> str | None:
    """Resolve destination segment from ECM entry or policy CIDR lookup."""
    entry = ecm.get(edge.dst_ip, edge.port, edge.proto)
    if entry is not None and entry.dst_group is not None:
        return entry.dst_group
    return policy.segment_for_ip(edge.dst_ip)
