"""Audit Intelligence aggregation pipeline; entry point build_audit_findings().

Converts the classification layer's list[PolicyFinding] into AuditFindings that
answer, per exposed service, "Who can reach this service, and why?"

Pipeline:
  1. Flatten        - PolicyFinding.evidence -> per-host RawFindings.
  2. Correlate      - group by service (dst_ip, dst_port, proto); sets reason,
                      source_hosts, source_groups, dst_name.
  3. Violated rules - ViolatedRule entries with per-control summaries.
  4. Evidence       - representative paths (novelty-driven).
  5. Priority       - priority score and severity label.
  6. Sort           - descending priority.

Every AuditFinding is a Compliance Finding with a stable "AF-000N" id
(assign_ids()). In NSSA's closed-world model, undeclared connectivity
(UNEXPECTED_REACHABILITY) is reported like a contradicted rule; `reason` stays
as internal metadata only.

The FindingCandidate -> RawFinding conversion is the only place in this layer
aware of upstream classification structures.
"""

from __future__ import annotations

import dataclasses
from typing import Callable

from nssa.oae.analysis.finding import FindingCandidate, PolicyFinding
from nssa.oae.audit.correlation import correlate
from nssa.oae.audit.evidence import select_representative_paths
from nssa.oae.audit.models import AuditFinding, RawFinding
from nssa.oae.audit.priority import DEFAULT_SECONDARY_FACTORS, ScoringFactor, score_priority
from nssa.oae.audit.summary import build_violated_rules


# ── Report identity ──


def assign_ids(findings: list[AuditFinding], prefix: str) -> list[AuditFinding]:
    """Assign sequential "{prefix}-0001".. identifiers in list order.

    Stable only within one report; not a durable cross-run identifier.
    """
    return [
        dataclasses.replace(f, finding_id=f"{prefix}-{i:04d}")
        for i, f in enumerate(findings, start=1)
    ]


# ── Flattening ──


def _candidate_to_raw(candidate: FindingCandidate) -> RawFinding:
    edge = candidate.observed_edge
    return RawFinding(
        finding_type=candidate.finding_type,
        confidence=candidate.confidence,
        src_ip=edge.src_ip,
        src_segment=candidate.src_segment,
        dst_ip=edge.dst_ip,
        dst_port=edge.port,
        proto=edge.proto,
        dst_segment=candidate.dst_segment,
        violated_rule_ids=candidate.violated_rule_ids,
        via_hop=candidate.via_hop,
        observed_state=edge.state,
        shortest_path=edge.shortest_path,
        hop_count=edge.hop_count,
        reachability_evidence=edge,
        authorized_src_ips=candidate.authorized_src_ips,
        authorized_groups=candidate.authorized_groups,
    )


def _flatten(policy_findings: list[PolicyFinding]) -> list[RawFinding]:
    result: list[RawFinding] = []
    for pf in policy_findings:
        for candidate in pf.evidence:
            result.append(_candidate_to_raw(candidate))
    return result


# ── Pipeline entry point ──


def build_audit_findings(
    policy_findings: list[PolicyFinding],
    *,
    segment_criticality: Callable[[str], str] | None = None,
    host_names: dict[str, str] | None = None,
    max_paths: int = 5,
    secondary_factors: list[ScoringFactor] | None = None,
) -> list[AuditFinding]:
    """Run the Audit Intelligence pipeline end-to-end.

    Returns AuditFindings with summary, representative evidence, priority and a
    stable "AF-000N" id, sorted by descending priority. Every finding is a
    Compliance Finding; reason is metadata only.

    segment_criticality: callable resolving dst_ip to a criticality label,
        forwarded to score_priority() (typically
        SegmentationPolicy.criticality_for_ip()); None gives severity="low".
    host_names: IP -> hostname mapping for dst_name, typically
        {server.ip: server.name}; None leaves dst_name None.
    max_paths: maximum representative RawFindings per AuditFinding.
    secondary_factors: within-band ordering factors; None uses
        DEFAULT_SECONDARY_FACTORS.
    """
    raw = _flatten(policy_findings)
    if not raw:
        return []

    secondary = secondary_factors if secondary_factors is not None else DEFAULT_SECONDARY_FACTORS

    findings = correlate(raw, host_names=host_names)

    enriched: list[AuditFinding] = []
    for f in findings:
        f = build_violated_rules(f, host_names=host_names)
        f = select_representative_paths(f, max_paths=max_paths)
        f = score_priority(
            f,
            segment_criticality=segment_criticality,
            secondary_factors=secondary,
        )
        enriched.append(f)

    enriched.sort(key=lambda f: f.priority or 0.0, reverse=True)
    return assign_ids(enriched, "AF")
