"""Finding correlation: group RawFindings by exposed service.

An AuditFinding is the exposure of one service (dst_ip, dst_port, proto); every
RawFinding for that service belongs to it, whatever its type, rule or
confidence. This makes the audit question explicit: "Who can reach this service?"

source_hosts is a tuple of HostRef sorted by IP, with names from the optional
host_names mapping. violated_rules and representative_paths come from later
stages; no scoring, ordering or evidence selection happens here.
"""

from __future__ import annotations

from collections import defaultdict

from nssa.oae.analysis.finding import Confidence
from nssa.oae.audit.models import AuditFinding, FindingReason, HostRef, RawFinding


def _group_key(r: RawFinding) -> tuple[str, int, str]:
    return (r.dst_ip, r.dst_port, r.proto)


def correlate(
    raw_findings: list[RawFinding],
    *,
    host_names: dict[str, str] | None = None,
) -> list[AuditFinding]:
    """Group RawFindings into AuditFindings by (dst_ip, dst_port, proto).

    host_names: optional IP -> hostname mapping (e.g.
        {server.ip: server.name for server in policy.servers}); sets
        HostRef.name for source_hosts and dst_name.
    reason: DIRECT_POLICY_VIOLATION if any member is CONFIRMED, else
        UNEXPECTED_REACHABILITY.

    violated_rules is None here; build_violated_rules() fills it.
    """
    buckets: dict[tuple[str, int, str], list[RawFinding]] = defaultdict(list)
    for r in raw_findings:
        buckets[_group_key(r)].append(r)

    findings: list[AuditFinding] = []
    for (dst_ip, dst_port, proto), members in buckets.items():
        dst_segment = next(
            (r.dst_segment for r in members if r.dst_segment is not None),
            None,
        )
        has_confirmed = any(r.confidence == Confidence.CONFIRMED for r in members)
        reason = (
            FindingReason.DIRECT_POLICY_VIOLATION
            if has_confirmed
            else FindingReason.UNEXPECTED_REACHABILITY
        )
        dst_name = host_names.get(dst_ip) if host_names else None

        # Deduplicate by IP and resolve names.
        seen_ips: dict[str, HostRef] = {}
        for r in members:
            if r.src_ip not in seen_ips:
                name = host_names.get(r.src_ip) if host_names else None
                seen_ips[r.src_ip] = HostRef(ip=r.src_ip, name=name)
        source_hosts = tuple(sorted(seen_ips.values(), key=lambda h: h.ip))

        findings.append(AuditFinding(
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            dst_segment=dst_segment,
            dst_name=dst_name,
            reason=reason,
            source_hosts=source_hosts,
            source_groups=tuple(sorted({r.src_segment for r in members})),
            raw_findings=tuple(members),
        ))
    return findings
