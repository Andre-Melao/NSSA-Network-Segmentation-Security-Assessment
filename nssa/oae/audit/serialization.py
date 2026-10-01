"""Serializers for OAE audit output structures.

serialize_audit_finding() is the auditor-facing Compliance Finding serializer
(canonical output): a stable id, human-readable destination, concise
representative-path narratives, and severity. Classification-layer internals
(raw_findings, confidence, hop_count, observed_state, reachability_evidence,
authorized_src_ips) and the internal priority score are omitted.

serialize_raw_finding() is a debug-level helper (full RawFinding fidelity minus
the two heaviest evidence fields). serialize_representative_path() is its
auditor-facing counterpart.
"""

from __future__ import annotations

from nssa.oae.audit.models import AuditFinding, HostRef, RawFinding


# ── Auditor-facing (canonical output) ──

def _display_host(ip: str, host_names: dict[str, str] | None) -> str:
    """Render one IP as "name (ip)" when a hostname is known, else just "ip"."""
    name = host_names.get(ip) if host_names else None
    return str(HostRef(ip=ip, name=name))


def _display_groups(source_groups: tuple[str, ...]) -> list[str]:
    """Expand internal "+"-joined src_segment labels into a deduplicated, sorted
    list of group names (["frontend-sg", "monitoring-sg"]); the join character
    must not reach the report.
    """
    return sorted({g for label in source_groups for g in label.split("+")})


def _destination_groups(
    dst_ip: str,
    dst_segment: str | None,
    dst_groups: "dict[str, tuple[str, ...]] | None",
) -> list[str]:
    """Every group the destination workload belongs to, for auditor-facing JSON.

    dst_groups: optional IP -> groups mapping, preferred over dst_segment
    because dst_segment is None for multi-group destinations. Falls back to
    dst_segment (1-element list, or empty if None) when dst_groups is missing
    or has no entry for this IP.
    """
    if dst_groups is not None:
        groups = dst_groups.get(dst_ip)
        if groups:
            return sorted(groups)
    return [dst_segment] if dst_segment else []


def serialize_representative_path(rf: RawFinding, host_names: dict[str, str] | None = None) -> str:
    """Concise narrative of one representative reachability path.

    Renders "src (ip) -> ... -> dst (ip):port/proto", resolving hostnames via
    *host_names*; the service is appended to the final hop only. For
    MANDATORY_TRANSIT_PATH_BYPASS findings, the bypassed transit is appended.
    Classification internals are omitted (see serialize_raw_finding()).
    """
    hops = [_display_host(ip, host_names) for ip in rf.shortest_path]
    hops[-1] = f"{hops[-1]}:{rf.dst_port}/{rf.proto}"
    narrative = " -> ".join(hops)
    if rf.via_hop is not None:
        narrative += f" (bypassed mandatory transit via {_display_host(rf.via_hop, host_names)})"
    return narrative


def serialize_audit_finding(
    af: AuditFinding,
    host_names: dict[str, str] | None = None,
    dst_groups: "dict[str, tuple[str, ...]] | None" = None,
) -> dict:
    """Auditor-facing serialization of one AuditFinding (the canonical output).

    *host_names*: optional IP -> hostname mapping for intermediate/via hops.
    *dst_groups*: optional IP -> groups mapping (see _destination_groups()).

    reason is omitted: every AuditFinding is a Compliance Finding in NSSA's
    closed-world model. violated_rules is None for UNEXPECTED_REACHABILITY.
    """
    destination_host = HostRef(ip=af.dst_ip, name=af.dst_name)
    return {
        "id": af.finding_id,
        "severity": af.severity,
        "destination": f"{destination_host}:{af.dst_port}/{af.proto}",
        "destination_groups": _destination_groups(af.dst_ip, af.dst_segment, dst_groups),
        "source_hosts": [str(h) for h in af.source_hosts],
        "source_groups": _display_groups(af.source_groups),
        "violated_rules": (
            [{"rule_id": vr.rule_id, "summary": vr.summary} for vr in af.violated_rules]
            if af.violated_rules is not None else None
        ),
        "representative_paths": (
            [serialize_representative_path(rf, host_names) for rf in af.representative_paths]
            if af.representative_paths is not None else None
        ),
    }


# ── Debug/developer (full internal fidelity) ──

def serialize_raw_finding(rf: RawFinding) -> dict:
    """Debug-level serialization of one RawFinding (full classification detail)."""
    return {
        "finding_type": rf.finding_type.value,
        "confidence": rf.confidence.value,
        "src_ip": rf.src_ip,
        "src_segment": rf.src_segment,
        "dst_ip": rf.dst_ip,
        "dst_port": rf.dst_port,
        "proto": rf.proto,
        "dst_segment": rf.dst_segment,
        "violated_rule_ids": sorted(rf.violated_rule_ids),
        "via_hop": rf.via_hop,
        "observed_state": rf.observed_state.value,
        "shortest_path": list(rf.shortest_path),
        "hop_count": rf.hop_count,
    }


