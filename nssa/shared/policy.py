"""SegmentationPolicy: the fully parsed, indexed policy model.

A data structure with O(1) lookup indices and no business logic, only
structural queries. Consumed by the APU (test derivation) and the OAE
(comparison with observations).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from nssa.shared.models import Rule, Segment, Server, MandatoryTransitPath

# Criticality ordering for reducing several groups to one (unknown sorts as "low").
_CRITICALITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(slots=True)
class SegmentationPolicy:
    """Fully parsed and indexed Segmentation Policy Model."""

    # ── Core data ─────────────────────────────────────────────────────
    segments: tuple[Segment, ...]
    servers: tuple[Server, ...]
    rules: tuple[Rule, ...]
    mandatory_transit_paths: tuple[MandatoryTransitPath, ...]

    # ── Fast look-up indices (built once) ─────────────────────────────
    _seg_by_name: dict[str, Segment] = field(default_factory=dict, repr=False)
    _srv_by_name: dict[str, Server] = field(default_factory=dict, repr=False)
    # Legacy single-group indices: only servers with exactly one group;
    # multi-group workloads are absent rather than under a "primary" group.
    _srv_by_segment: dict[str, list[Server]] = field(default_factory=dict, repr=False)
    _seg_by_ip: dict[str, str] = field(default_factory=dict, repr=False)
    # Full multi-membership indices: a server appears once per group. Canonical view.
    _srv_by_group: dict[str, list[Server]] = field(default_factory=dict, repr=False)
    _groups_by_ip: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _rules_by_src: dict[str, list[Rule]] = field(default_factory=dict, repr=False)
    _rules_by_dst: dict[str, list[Rule]] = field(default_factory=dict, repr=False)
    _rule_by_id: dict[str, Rule | MandatoryTransitPath] = field(default_factory=dict, repr=False)
    # Case-insensitive fallback (lowercased -> declared casing) for get_segment()/
    # workloads_in_group(), needed for group names from a separately parsed
    # Deployment. spm_parser already resolves casing for SPM names.
    _seg_name_ci: dict[str, str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.build_indices()

    def build_indices(self) -> None:
        """Pre-compute look-up tables."""
        self._seg_by_name = {s.name: s for s in self.segments}
        self._srv_by_name = {s.name: s for s in self.servers}
        self._seg_name_ci = {s.name.lower(): s.name for s in self.segments}

        seg_map: dict[str, list[Server]] = {s.name: [] for s in self.segments}
        seg_by_ip: dict[str, str] = {}
        for srv in self.servers:
            if len(srv.groups) == 1:
                group = srv.groups[0]
                seg_map.setdefault(group, []).append(srv)
                seg_by_ip[srv.ip] = group
        self._srv_by_segment = seg_map
        self._seg_by_ip = seg_by_ip

        srv_by_group: dict[str, list[Server]] = {s.name: [] for s in self.segments}
        groups_by_ip: dict[str, tuple[str, ...]] = {}
        for srv in self.servers:
            for group in srv.groups:
                srv_by_group.setdefault(group, []).append(srv)
            groups_by_ip[srv.ip] = srv.groups
        self._srv_by_group = srv_by_group
        self._groups_by_ip = groups_by_ip

        src_map: dict[str, list[Rule]] = {}
        dst_map: dict[str, list[Rule]] = {}
        for r in self.rules:
            src_map.setdefault(r.src, []).append(r)
            dst_map.setdefault(r.dst, []).append(r)
        self._rules_by_src = src_map
        self._rules_by_dst = dst_map

        # Identity index for finding/audit attribution. Empty ids (rules built
        # outside the parser) are skipped; the parser guarantees populated ids.
        self._rule_by_id = {
            r.rule_id: r
            for r in (*self.rules, *self.mandatory_transit_paths)
            if r.rule_id
        }

    # ── Queries ───────────────────────────────────────────────────────
    def get_segment(self, name: str) -> Segment | None:
        segment = self._seg_by_name.get(name)
        if segment is not None:
            return segment
        canonical = self._seg_name_ci.get(name.lower())
        return self._seg_by_name.get(canonical) if canonical is not None else None

    def segment_criticality(self, name: str | None) -> str:
        if not name:
            return "low"
        segment = self.get_segment(name)
        if segment is None:
            return "low"
        return segment.criticality

    def get_server(self, name: str) -> Server | None:
        return self._srv_by_name.get(name)

    def segment_names(self) -> list[str]:
        return [s.name for s in self.segments]

    def servers_in(self, segment_name: str) -> list[Server]:
        return self._srv_by_segment.get(segment_name, [])

    def resolve_dst_ips(self, rule: Rule) -> list[str]:
        """Resolve rule destination to concrete IPs (uses workloads_in_group(), so multi-group members are included)."""
        srv = self.get_server(rule.dst)
        if srv is not None:
            return [srv.ip]
        return [s.ip for s in self.workloads_in_group(rule.dst)]

    def segment_for_ip(self, ip: str) -> str | None:
        """Return the name of the segment whose network contains *ip*, if any.

        O(1) for single-group servers; otherwise an O(S) CIDR scan, skipped for
        groups without a CIDR.
        """
        seg = self._seg_by_ip.get(ip)
        if seg is not None:
            return seg
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return None
        for segment in self.segments:
            if segment.network is not None and addr in segment.network:
                return segment.name
        return None

    def endpoint_segment(self, name: str) -> str | None:
        """Resolve a rule endpoint (segment or server name) to its segment.

        None for a server with zero or multiple groups (see Server.segment).
        """
        if self.get_segment(name) is not None:
            return name
        server = self.get_server(name)
        if server is None or len(server.groups) != 1:
            return None
        return server.segment

    def workloads_in_group(self, group_name: str) -> list[Server]:
        """Every server that declares *group_name* among its groups.

        The canonical membership query, complete for multi-group workloads.
        group_name also matches case-insensitively (see _seg_name_ci), since
        Deployment groups are parsed independently of the SPM.
        """
        exact = self._srv_by_group.get(group_name)
        if exact is not None:
            return exact
        canonical = self._seg_name_ci.get(group_name.lower())
        return self._srv_by_group.get(canonical, []) if canonical is not None else []

    def groups_for_ip(self, ip: str) -> tuple[str, ...]:
        """Every group the workload at *ip* belongs to, in declaration order."""
        return self._groups_by_ip.get(ip, ())

    def resolved_groups_for_ip(
        self,
        ip: str,
        probe_groups: "dict[str, tuple[str, ...]] | None" = None,
    ) -> tuple[str, ...]:
        """Every group *ip* may act as: declared SPM membership, then
        Deployment-declared probe identity, then CIDR fallback.

        Classification must resolve Representative-mode sensors, which are
        usually not declared SPM servers.

        probe_groups: optional {probe.ip: probe.groups} from Deployment.probes,
            checked before the CIDR scan. None skips it.

        The CIDR fallback (segment_for_ip(), as a 1-tuple) applies only when
        neither the SPM nor probe_groups knows the IP. Declared servers always
        take the declared-membership branch.
        """
        groups = self.groups_for_ip(ip)
        if groups:
            return groups
        if probe_groups is not None:
            declared = probe_groups.get(ip)
            if declared:
                return declared
        seg = self.segment_for_ip(ip)
        return (seg,) if seg is not None else ()

    def criticality_for_ip(
        self,
        ip: str,
        probe_groups: "dict[str, tuple[str, ...]] | None" = None,
    ) -> str:
        """Criticality of the workload at *ip*, reduced across all its groups.

        Single-group workloads get that group's criticality; multi-group
        workloads take the most severe one. Uses resolved_groups_for_ip().
        """
        groups = self.resolved_groups_for_ip(ip, probe_groups=probe_groups)
        if not groups:
            return "low"
        return max(
            (self.segment_criticality(g) for g in groups),
            key=lambda label: _CRITICALITY_ORDER.get(label, 0),
        )

    def groups_for_workload(self, name: str) -> tuple[str, ...]:
        """Every group the named workload belongs to."""
        server = self.get_server(name)
        return server.groups if server is not None else ()

    def summary(self) -> str:
        return (
            f"SPM: {len(self.segments)} segments, "
            f"{len(self.servers)} servers, "
            f"{len(self.rules)} rules, "
            f"{len(self.mandatory_transit_paths)} transitive rules"
        )
