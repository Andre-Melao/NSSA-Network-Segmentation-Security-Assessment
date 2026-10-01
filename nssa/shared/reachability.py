"""Reachability semantics (ECM and TCM) derived from SegmentationPolicy."""

from __future__ import annotations

from dataclasses import dataclass, field

from nssa.shared.policy import SegmentationPolicy


# ── Key ───────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DestinationKey:
    """Canonical key for a destination endpoint (dst_ip, dst_port, proto); proto lowercased."""

    dst_ip: str
    dst_port: int
    proto: str


# ── Direct-reachability model ─────────────────────────────────────────────────


@dataclass(slots=True)
class ExpectedConnectivity:
    """Expected direct-reachability permissions for one destination endpoint.

    allowed_groups: groups with group-level authorization.
    allowed_hosts_by_group: per-group IPs with host-level authorization.
    rule_ids_by_group: per-group direct rule ids granting access (provenance).
    """

    dst_ip: str
    dst_group: str | None

    dst_port: int
    proto: str

    allowed_groups: set[str] = field(default_factory=set)
    allowed_hosts_by_group: dict[str, set[str]] = field(default_factory=dict)
    rule_ids_by_group: dict[str, set[str]] = field(default_factory=dict)

    def allows(self, *, group_name: str, src_ip: str) -> bool:
        """Whether *group_name* / *src_ip* is authorized (group-wide or host-level)."""
        if group_name in self.allowed_groups:
            return True
        allowed_hosts = self.allowed_hosts_by_group.get(group_name)
        if allowed_hosts:
            return src_ip in allowed_hosts
        return False

    def allows_any(self, *, groups, src_ip: str) -> bool:
        """Whether a principal in any of *groups* is authorized (see allows())."""
        return any(self.allows(group_name=g, src_ip=src_ip) for g in groups)

    def host_scoped_context(self, *, groups) -> tuple[frozenset[str], frozenset[str]]:
        """Union of rule ids and authorized hosts for groups with host-scoped access here.

        Empty means no group is host-scoped, i.e. GROUP_ISOLATION_VIOLATION
        rather than HOST_SCOPED_ACCESS_VIOLATION.
        """
        rule_ids: set[str] = set()
        hosts: set[str] = set()
        for g in groups:
            if g in self.allowed_hosts_by_group:
                rule_ids |= self.rule_ids_by_group.get(g, set())
                hosts |= self.allowed_hosts_by_group.get(g, set())
        return frozenset(rule_ids), frozenset(hosts)


@dataclass(slots=True)
class ExpectedConnectivityModel:
    """Direct-reachability model for all policy-authorized destinations.

    Secondary indices (_group_auth_keys, _host_auth_keys, _dst_group_keys) let
    entries_to_probe_for_groups() skip authorized and own-group keys without a
    full scan.
    """

    entries: dict[DestinationKey, ExpectedConnectivity]

    # Keys where a segment has segment-level authorization.
    _group_auth_keys: dict[str, set[DestinationKey]] = field(
        default_factory=dict, init=False, repr=False
    )
    # Keys where a segment has host-level authorization.
    _host_auth_keys: dict[str, set[DestinationKey]] = field(
        default_factory=dict, init=False, repr=False
    )
    # Keys grouped by dst_segment for own-segment exclusion.
    _dst_group_keys: dict[str, set[DestinationKey]] = field(
        default_factory=dict, init=False, repr=False
    )

    def get(
        self,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> ExpectedConnectivity | None:
        return self.entries.get(DestinationKey(dst_ip=dst_ip, dst_port=dst_port, proto=proto))

    def entries_to_probe_for_groups(self, groups, src_ip: str, *, exclude_own_group: bool = True):
        """Yield (key, entry) pairs that a principal with *groups* is forbidden to reach.

        Skips entries authorized for any of the groups and, if
        exclude_own_group, the destination's own group. exclude_own_group=False
        is for individually attributable sources (Host Mode). A destination
        equal to src_ip is always skipped: a self-probe proves nothing, and
        multi-group destinations have no single dst_group to catch it.
        """
        groups = list(groups)
        own_seg: set = set()
        seg_auth: set = set()
        host_auth: set = set()
        for g in groups:
            if exclude_own_group:
                own_seg |= self._dst_group_keys.get(g, set())
            seg_auth |= self._group_auth_keys.get(g, set())
            host_auth |= self._host_auth_keys.get(g, set())

        for ck, entry in self.entries.items():
            if ck.dst_ip == src_ip:
                continue
            if ck in own_seg or ck in seg_auth:
                continue
            if ck in host_auth:
                if any(src_ip in entry.allowed_hosts_by_group.get(g, ()) for g in groups):
                    continue
            yield ck, entry


# ── Transitive-reachability model ─────────────────────────────────────────────


@dataclass(slots=True)
class TransitConstraint:
    """Expected transitive (multi-hop) reachability for one destination tuple.

    mtp_ids_by_src maps each source IP with transit intent to the rule ids
    expressing it, whether or not the via-chain resolves. Its keys are the
    intent sources.
    """

    mtp_ids_by_src: dict[str, set[str]] = field(default_factory=dict)


@dataclass(slots=True)
class TransitConstraintModel:
    """Transitive-reachability model for all policy-authorized transit paths."""

    entries: dict[DestinationKey, TransitConstraint]

    def get(
        self,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> TransitConstraint | None:
        return self.entries.get(DestinationKey(dst_ip=dst_ip, dst_port=dst_port, proto=proto))

    def has_intent(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> bool:
        """Whether any transitive rule gives *src_ip* transit intent to this destination.

        Checks the specific (dst_port, proto) key and the wildcard key (0, "").
        """
        transitive = self.get(dst_ip, dst_port, proto)
        if transitive is not None and src_ip in transitive.mtp_ids_by_src:
            return True
        wildcard = self.get(dst_ip, 0, "")
        return wildcard is not None and src_ip in wildcard.mtp_ids_by_src

    def mtp_ids(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> set[str]:
        """Transitive rule ids with intent from *src_ip*, from the specific and wildcard keys."""
        result: set[str] = set()
        transitive = self.get(dst_ip, dst_port, proto)
        if transitive is not None:
            result.update(transitive.mtp_ids_by_src.get(src_ip, set()))
        wildcard = self.get(dst_ip, 0, "")
        if wildcard is not None:
            result.update(wildcard.mtp_ids_by_src.get(src_ip, set()))
        return result


# ── Shared helpers ────────────────────────────────────────────────────────────


def resolve_principal_ips(
    policy: SegmentationPolicy,
    principal: str,
    *,
    probe_groups: "dict[str, tuple[str, ...]] | None" = None,
) -> list[str]:
    """Resolve a rule endpoint (segment or server name) to concrete IPs.

    Returns IPs in server declaration order (deterministic BFS tie-breaking).
    Groups resolve via workloads_in_group() (full multi-membership).

    probe_groups ({probe.ip: probe.groups}): when *principal* names a Group,
    Probes declared for that group are added, de-duplicated, so a
    Representative probe's IP can stand in for its group.
    """
    server = policy.get_server(principal)
    if server is not None:
        return [server.ip]
    ips = [srv.ip for srv in policy.workloads_in_group(principal)]
    if probe_groups:
        for probe_ip, groups in probe_groups.items():
            if principal in groups and probe_ip not in ips:
                ips.append(probe_ip)
    return ips


# ── Builders ───────────────────────────────────────────────────────────────────


def build_expected_connectivity(policy: SegmentationPolicy) -> ExpectedConnectivityModel:
    """Build the expected direct-reachability model from direct policy rules.

    Transitive rules are handled by build_transit_constraint_model.
    """
    entries: dict[DestinationKey, ExpectedConnectivity] = {}
    group_auth_keys: dict[str, set[DestinationKey]] = {}
    host_auth_keys: dict[str, set[DestinationKey]] = {}
    dst_group_keys: dict[str, set[DestinationKey]] = {}

    for rule in policy.rules:
        src_segment = policy.get_segment(rule.src)
        src_host = None if src_segment is not None else policy.get_server(rule.src)

        # Resolve destination and segment in one step to avoid re-scanning CIDRs.
        dst_srv = policy.get_server(rule.dst)
        if dst_srv is not None:
            # dst_group stays None for a workload with zero or several groups.
            dst_group = dst_srv.groups[0] if len(dst_srv.groups) == 1 else None
            dst_pairs: list[tuple[str, str | None]] = [(dst_srv.ip, dst_group)]
        else:
            seg_name = rule.dst
            dst_pairs = [(s.ip, seg_name) for s in policy.workloads_in_group(seg_name)]

        for dst_ip, dst_group in dst_pairs:
            for port in rule.ports:
                key = DestinationKey(dst_ip=dst_ip, dst_port=port, proto=rule.proto.lower())
                if key not in entries:
                    entries[key] = ExpectedConnectivity(
                        dst_ip=dst_ip,
                        dst_group=dst_group,
                        dst_port=port,
                        proto=key.proto,
                    )
                    if dst_group is not None:
                        dst_group_keys.setdefault(dst_group, set()).add(key)
                entry = entries[key]

                if src_segment is not None:
                    entry.allowed_groups.add(rule.src)
                    entry.rule_ids_by_group.setdefault(rule.src, set()).add(rule.rule_id)
                    group_auth_keys.setdefault(rule.src, set()).add(key)
                    continue

                if src_host is None:
                    continue

                # File this host-scoped grant under every group src_host belongs to.
                for group in src_host.groups:
                    entry.allowed_hosts_by_group.setdefault(group, set()).add(src_host.ip)
                    entry.rule_ids_by_group.setdefault(group, set()).add(rule.rule_id)
                    host_auth_keys.setdefault(group, set()).add(key)

    model = ExpectedConnectivityModel(entries=entries)
    model._group_auth_keys = group_auth_keys
    model._host_auth_keys = host_auth_keys
    model._dst_group_keys = dst_group_keys
    return model


def build_transit_constraint_model(
    policy: SegmentationPolicy,
    *,
    probe_groups: "dict[str, tuple[str, ...]] | None" = None,
) -> TransitConstraintModel:
    """Build the expected transitive-reachability model from policy rules.

    Endpoints and via are resolved once. A rule whose via server is not found
    still records transit intent but contributes no route. Wildcard rules
    (no ports/proto) use the sentinel key (dst_port=0, proto="").

    probe_groups ({probe.ip: probe.groups}) applies only to *src* resolution,
    so a Representative probe's IP can stand in for its groups; never to dst
    or via.
    """
    entries: dict[DestinationKey, TransitConstraint] = {}

    for rule in policy.mandatory_transit_paths:
        src_ips = resolve_principal_ips(policy, rule.src, probe_groups=probe_groups)
        dst_ips = resolve_principal_ips(policy, rule.dst)

        for dst_ip in dst_ips:
            # Specific rules get one key per port; wildcard rules use sentinel (0, "").
            if rule.ports:
                keys = [
                    DestinationKey(dst_ip=dst_ip, dst_port=p, proto=rule.proto.lower())
                    for p in rule.ports
                ]
            else:
                keys = [DestinationKey(dst_ip=dst_ip, dst_port=0, proto="")]

            for key in keys:
                if key not in entries:
                    entries[key] = TransitConstraint()
                td = entries[key]
                for src_ip in src_ips:
                    td.mtp_ids_by_src.setdefault(src_ip, set()).add(rule.rule_id)

    return TransitConstraintModel(entries=entries)
