"""Violated rule enrichment for AuditFindings.

build_violated_rules() answers: "What policies are being violated, and how?"
One ViolatedRule is produced per distinct policy control (never per RawFinding
or path); raw findings violating the same control collapse into one entry whose
summary names all affected hosts.

Control grouping:

  GROUP_ISOLATION_VIOLATION     -> (type, src_segment)
    rule_ids on the raw findings (the rule(s) authorizing a different principal
    here) are unioned into one ViolatedRule per rule_id; IMPLICIT_DEFAULT_DENY
    is used only when that union is empty. authorized_groups enables an
    "only X is allowed" clause.

  HOST_SCOPED_ACCESS_VIOLATION  -> (type, src_segment, violated_rule_ids)
    authorized_src_ips enables an "only X is authorised" summary; one
    ViolatedRule per rule_id.

  MANDATORY_TRANSIT_PATH_BYPASS -> (type, src_segment, via_hop)
    Each bypassed transit is an independent failure; one ViolatedRule per rule_id.

  UNDECLARED_CONNECTIVITY       -> not processed (violated_rules stays None).

Hosts are shown as "name (IP)", or "IP" when no name is known. Entries sort by
rule_id with IMPLICIT_DEFAULT_DENY last, then by summary. No graph traversal is
done; everything comes from the RawFindings' metadata.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from collections import defaultdict

from nssa.oae.analysis.finding import FindingType
from nssa.oae.audit.models import (
    AuditFinding,
    FindingReason,
    HostRef,
    IMPLICIT_DEFAULT_DENY,
    RawFinding,
    ViolatedRule,
)

_TYPE_ORDER: dict[FindingType, int] = {
    FindingType.GROUP_ISOLATION_VIOLATION:   0,
    FindingType.HOST_SCOPED_ACCESS_VIOLATION:  1,
    FindingType.MANDATORY_TRANSIT_PATH_BYPASS: 2,
}


def _control_key(r: RawFinding) -> tuple | None:
    """Return the key identifying a distinct control failure; None for UNDECLARED_CONNECTIVITY."""
    t = r.finding_type
    if t == FindingType.GROUP_ISOLATION_VIOLATION:
        return (t, r.src_segment)
    if t == FindingType.HOST_SCOPED_ACCESS_VIOLATION:
        return (t, r.src_segment, r.violated_rule_ids)
    if t == FindingType.MANDATORY_TRANSIT_PATH_BYPASS:
        return (t, r.src_segment, r.via_hop)
    return None  # UNDECLARED_CONNECTIVITY — not a rule violation


def _key_sort_order(k: tuple) -> tuple[int, str, str]:
    t = k[0]
    seg = k[1] if len(k) > 1 else ""
    extra = k[2] if len(k) > 2 else None
    if isinstance(extra, frozenset):
        extra_str = ",".join(sorted(extra))
    else:
        extra_str = str(extra) if extra is not None else ""
    return (_TYPE_ORDER.get(t, 99), seg, extra_str)


def _host_list(displays: list[str]) -> str:
    if len(displays) == 1:
        return displays[0]
    if len(displays) == 2:
        return f"{displays[0]} and {displays[1]}"
    return ", ".join(displays[:-1]) + f" and {displays[-1]}"


def _group_phrase(src_segment: str) -> str:
    """Human-readable phrase for a src_segment label ("the X group", "the X and Y groups").

    Splits the internal "+"-joined label from _group_label().
    """
    groups = sorted(src_segment.split("+"))
    noun = "group" if len(groups) == 1 else "groups"
    return f"the {_host_list(groups)} {noun}"


def _is_ip_literal(value: str) -> bool:
    """Whether *value* parses as an IPv4/IPv6 address.

    Distinguishes a host-named via_hop from a group-named one (see
    _resolve_via_hop()).
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _sentence(
    finding_type: FindingType,
    src_segment: str,
    via_hop: str | None,
    via_raw: str | None,
    unauth_displays: list[str],
    auth_displays: list[str],
    authorized_groups: frozenset[str] = frozenset(),
) -> str:
    """Generate a deterministic description of one policy control failure.

    unauth_displays   - "name (IP)" or "IP" for the unauthorised hosts.
    auth_displays     - same, for hosts the policy permits (HOST_SCOPED only).
    authorized_groups - groups the policy authorizes here (GROUP_ISOLATION only).
    via_hop           - display-formatted transit identity (BYPASS only).
    via_raw           - via_hop before formatting, used for the IP-literal test
                        (formatting can turn an IP into "name (ip)").
    """
    group_phrase = _group_phrase(src_segment)

    if finding_type == FindingType.GROUP_ISOLATION_VIOLATION:
        base = (
            f"Hosts from {group_phrase} can reach this service, "
            f"violating the intended group isolation policy."
        )
        if authorized_groups:
            auth_verb = "is" if len(authorized_groups) == 1 else "are"
            auth_phrase = _group_phrase("+".join(sorted(authorized_groups)))
            return f"{base} According to the policy, only {auth_phrase} {auth_verb} allowed."
        return base

    if finding_type == FindingType.HOST_SCOPED_ACCESS_VIOLATION:
        plural = "s" if len(unauth_displays) > 1 else ""
        unauth_str = _host_list(unauth_displays)
        if auth_displays:
            auth_str = _host_list(auth_displays)
            auth_verb = "are" if len(auth_displays) > 1 else "is"
            return (
                f"Host{plural} {unauth_str} from {group_phrase} "
                f"can reach this service, although only {auth_str} "
                f"{auth_verb} authorised by policy."
            )
        return (
            f"Host{plural} {unauth_str} from {group_phrase} "
            f"can reach this service, although access is restricted to "
            f"specific authorized hosts by policy."
        )

    if finding_type == FindingType.MANDATORY_TRANSIT_PATH_BYPASS:
        if via_hop is None:
            transit_phrase = "the required transit host"
        elif via_raw is not None and _is_ip_literal(via_raw):
            transit_phrase = f"{via_hop} host"
        else:
            transit_phrase = f"{via_hop} group"
        return (
            f"The service can be reached from {group_phrase} "
            f"without traversing the mandatory {transit_phrase} defined by policy."
        )

    # Should not be reached; UNDECLARED_CONNECTIVITY is filtered before calling.
    return (
        "This service is reachable despite having no explicit authorisation "
        "in the segmentation policy."
    )


def build_violated_rules(
    finding: AuditFinding,
    *,
    host_names: dict[str, str] | None = None,
) -> AuditFinding:
    """Enrich an AuditFinding with per-rule violation summaries (returns a new one).

    violated_rules stays None for UNEXPECTED_REACHABILITY. Otherwise one
    ViolatedRule is created per control (rule_id, or IMPLICIT_DEFAULT_DENY for
    group isolation).

    host_names: optional IP -> hostname mapping for permitted hosts not in
    source_hosts; pass the one used in build_audit_findings().
    """
    if finding.reason == FindingReason.UNEXPECTED_REACHABILITY:
        return finding

    if not finding.raw_findings:
        return finding

    # IP → HostRef lookup for unauthorised hosts (those present in source_hosts).
    host_lookup: dict[str, HostRef] = {h.ip: h for h in finding.source_hosts}

    def _display(ip: str) -> str:
        h = host_lookup.get(ip)
        if h:
            return str(h)
        name = host_names.get(ip) if host_names else None
        return f"{name} ({ip})" if name else ip

    # Group src_ips, rule_ids, and authorized_ips/groups by control key.
    groups: dict[tuple, dict] = defaultdict(
        lambda: {"src_ips": set(), "rule_ids": set(), "authorized_ips": set(), "authorized_groups": set()}
    )
    for r in finding.raw_findings:
        key = _control_key(r)
        if key is None:
            continue  # UNDECLARED_CONNECTIVITY — skip
        groups[key]["src_ips"].add(r.src_ip)
        groups[key]["rule_ids"].update(r.violated_rule_ids)
        groups[key]["authorized_ips"].update(r.authorized_src_ips)
        groups[key]["authorized_groups"].update(r.authorized_groups)

    violated: list[ViolatedRule] = []
    seen: set[tuple] = set()

    for key in sorted(groups.keys(), key=_key_sort_order):
        data = groups[key]
        t = key[0]
        seg = key[1] if len(key) > 1 else ""
        via_raw = key[2] if t == FindingType.MANDATORY_TRANSIT_PATH_BYPASS else None

        unauth_displays = sorted(_display(ip) for ip in data["src_ips"])
        auth_displays = sorted(_display(ip) for ip in data["authorized_ips"])
        via_display = _display(via_raw) if via_raw else None
        sentence = _sentence(
            t, seg, via_display, via_raw, unauth_displays, auth_displays,
            authorized_groups=frozenset(data["authorized_groups"]),
        )

        rule_ids = sorted(data["rule_ids"])
        if rule_ids:
            for rule_id in rule_ids:
                entry = (rule_id, sentence)
                if entry not in seen:
                    seen.add(entry)
                    violated.append(ViolatedRule(rule_id=rule_id, summary=sentence))
        else:
            entry = (IMPLICIT_DEFAULT_DENY, sentence)
            if entry not in seen:
                seen.add(entry)
                violated.append(ViolatedRule(rule_id=IMPLICIT_DEFAULT_DENY, summary=sentence))

    if not violated:
        return finding

    # Explicit rule IDs first (sorted), IMPLICIT_DEFAULT_DENY entries last.
    violated.sort(key=lambda vr: (vr.rule_id == IMPLICIT_DEFAULT_DENY, vr.rule_id, vr.summary))
    return dataclasses.replace(finding, violated_rules=tuple(violated))
