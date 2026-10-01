"""Core data models for the Audit Intelligence layer.

The central abstraction is a *service exposure*, not a *policy violation*.

HostRef      - a host identified by IP with an optional resolved hostname.
RawFinding   - one classified reachability observation for one source host.
ViolatedRule - one policy control violation with a deterministic summary.
AuditFinding - the exposure of one service (dst_ip, dst_port, proto); the
               canonical OAE output, understandable without an LLM.

Pipeline stages each return a new AuditFinding via dataclasses.replace():
  correlate()                 -> reason, source_hosts, source_groups, dst_name
  build_violated_rules()      -> violated_rules
  select_representative_paths -> representative_paths
  score_priority()            -> priority, severity

IMPLICIT_DEFAULT_DENY is the rule_id for GROUP_ISOLATION_VIOLATION findings
that no rule explains; it is a defensive fallback. Most carry the rule(s) that
authorize a different principal at that destination/service.

violated_rules is None for UNEXPECTED_REACHABILITY, never an empty tuple.
Ordered collections are stored sorted for deterministic output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nssa.oae.analysis.finding import Confidence, FindingType
from nssa.oae.analysis.reachability import ReachabilityEvidence
from nssa.shared.contracts import ProbeState

# Sentinel rule_id for GROUP_ISOLATION_VIOLATION findings with no explicit SPM rule.
IMPLICIT_DEFAULT_DENY: str = "IMPLICIT_DEFAULT_DENY"


class FindingReason(str, Enum):
    """Why this AuditFinding exists."""

    DIRECT_POLICY_VIOLATION = "Direct Policy Violation"
    UNEXPECTED_REACHABILITY  = "Unexpected Reachability"


@dataclass(frozen=True, slots=True)
class HostRef:
    """A network host identified by IP, optionally with a resolved hostname.

    str() gives "name (IP)", or just "IP" without a name.

    ip may be the synthetic "probe-<group(s)>" identity of a Policy-Graph-derived
    bypass finding (no host was observed), rendered as
    "probe-<group(s)> (policy-derived)". Detection uses only that "probe-"
    prefix, since a via_hop can legitimately be a raw group name (see
    nssa.oae.audit.summary._sentence()).
    """

    ip: str
    name: str | None = None

    def __str__(self) -> str:
        if self.name:
            return f"{self.name} ({self.ip})"
        if self.ip.startswith("probe-"):
            return f"{self.ip} (policy-derived)"
        return self.ip


@dataclass(frozen=True, slots=True)
class ViolatedRule:
    """One policy violation with its deterministic technical summary.

    rule_id is the SPM rule identifier (for group isolation, the rule(s)
    authorizing a different principal here) or IMPLICIT_DEFAULT_DENY.
    Raw findings violating the same control collapse into one ViolatedRule.
    """

    rule_id: str  # use IMPLICIT_DEFAULT_DENY for implicit default-deny violations
    summary: str


@dataclass(frozen=True, slots=True)
class RawFinding:
    """One classified reachability observation for one source host.

    authorized_src_ips (HOST_SCOPED_ACCESS_VIOLATION only) and authorized_groups
    (GROUP_ISOLATION_VIOLATION only) name the authorised parties in summaries.
    """

    finding_type: FindingType
    confidence: Confidence
    src_ip: str
    src_segment: str
    dst_ip: str
    dst_port: int
    proto: str
    dst_segment: str | None
    violated_rule_ids: frozenset[str]
    via_hop: str | None            # MANDATORY_TRANSIT_PATH_BYPASS only
    observed_state: ProbeState
    shortest_path: tuple[str, ...]  # (src, ..., dst)
    hop_count: int                  # len(shortest_path) - 2
    reachability_evidence: ReachabilityEvidence | None
    authorized_src_ips: frozenset[str] = frozenset()  # HOST_SCOPED only
    authorized_groups: frozenset[str] = frozenset()   # GROUP_ISOLATION only


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """The exposure of one service, aggregating all source hosts that can reach it.

    Identity is (dst_ip, dst_port, proto).

    reason: why this finding exists (see FindingReason).
    violated_rules: one ViolatedRule per distinct control; None for
        UNEXPECTED_REACHABILITY.
    representative_paths: how the exposure was observed (evidence only).

    Pipeline-populated fields are None until that stage runs.
    """

    # ── Service identity — required, set at correlation time ──────────────────

    dst_ip: str
    dst_port: int
    proto: str
    dst_segment: str | None
    reason: FindingReason
    source_hosts: tuple[HostRef, ...]     # sorted by IP; each carries name when resolvable
    # Sorted src_segment labels (see finding._group_label); an entry may be a
    # "+"-joined multi-group label. Serializers split them for auditor-facing JSON.
    source_groups: tuple[str, ...]
    raw_findings: tuple[RawFinding, ...]

    # ── Enriched by pipeline stages; None until set ───────────────────────────

    violated_rules: tuple[ViolatedRule, ...] | None = None
    dst_name: str | None = None
    representative_paths: tuple[RawFinding, ...] | None = None
    priority: float | None = None
    severity: str | None = None

    # ── Report identity — assigned last, by assign_ids() ──────────────────────
    # "AF-0001".. for every AuditFinding; stable only within one report.
    finding_id: str | None = None
