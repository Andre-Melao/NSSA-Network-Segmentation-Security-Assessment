"""Representative path selection for AuditFindings.

The goal is the most informative evidence for why a service is exposed: one
path per independent exposure mechanism, not the shortest paths. It uses the
same exposure_mechanism() fingerprint as ReachabilityDiversityFactor
(priority.py). A path is "novel" if its fingerprint is not yet among the
selected paths, so HA-equivalent paths consolidate into one.

Selection:
  1. Sort raw_findings by (hop_count ASC, state_priority ASC); the best path is
     always selected first.
  2. Novelty pass: accept the next candidate whose fingerprint is uncovered.
  3. Coverage pass: fill remaining slots with the best-ranked unselected findings.

No graph traversal; all evidence comes from RawFinding metadata.
"""

from __future__ import annotations

import dataclasses
from collections import defaultdict

from nssa.oae.audit.models import AuditFinding, RawFinding
from nssa.oae.audit.priority import exposure_mechanism
from nssa.shared.contracts import ProbeState

_DEFAULT_MAX_PATHS = 5

_STATE_PRIORITY: dict[ProbeState, int] = {
    ProbeState.OPEN:          0,
    ProbeState.CLOSED:        1,
    ProbeState.OPEN_FILTERED: 2,
}


def _rank_key(r: RawFinding) -> tuple[int, int]:
    return (r.hop_count, _STATE_PRIORITY.get(r.observed_state, 99))


def _collapse_duplicate_communications(raw_findings: tuple[RawFinding, ...]) -> tuple[RawFinding, ...]:
    """Collapse RawFindings describing the same communication into the richest one.

    A confirmed bypass can yield two RawFindings with identical
    (src_ip, dst_ip, dst_port, proto, shortest_path): a bypass (via_hop set) and
    an ECM violation (via_hop None). Within such a group the via_hop-carrying
    entry wins, so the route is not shown twice. Only representative_paths
    selection changes; raw_findings, violated_rules and aggregation are untouched.
    """
    groups: dict[tuple, list[RawFinding]] = defaultdict(list)
    for r in raw_findings:
        groups[(r.src_ip, r.dst_ip, r.dst_port, r.proto, r.shortest_path)].append(r)

    collapsed: list[RawFinding] = []
    for members in groups.values():
        if len(members) == 1:
            collapsed.append(members[0])
            continue
        with_via = [r for r in members if r.via_hop is not None]
        collapsed.extend(with_via if with_via else members)
    return tuple(collapsed)


def select_representative_paths(
    finding: AuditFinding,
    *,
    max_paths: int = _DEFAULT_MAX_PATHS,
) -> AuditFinding:
    """Select representative RawFindings and return an enriched AuditFinding.

    Returns a new AuditFinding with representative_paths populated.
    The input is never mutated.
    """
    if not finding.raw_findings:
        return dataclasses.replace(finding, representative_paths=())

    candidates = _collapse_duplicate_communications(finding.raw_findings)
    ranked = sorted(candidates, key=_rank_key)

    selected: list[RawFinding] = []
    selected_ids: set[int] = set()
    seen_mechanisms: set[tuple] = set()

    def _pick(r: RawFinding) -> None:
        selected.append(r)
        selected_ids.add(id(r))
        seen_mechanisms.add(exposure_mechanism(r))

    # Always take the best path first (shortest, strongest connectivity).
    _pick(ranked[0])

    # Novelty pass: one representative per distinct exposure mechanism.
    for r in ranked[1:]:
        if len(selected) >= max_paths:
            break
        if exposure_mechanism(r) not in seen_mechanisms:
            _pick(r)

    # Coverage pass: fill remaining slots with best-ranked unselected paths.
    for r in ranked:
        if len(selected) >= max_paths:
            break
        if id(r) not in selected_ids:
            _pick(r)

    # Display order only: direct evidence before bypass evidence (stable sort);
    # which paths were chosen is unaffected.
    selected.sort(key=lambda r: r.via_hop is not None)

    return dataclasses.replace(finding, representative_paths=tuple(selected))
