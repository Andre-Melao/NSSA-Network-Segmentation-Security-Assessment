"""Reverse-BFS reachability index over the observed connectivity graph.

ObservedGraph -> build_reachability_index() -> ReachabilityIndex, the
destination-centric fact layer the classification layer relies on.

The index is built by reverse BFS from each protected destination (ECM+TCM),
answering "who can reach db01?" without traversing unprotected nodes:

  index[dst_ip][(src_ip, port, proto)] = ReachabilityEvidence

Each (src, dst, port, proto) tuple yields exactly one ReachabilityEvidence with
the shortest-hop forward path. traversal_limit is a runtime safeguard, not part
of the security model; None (default) means complete discovery.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from nssa.oae.observed.graph import GraphEdge, ObservedGraph
from nssa.shared.contracts import ProbeState


# ── Reachability evidence ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ReachabilityEvidence:
    """One observed reachability fact: src_ip can reach (dst_ip, port, proto).

    shortest_path is the shortest-hop forward path from the reverse BFS, used
    for classification and as audit evidence. context and state come from the
    final edge (direct predecessor -> dst_ip).
    """

    src_ip: str
    dst_ip: str
    port: int
    proto: str
    shortest_path: tuple[str, ...]
    context: str | None
    state: ProbeState

    @property
    def hop_count(self) -> int:
        """Hop count along the shortest path (0 = direct connection)."""
        return len(self.shortest_path) - 2


# Destination-centric index:
#   reachable_to[dst_ip][(src_ip, port, proto)] = ReachabilityEvidence
ReachabilityIndex = dict[str, dict[tuple[str, int, str], ReachabilityEvidence]]


# ── Edge relevance helpers ────────────────────────────────────────────────────


def is_relevant(edge: GraphEdge) -> bool:
    # OPEN and CLOSED prove reachability: CLOSED (TCP RST) means the destination
    # received the packet. OPEN_FILTERED (UDP only) is excluded: it cannot tell
    # open from filtered, too ambiguous to count as confirmed evidence. It stays
    # in the ObservedMatrix/graph unchanged.
    return edge.state in {ProbeState.OPEN, ProbeState.CLOSED}


def _state_priority(state: ProbeState) -> int:
    if state == ProbeState.OPEN:
        return 0
    if state == ProbeState.CLOSED:
        return 1
    return 2


# ── Reverse BFS ───────────────────────────────────────────────────────────────


def _reverse_bfs_destination(
    dst_ip: str,
    final_edges: list[GraphEdge],
    graph: ObservedGraph,
    traversal_limit: int | None,
    excluded_hosts: frozenset[str] | None = None,
) -> dict[str, tuple[tuple[str, ...], GraphEdge]]:
    """Single multi-source reverse BFS from all direct predecessors of *dst_ip*.

    BFS reaches every source first via its shortest-hop path.

    excluded_hosts: traversal barriers; they can be seeded but, once dequeued,
    do not propagate reachability backwards ("who can still reach dst_ip
    without these nodes?"), used for TCM bypass detection.

    Complexity O(E). Returns {src_ip: (shortest_path_to_dst, final_edge)} for
    every reachable source other than *dst_ip*.
    """
    node_path: dict[str, tuple[tuple[str, ...], GraphEdge]] = {}
    depth_of: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque()

    for final_edge in sorted(final_edges, key=lambda e: _state_priority(e.state)):
        pred = final_edge.src_ip
        if pred not in depth_of:
            depth_of[pred] = 0
            node_path[pred] = ((pred, dst_ip), final_edge)
            queue.append((pred, 0))

    while queue:
        node, depth = queue.popleft()
        if traversal_limit is not None and depth >= traversal_limit:
            continue
        if excluded_hosts is not None and node in excluded_hosts:
            continue
        current_path, current_fedge = node_path[node]
        for in_edge in graph.reverse_adjacency.get(node, []):
            if not is_relevant(in_edge):
                continue
            prev = in_edge.src_ip
            if prev == dst_ip:
                continue
            candidate_depth = depth + 1
            stored_depth = depth_of.get(prev)
            if stored_depth is None:
                depth_of[prev] = candidate_depth
                node_path[prev] = ((prev,) + current_path, current_fedge)
                queue.append((prev, candidate_depth))
            elif stored_depth == candidate_depth:
                _, existing_fedge = node_path[prev]
                if _state_priority(current_fedge.state) < _state_priority(existing_fedge.state):
                    node_path[prev] = ((prev,) + current_path, current_fedge)

    return {src: entry for src, entry in node_path.items() if src != dst_ip}


# ── Reachability index builder ────────────────────────────────────────────────


def build_reachability_index(
    graph: ObservedGraph,
    *,
    destinations: set[str] | None = None,
    traversal_limit: int | None = None,
    excluded_hosts: set[str] | None = None,
) -> ReachabilityIndex:
    """Build a destination-centric reachability index via reverse BFS.

    *destinations*: only these IPs are analyzed (engine.py passes the observed
    plus ECM/TCM policy destinations); None means all graph nodes.

    excluded_hosts: traversal barriers (the mandatory transit hosts' IPs) to
    build a bypass index of sources that reach the destination without them.

    traversal_limit: runtime safeguard on BFS depth, not a security boundary.

    Complexity O(K x E), K = |destinations|, E = graph edges.
    """
    target_dsts = destinations if destinations is not None else set(graph.nodes.keys())
    index: ReachabilityIndex = {}

    for dst_ip in target_dsts:
        if dst_ip not in graph.nodes:
            continue

        incoming = [
            e for e in graph.reverse_adjacency.get(dst_ip, [])
            if is_relevant(e)
        ]
        if not incoming:
            continue

        pp_edges: dict[tuple[int, str], list[GraphEdge]] = {}
        for e in incoming:
            pp_edges.setdefault((e.port, e.proto), []).append(e)

        excluded = frozenset(excluded_hosts) if excluded_hosts else None
        for (port, proto), final_edges in pp_edges.items():
            for src_ip, (path, final_edge) in _reverse_bfs_destination(
                dst_ip, final_edges, graph, traversal_limit, excluded
            ).items():
                index.setdefault(dst_ip, {})[(src_ip, port, proto)] = ReachabilityEvidence(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    port=port,
                    proto=proto,
                    shortest_path=path,
                    context=final_edge.context,
                    state=final_edge.state,
                )

    return index
