from __future__ import annotations

from dataclasses import dataclass

from nssa.oae.observed.matrix import ObservedMatrix
from nssa.shared.contracts import ProbeState


@dataclass(slots=True)
class GraphNode:
    ip: str


@dataclass(slots=True)
class GraphEdge:
    src_ip: str
    dst_ip: str
    port: int
    proto: str
    state: ProbeState
    context: str | None


@dataclass(slots=True)
class ObservedGraph:
    nodes: dict[str, GraphNode]
    edges: list[GraphEdge]
    adjacency: dict[str, list[GraphEdge]]
    reverse_adjacency: dict[str, list[GraphEdge]]


def build_graph(observed: ObservedMatrix) -> ObservedGraph:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    adjacency: dict[str, list[GraphEdge]] = {}
    reverse_adjacency: dict[str, list[GraphEdge]] = {}

    for (dst_ip, port, proto), sources in observed.data.items():
        for src_ip, observed_edges in sources.items():
            if src_ip not in nodes:
                nodes[src_ip] = GraphNode(ip=src_ip)
            if dst_ip not in nodes:
                nodes[dst_ip] = GraphNode(ip=dst_ip)

            for edge in observed_edges:
                graph_edge = GraphEdge(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    port=port,
                    proto=proto,
                    state=edge.state,
                    context=edge.context,
                )
                edges.append(graph_edge)
                adjacency.setdefault(src_ip, []).append(graph_edge)
                reverse_adjacency.setdefault(dst_ip, []).append(graph_edge)

    return ObservedGraph(
        nodes=nodes,
        edges=edges,
        adjacency=adjacency,
        reverse_adjacency=reverse_adjacency,
    )
