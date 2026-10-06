"""Export the capability graph as a Mermaid diagram for docs/reports."""

from __future__ import annotations

import networkx as nx


def graph_to_mermaid(graph: nx.DiGraph) -> str:
    """Render a directed capability graph to Mermaid ``flowchart LR`` syntax."""

    lines = ["flowchart LR"]
    node_ids: dict[str, str] = {}
    for idx, node in enumerate(graph.nodes):
        node_id = f"n{idx}"
        node_ids[node] = node_id
        caps = ",".join(graph.nodes[node].get("capabilities", []))
        label = node.replace('"', "'")
        lines.append(f'    {node_id}["{label}\\n{caps}"]')
    for source, target, data in graph.edges(data=True):
        arrow = "-. cross-server .->" if data.get("cross_server") else "-->"
        lines.append(f"    {node_ids[source]} {arrow} {node_ids[target]}")
    return "\n".join(lines)
