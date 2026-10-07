"""Export the capability graph as a Mermaid diagram for docs/reports."""

from __future__ import annotations

import networkx as nx


def graph_to_mermaid(graph: nx.DiGraph) -> str:
    """Render a directed capability graph with distinct visual styles and capability grouping."""

    lines = [
        "flowchart TB",
        "    classDef sensitive fill:#451a03,stroke:#f97316,stroke-width:2px,color:#fed7aa",
        "    classDef egress fill:#4c0519,stroke:#f43f5e,stroke-width:2px,color:#fecdd3",
        "    classDef untrusted fill:#172554,stroke:#3b82f6,stroke-width:2px,color:#bfdbfe",
        "    classDef write fill:#3b0764,stroke:#a855f7,stroke-width:2px,color:#e9d5ff",
        "    classDef normal fill:#1e293b,stroke:#475569,stroke-width:1px,color:#cbd5e1",
    ]

    # Only include connected nodes to avoid massive unreadable charts with 30 isolated boxes
    connected_nodes = set()
    for u, v in graph.edges():
        connected_nodes.add(u)
        connected_nodes.add(v)

    target_nodes = connected_nodes if connected_nodes else set(graph.nodes)

    node_ids: dict[str, str] = {}
    node_classes: dict[str, str] = {}

    for idx, node in enumerate(target_nodes):
        node_id = f"node_{idx}"
        node_ids[node] = node_id
        caps = graph.nodes[node].get("capabilities", [])
        tool_name = node.split("::")[-1] if "::" in node else node
        server_name = node.split("::")[0] if "::" in node else "server"

        # Categorize node style
        if "READ_SENSITIVE" in caps:
            node_classes[node_id] = "sensitive"
            icon = "🔒"
        elif "EGRESS" in caps:
            node_classes[node_id] = "egress"
            icon = "🌐"
        elif "READ_UNTRUSTED" in caps:
            node_classes[node_id] = "untrusted"
            icon = "📥"
        elif "WRITE_STATE" in caps or "EXECUTE" in caps:
            node_classes[node_id] = "write"
            icon = "⚡"
        else:
            node_classes[node_id] = "normal"
            icon = "🔧"

        cap_text = f"[{' | '.join(caps)}]" if caps else ""
        label = f"<b>{icon} {tool_name}</b><br/><small>{server_name}</small><br/><code>{cap_text}</code>"
        lines.append(f'    {node_id}["{label}"]')

    # Add edges with clear risk labels
    for source, target, data in graph.edges(data=True):
        if source in node_ids and target in node_ids:
            if data.get("cross_server"):
                lines.append(f'    {node_ids[source]} ==>|🚨 Cross-Server Flow| {node_ids[target]}')
            else:
                lines.append(f'    {node_ids[source]} -->|Influences| {node_ids[target]}')

    # Apply classes
    for nid, cls in node_classes.items():
        lines.append(f"    class {nid} {cls}")

    return "\n".join(lines)

