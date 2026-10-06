"""Build the in-process capability graph.

Nodes are tools; a directed edge ``A -> B`` means tool ``A`` could influence tool ``B`` within a
shared agent context. Because an agent can chain any available tool, we model the reachability
conservatively: any tool that *reads* data can influence any tool that *acts* on it. This is what
allows detection of exfiltration chains that span multiple servers.
"""

from __future__ import annotations

import networkx as nx

from mcpscan.models import Capability, ToolModel

# Capabilities that produce data an attacker cares about.
_SOURCE_CAPS = {Capability.READ_SENSITIVE, Capability.READ_UNTRUSTED}
# Capabilities that can act on / leak that data.
_SINK_CAPS = {Capability.EGRESS, Capability.EXECUTE, Capability.WRITE_STATE}


def build_capability_graph(tools: list[ToolModel]) -> nx.DiGraph:
    """Construct a directed capability-influence graph over all tools across all servers."""

    graph: nx.DiGraph = nx.DiGraph()

    for tool in tools:
        graph.add_node(
            tool.qualified_name,
            server=tool.server,
            name=tool.name,
            capabilities=[c.value for c in tool.capabilities],
        )

    sources = [t for t in tools if _SOURCE_CAPS.intersection(t.capabilities)]
    sinks = [t for t in tools if _SINK_CAPS.intersection(t.capabilities)]

    for source in sources:
        for sink in sinks:
            if source.qualified_name == sink.qualified_name:
                continue
            graph.add_edge(
                source.qualified_name,
                sink.qualified_name,
                cross_server=source.server != sink.server,
            )
    return graph
