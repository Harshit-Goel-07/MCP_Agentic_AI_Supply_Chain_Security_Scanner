"""Search the capability graph for toxic data flows.

A toxic flow is a path where sensitive/untrusted data can reach an egress-capable sink. Chains
that cross server boundaries are the highest-signal finding: two individually-benign servers
combine into an exfiltration primitive.
"""

from __future__ import annotations

import networkx as nx

from mcpscan.config import Severity
from mcpscan.models import Capability, Chain, ChainStep, ToolModel


def _cap_lookup(tools: list[ToolModel]) -> dict[str, list[Capability]]:
    return {t.qualified_name: t.capabilities for t in tools}


def find_toxic_flows(
    graph: nx.DiGraph, tools: list[ToolModel], *, max_hops: int = 4
) -> list[Chain]:
    """Return toxic flows from sensitive/untrusted sources to egress sinks."""

    caps = _cap_lookup(tools)
    sources = [
        name
        for name, c in caps.items()
        if {Capability.READ_SENSITIVE, Capability.READ_UNTRUSTED}.intersection(c)
    ]
    sinks = [name for name, c in caps.items() if Capability.EGRESS in c]

    chains: list[Chain] = []
    seen: set[tuple[str, ...]] = set()

    for source in sources:
        if source not in graph:
            continue
        for sink in sinks:
            if sink not in graph or source == sink:
                continue
            try:
                paths = nx.all_simple_paths(graph, source, sink, cutoff=max_hops)
            except nx.NodeNotFound:
                continue
            for path in paths:
                key = tuple(path)
                if key in seen:
                    continue
                seen.add(key)
                chains.append(_build_chain(path, caps, graph))

    # Highest severity / shortest chains first.
    chains.sort(key=lambda c: (-c.severity.rank, len(c.path)))
    return chains


def _build_chain(path: list[str], caps: dict[str, list[Capability]], graph: nx.DiGraph) -> Chain:
    servers = {graph.nodes[node].get("server") for node in path}
    cross_server = len(servers) > 1
    steps = [
        ChainStep(tool=node, capability=_primary_capability(caps.get(node, []))) for node in path
    ]
    has_sensitive = any(Capability.READ_SENSITIVE in caps.get(n, []) for n in path)
    if cross_server and has_sensitive:
        severity = Severity.CRITICAL
    elif cross_server or has_sensitive:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM
    return Chain(
        flow_type="cross_server_exfil" if cross_server else "intra_server_exfil",
        severity=severity,
        confidence=0.85 if cross_server else 0.7,
        path=steps,
    )


def _primary_capability(capabilities: list[Capability]) -> Capability:
    for preferred in (
        Capability.READ_SENSITIVE,
        Capability.EGRESS,
        Capability.EXECUTE,
        Capability.READ_UNTRUSTED,
        Capability.WRITE_STATE,
    ):
        if preferred in capabilities:
            return preferred
    return Capability.READ_UNTRUSTED
