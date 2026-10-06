"""Tests for capability inference and cross-server toxic-flow detection."""

from __future__ import annotations

from mcpscan.analyzers.schema import infer_capabilities
from mcpscan.graph import build_capability_graph, find_toxic_flows
from mcpscan.models import Capability, ServerModel


def test_infers_capabilities(sensitive_reader, egress_tool) -> None:  # type: ignore[no-untyped-def]
    assert Capability.READ_SENSITIVE in infer_capabilities(sensitive_reader)
    assert Capability.EGRESS in infer_capabilities(egress_tool)


def test_cross_server_flow_detected(two_server_setup: list[ServerModel]) -> None:
    tools = [t for s in two_server_setup for t in s.tools]
    for tool in tools:
        tool.capabilities = infer_capabilities(tool)
    graph = build_capability_graph(tools)
    chains = find_toxic_flows(graph, tools, max_hops=4)
    assert chains, "expected at least one toxic flow"
    assert chains[0].flow_type == "cross_server_exfil"
    assert chains[0].severity.value in {"high", "critical"}
