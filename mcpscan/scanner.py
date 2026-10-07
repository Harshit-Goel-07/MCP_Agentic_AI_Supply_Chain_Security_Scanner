"""Scan orchestrator: the deterministic pipeline that produces a :class:`ScanResult`.

Pipeline: discover -> (enrich capabilities via schema analyzer) -> run analyzers -> build
capability graph -> search toxic flows -> optional LLM judge -> enrich via catalog -> score.
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from mcpscan.analyzers.base import Analyzer, AnalyzerRegistry, ScanContext
from mcpscan.analyzers.schema import SchemaAnalyzer
from mcpscan.analyzers.semantic import SemanticAnalyzer
from mcpscan.analyzers.static_text import StaticTextAnalyzer
from mcpscan.config import Settings, Severity
from mcpscan.connector import enumerate_server_tools
from mcpscan.discovery import discover_servers
from mcpscan.graph import build_capability_graph, find_toxic_flows
from mcpscan.llm import build_judge
from mcpscan.models import (
    EvidenceLocation,
    Finding,
    ScanResult,
    ServerModel,
    ToolModel,
)
from mcpscan.rules.engine import load_catalog
from mcpscan.scoring import risk_score
from mcpscan.version import __version__


def default_analyzers() -> list[Analyzer]:
    """The built-in analyzer pipeline. Schema runs first so it can tag capabilities."""

    return [SchemaAnalyzer(), StaticTextAnalyzer(), SemanticAnalyzer()]


class Scanner:
    """Reusable scanner. Construct once, call :meth:`scan` many times."""

    def __init__(
        self,
        settings: Settings | None = None,
        registry: AnalyzerRegistry | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.registry = registry or AnalyzerRegistry()
        if not self.registry.all():
            for analyzer in default_analyzers():
                self.registry.register(analyzer)
        self._judge = build_judge(self.settings)
        self._catalog = load_catalog()

    def scan_servers(self, servers: list[ServerModel]) -> ScanResult:
        from datetime import datetime

        # Enumerate live tools for servers that define a command but lack static tools
        for server in servers:
            if not server.tools and server.command:
                server.tools = enumerate_server_tools(server)

        ctx = ScanContext(settings=self.settings, servers=servers)
        result = ScanResult(scanner_version=__version__, servers=servers)

        tools = ctx.all_tools()
        for tool in tools:
            for analyzer in self.registry.all():
                result.findings.extend(analyzer.analyze(tool, ctx))
            result.findings.extend(self._llm_findings(tool))

        graph = build_capability_graph(tools)
        result.chains = find_toxic_flows(graph, tools, max_hops=self.settings.max_flow_hops)

        result.findings = [self._catalog.enrich(f) for f in result.findings]
        # Chains contribute findings for the flat findings view / SARIF too.
        chain_findings = [self._catalog.enrich(c.as_finding()) for c in result.chains]

        all_findings = result.findings + chain_findings
        result.risk_score = risk_score(all_findings)
        result.mode = "dynamic" if self.settings.enable_dynamic else "static"
        result.finished_at = datetime.now(UTC)
        # Keep chain findings out of `findings` (they live in `chains`) but reflect them in score.
        return result

    def scan_targets(self, targets: list[Path], *, include_clients: bool = False) -> ScanResult:
        servers = discover_servers(targets, include_clients=include_clients)
        return self.scan_servers(servers)

    def _llm_findings(self, tool: ToolModel) -> list[Finding]:
        if self._judge.provider == "none" or not tool.description:
            return []
        verdict = self._judge.judge(tool.name, tool.description)
        if not verdict.poisoned or verdict.confidence < 0.5:
            return []
        return [
            Finding(
                rule_id="MCP-TP-002",
                severity=Severity.HIGH if verdict.confidence >= 0.7 else Severity.MEDIUM,
                confidence=verdict.confidence,
                tool=tool.qualified_name,
                server=tool.server,
                title="LLM judge flagged tool poisoning",
                message=verdict.rationale or "LLM judged this description as poisoning the agent.",
                location=EvidenceLocation(field="description"),
                ai_assisted=True,
            )
        ]


def diff_scans(base: ScanResult, head: ScanResult) -> list[Finding]:
    """Detect tool-definition drift (rug-pull) between two scans.

    Returns MCP-DRIFT-001 findings for tools whose description/schema hash changed.
    """

    def index(result: ScanResult) -> dict[str, str]:
        return {
            tool.qualified_name: tool.description_hash
            for server in result.servers
            for tool in server.tools
        }

    base_idx = index(base)
    head_idx = index(head)
    findings: list[Finding] = []
    catalog = load_catalog()
    for qualified_name, head_hash in head_idx.items():
        base_hash = base_idx.get(qualified_name)
        if base_hash is not None and base_hash != head_hash:
            server = qualified_name.split("::", 1)[0]
            findings.append(
                catalog.enrich(
                    Finding(
                        rule_id="MCP-DRIFT-001",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        tool=qualified_name,
                        server=server,
                        title="Tool definition drift (possible rug-pull)",
                        message="Tool description/schema changed between scans.",
                        evidence={"base_hash": base_hash, "head_hash": head_hash},
                    )
                )
            )
    return findings
