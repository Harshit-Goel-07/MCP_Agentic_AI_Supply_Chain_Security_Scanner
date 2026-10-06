"""Analyzer protocol and registry.

Analyzers are pure functions of a tool (plus scan context) that produce findings. They register
themselves in a registry so new detectors can be added without touching the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from mcpscan.config import Settings
from mcpscan.models import Finding, ServerModel, ToolModel


@dataclass
class ScanContext:
    """Shared, read-only context passed to every analyzer during a scan."""

    settings: Settings
    servers: list[ServerModel] = field(default_factory=list)

    def all_tools(self) -> list[ToolModel]:
        return [tool for server in self.servers for tool in server.tools]


@runtime_checkable
class Analyzer(Protocol):
    """A detector that inspects a single tool and returns zero or more findings."""

    id: str

    def analyze(self, tool: ToolModel, ctx: ScanContext) -> list[Finding]: ...


class AnalyzerRegistry:
    """Ordered registry of analyzers."""

    def __init__(self) -> None:
        self._analyzers: dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> Analyzer:
        if analyzer.id in self._analyzers:
            raise ValueError(f"Analyzer '{analyzer.id}' already registered")
        self._analyzers[analyzer.id] = analyzer
        return analyzer

    def unregister(self, analyzer_id: str) -> None:
        self._analyzers.pop(analyzer_id, None)

    def all(self) -> list[Analyzer]:
        return list(self._analyzers.values())

    def get(self, analyzer_id: str) -> Analyzer | None:
        return self._analyzers.get(analyzer_id)


default_registry = AnalyzerRegistry()
