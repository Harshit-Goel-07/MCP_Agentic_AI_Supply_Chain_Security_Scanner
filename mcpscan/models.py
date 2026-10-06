"""Core domain models shared across the scanner.

These pydantic models are the contract between analyzers, the graph engine, the rule engine,
the scorer, and the report writers. They are intentionally serialisation-friendly so a scan can
be persisted as JSON and later diffed (rug-pull / drift detection).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcpscan.config import Severity


class Capability(str, Enum):
    """Abstract capability tags used to reason about data flows across tools."""

    READ_SENSITIVE = "READ_SENSITIVE"
    READ_UNTRUSTED = "READ_UNTRUSTED"
    EGRESS = "EGRESS"
    WRITE_STATE = "WRITE_STATE"
    EXECUTE = "EXECUTE"


class Transport(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    UNKNOWN = "unknown"


class ToolModel(BaseModel):
    """A normalised MCP tool definition."""

    server: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[Capability] = Field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}::{self.name}"

    @property
    def description_hash(self) -> str:
        payload = json.dumps(
            {"description": self.description, "schema": self.input_schema},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class ServerModel(BaseModel):
    """A normalised MCP server and the tools it exposes."""

    name: str
    transport: Transport = Transport.UNKNOWN
    source_config: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    tools: list[ToolModel] = Field(default_factory=list)



class EvidenceLocation(BaseModel):
    field: str
    span: tuple[int, int] | None = None


class Finding(BaseModel):
    """A single security finding raised against a tool (or a cross-server chain)."""

    rule_id: str
    owasp_mcp_id: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    tool: str | None = None
    server: str | None = None
    title: str = ""
    message: str = ""
    location: EvidenceLocation | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    ai_assisted: bool = False

    def stable_id(self) -> str:
        payload = json.dumps(
            {
                "rule_id": self.rule_id,
                "tool": self.tool,
                "server": self.server,
                "location": self.location.model_dump() if self.location else None,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


class ChainStep(BaseModel):
    tool: str
    capability: Capability


class Chain(BaseModel):
    """A cross-server toxic flow: a path from a sensitive/untrusted source to an egress sink."""

    flow_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    path: list[ChainStep]

    def as_finding(self) -> Finding:
        hops = " -> ".join(step.tool for step in self.path)
        return Finding(
            rule_id="MCP-FLOW-001",
            owasp_mcp_id="MCP-06",
            severity=self.severity,
            confidence=self.confidence,
            title="Cross-server toxic data flow",
            message=f"Potential data exfiltration chain: {hops}",
            evidence={"path": [step.model_dump() for step in self.path], "flow_type": self.flow_type},
        )


class ScanResult(BaseModel):
    """The full, serialisable output of a scan."""

    scanner_version: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    mode: str = "static"
    servers: list[ServerModel] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    chains: list[Chain] = Field(default_factory=list)
    risk_score: int = 0

    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def findings_hash(self) -> str:
        """Deterministic hash of findings, enabling reproducibility assertions in CI."""

        ids = sorted(f.stable_id() for f in self.findings)
        return hashlib.sha256("".join(ids).encode()).hexdigest()

    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
