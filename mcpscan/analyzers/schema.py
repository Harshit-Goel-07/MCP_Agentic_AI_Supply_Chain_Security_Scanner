"""Schema / capability analysis.

Two responsibilities:

1. **Capability tagging** — derive abstract capabilities (read-sensitive, egress, execute, ...)
   from a tool's name, description, and input schema. These tags feed the capability graph and
   the cross-server toxic-flow search.
2. **Excessive-scope detection** — flag tools that request dangerous or over-broad parameters
   (raw commands, arbitrary URLs, unrestricted file paths).
"""

from __future__ import annotations

import re
from typing import Any

from mcpscan.analyzers.base import ScanContext
from mcpscan.config import Severity
from mcpscan.models import Capability, EvidenceLocation, Finding, ToolModel

_SENSITIVE_HINTS = (
    "secret",
    "token",
    "credential",
    "password",
    "private_key",
    "env",
    "/etc",
    "ssh",
)
_UNTRUSTED_HINTS = ("url", "fetch", "http", "web", "download", "read_file", "readfile", "open")
_EGRESS_HINTS = ("post", "upload", "send", "webhook", "publish", "email", "http_request", "request")
_EXECUTE_HINTS = ("exec", "shell", "command", "run", "spawn", "eval", "subprocess")
_WRITE_HINTS = ("write", "delete", "update", "create", "put", "set")

_DANGEROUS_PARAMS = {
    "command": Severity.HIGH,
    "cmd": Severity.HIGH,
    "shell": Severity.HIGH,
    "script": Severity.HIGH,
    "url": Severity.MEDIUM,
    "path": Severity.MEDIUM,
    "file": Severity.MEDIUM,
}


def _iter_property_names(schema: dict[str, Any]) -> list[str]:
    props = schema.get("properties")
    if isinstance(props, dict):
        return [str(k).lower() for k in props]
    return []


def infer_capabilities(tool: ToolModel) -> list[Capability]:
    """Infer capability tags from a tool's surface. Deterministic and side-effect free."""

    haystack = " ".join(
        [
            tool.name.lower(),
            tool.description.lower(),
            " ".join(_iter_property_names(tool.input_schema)),
        ]
    )
    caps: set[Capability] = set()
    if any(h in haystack for h in _SENSITIVE_HINTS):
        caps.add(Capability.READ_SENSITIVE)
    if any(h in haystack for h in _UNTRUSTED_HINTS):
        caps.add(Capability.READ_UNTRUSTED)
    if any(h in haystack for h in _EGRESS_HINTS):
        caps.add(Capability.EGRESS)
    if any(h in haystack for h in _EXECUTE_HINTS):
        caps.add(Capability.EXECUTE)
    if any(re.search(rf"\b{h}\b", haystack) for h in _WRITE_HINTS):
        caps.add(Capability.WRITE_STATE)
    return sorted(caps, key=lambda c: c.value)


class SchemaAnalyzer:
    id = "schema"

    def analyze(self, tool: ToolModel, ctx: ScanContext) -> list[Finding]:
        # Enrich the tool in place so downstream graph analysis sees capabilities.
        if not tool.capabilities:
            tool.capabilities = infer_capabilities(tool)

        findings: list[Finding] = []
        for prop in _iter_property_names(tool.input_schema):
            for dangerous, severity in _DANGEROUS_PARAMS.items():
                if prop == dangerous or prop.endswith(f"_{dangerous}"):
                    findings.append(
                        Finding(
                            rule_id="MCP-SCOPE-001",
                            owasp_mcp_id="MCP-04",
                            severity=severity,
                            confidence=0.7,
                            tool=tool.qualified_name,
                            server=tool.server,
                            title="Excessive or dangerous parameter",
                            message=f"Tool accepts a high-risk parameter '{prop}' (potential command/SSRF/path abuse).",
                            location=EvidenceLocation(field=f"input_schema.properties.{prop}"),
                            evidence={"parameter": prop},
                        )
                    )

        if (
            Capability.EXECUTE in tool.capabilities
            and Capability.READ_UNTRUSTED in tool.capabilities
        ):
            findings.append(
                Finding(
                    rule_id="MCP-SCOPE-002",
                    owasp_mcp_id="MCP-07",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    tool=tool.qualified_name,
                    server=tool.server,
                    title="Execute + untrusted-read on one tool",
                    message="Tool can both read untrusted input and execute; a classic confused-deputy surface.",
                    evidence={"capabilities": [c.value for c in tool.capabilities]},
                )
            )
        return findings
