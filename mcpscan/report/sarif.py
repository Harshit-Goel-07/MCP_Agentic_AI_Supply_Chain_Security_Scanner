"""SARIF 2.1.0 output.

SARIF is the primary machine format so results integrate with GitHub code scanning and other
CI tooling. Toxic-flow chains are encoded as ``codeFlows`` so each hop is visible.
"""

from __future__ import annotations

from typing import Any

from mcpscan.config import Severity
from mcpscan.models import ScanResult
from mcpscan.rules.engine import load_catalog

_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _rules_section() -> list[dict[str, Any]]:
    catalog = load_catalog()
    return [
        {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "helpUri": f"https://owasp.org/www-project-mcp-top-10/#{rule.owasp_mcp_id}",
            "properties": {
                "owaspMcpId": rule.owasp_mcp_id,
                "category": rule.category,
                "security-severity": str(_security_severity(rule.default_severity)),
            },
        }
        for rule in catalog.rules
    ]


def _security_severity(severity: Severity) -> float:
    return {
        Severity.INFO: 0.0,
        Severity.LOW: 3.0,
        Severity.MEDIUM: 5.5,
        Severity.HIGH: 8.0,
        Severity.CRITICAL: 9.5,
    }[severity]


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Serialise a scan result to a SARIF 2.1.0 log dictionary."""

    results: list[dict[str, Any]] = []
    for finding in result.findings:
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.message or finding.title},
            "properties": {
                "owaspMcpId": finding.owasp_mcp_id,
                "confidence": finding.confidence,
                "aiAssisted": finding.ai_assisted,
                "server": finding.server,
                "tool": finding.tool,
            },
        }
        if finding.location is not None:
            entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.server or "mcp"},
                        "region": {"snippet": {"text": finding.location.field}},
                    }
                }
            ]
        results.append(entry)

    for chain in result.chains:
        results.append(
            {
                "ruleId": "MCP-FLOW-001",
                "level": _LEVEL[chain.severity],
                "message": {
                    "text": "Cross-server toxic flow: "
                    + " -> ".join(step.tool for step in chain.path)
                },
                "codeFlows": [
                    {
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "message": {
                                                "text": f"{step.tool} [{step.capability.value}]"
                                            }
                                        }
                                    }
                                    for step in chain.path
                                ]
                            }
                        ]
                    }
                ],
                "properties": {"flowType": chain.flow_type, "confidence": chain.confidence},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPScan",
                        "informationUri": "https://github.com/your-org/mcpscan",
                        "version": result.scanner_version,
                        "rules": _rules_section(),
                    }
                },
                "results": results,
                "properties": {
                    "riskScore": result.risk_score,
                    "findingsHash": result.findings_hash(),
                    "severityCounts": result.severity_counts(),
                },
            }
        ],
    }
