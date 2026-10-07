# `mcpscan` Python Package

This directory contains the core Python implementation of the MCP Agentic AI Supply Chain Security Scanner.

## Module Structure

- **`cli.py`**:
  - Typer CLI entrypoint (`mcpscan scan`, `mcpscan rules`, `mcpscan serve`, `mcpscan generate-report`).
  - Implements exit codes, parameter parsing, output format selection (terminal table, JSON, SARIF, HTML).

- **`config.py`**:
  - `pydantic-settings` configuration loader for scanning thresholds, Neo4j connection parameters, Ollama/OpenAI API keys, and cache locations.

- **`models.py`**:
  - Pydantic v2 data models for `ToolDefinition`, `ServerConfig`, `Finding`, `ToxicFlowPath`, and `ScanResult`.

- **`scanner.py`**:
  - Orchestration pipeline coordinating discovery, connection, semantic analysis, graph path-finding, and scoring.

- **`scoring.py`**:
  - Risk scoring engine calculating an aggregate security score (0–100) based on severity weights and toxic graph flow multipliers.

- **`discovery/`**:
  - Configuration file discovery (`mcp.json`, Claude desktop configs, cursor rules, environment variables).

- **`connector/`**:
  - Protocol connectors for dynamically inspecting tools via stdio, SSE, or static schema JSON.

- **`analyzers/`**:
  - Static text analysis, capability tagging (`READ_UNTRUSTED`, `EXEC`, `EGRESS`, `WRITE_STATE`), and semantic similarity detection.

- **`graph/`**:
  - NetworkX directed graph builder for cross-tool and cross-server toxic flow analysis.

- **`rules/`**:
  - Security rule engine executing OWASP Top 10 for MCP checks loaded from `catalog.yaml`.

- **`report/`**:
  - Output generators for JSON, SARIF v2.1.0, and interactive HTML with embedded Mermaid.js diagrams.

- **`llm/`**:
  - LLM-assisted semantic analysis interface with Ollama (local) and OpenAI fallbacks.

- **`api/`**:
  - FastAPI web server exposing REST endpoints for CI/CD integrations and dashboard clients.
