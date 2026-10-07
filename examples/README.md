# Examples Directory

This directory contains test fixtures and sample MCP configurations used for testing, benchmarking, and demonstrating the MCP Security Scanner.

## Contents

- **`benign.mcp.json`**:
  - Sample MCP configuration with safe, non-toxic tools (`read_file`, `calculator`).
  - Expected Risk Score: `0 - 15 / 100` (Low / Safe).

- **`poisoned.mcp.json`**:
  - Deliberately vulnerable MCP configuration demonstrating toxic multi-tool execution chains and prompt injection.
  - Contains tools like `fetch_webpage` (untrusted data input) chained with `execute_bash` (remote code execution) and `send_slack_message` (egress).
  - Expected Risk Score: `90 - 100 / 100` (Critical).

- **`github_mcp_server.mcp.json`**:
  - Full schema dump of a real-world MCP server (`github-mcp-server`) with 42 enterprise tools.
  - Used for large-scale tool toxicity analysis and graph clustering demonstrations.

- **`live.mcp.json`**:
  - Configuration pointing to a live local subprocess or HTTP-based MCP server.

- **`live_poisoned_server.py`**:
  - Standalone mock MCP server using stdio transport that emits vulnerable tool schemas on connection.
  - Used for integration tests with `mcpscan/connector/stdio.py`.

## Running Scans on Examples

```bash
# Scan benign server
mcpscan scan --file examples/benign.mcp.json

# Scan poisoned testbed with HTML report
mcpscan scan --file examples/poisoned.mcp.json --format html --output report_poisoned.html

# Scan GitHub MCP server
mcpscan scan --file examples/github_mcp_server.mcp.json --format html --output report_github.html
```
