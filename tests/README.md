# Test Suite Directory

This directory contains automated test suites for verifying all security analyzers, graph building algorithms, report generators, and REST API endpoints of the MCP Security Scanner.

## Test Files

- **`conftest.py`**:
  - Global pytest fixtures providing mock server configurations, toxic tool definitions, and temporary report directories.

- **`test_scanner_e2e.py`**:
  - Comprehensive end-to-end integration tests.
  - Verifies scanner execution on JSON config fixtures.
  - Tests output formats (JSON, SARIF, HTML).
  - Tests FastAPI REST API endpoints (`/healthz`, `/api/v1/rules`, `/api/v1/scans`, `/api/v1/scans/sarif`).

- **`test_static_text.py`**:
  - Unit tests for deterministic static keyword and regex pattern matching in tool descriptions.
  - Verifies detection of high-risk capabilities like bash execution, file writes, and credential theft.

- **`test_toxic_flow.py`**:
  - Unit tests for graph construction and toxic path analysis (`NetworkX` directed graph).
  - Verifies taint propagation from `READ_UNTRUSTED` source nodes to `EXEC` and `EGRESS` sink nodes.

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=mcpscan --cov-report=term-missing
```
