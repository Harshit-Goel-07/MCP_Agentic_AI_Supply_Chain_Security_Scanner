# GitHub Workflows & Actions

This directory configures automated continuous integration, testing, code quality checks, and GitHub Actions integration for the MCP Supply Chain Security Scanner.

## Contents

- **`workflows/ci.yml`**:
  - Continuous Integration pipeline testing across Python 3.11 and 3.12.
  - Executes linting (`ruff`), type checking (`mypy`), security static checks (`bandit`), and unit/integration test suites (`pytest`).
  - Scans example MCP configurations and uploads SARIF security results to GitHub Code Scanning.

- **`../action.yml`** (Workspace Root):
  - Reusable GitHub Action definition allowing any repository to drop in `mcpscan` as a security gate in their CI pipeline.
