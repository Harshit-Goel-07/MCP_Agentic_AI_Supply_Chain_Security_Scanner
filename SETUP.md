# MCPScan — Development & Usage Setup

> This is the code setup guide. See `README.md` for the design overview and the section folders
> (`Architecture/`, `System Design/`, ...) for detailed design docs.

## Requirements

- Python **3.11+**
- (Optional) Docker for containerized runs
- (Optional) Neo4j for persisted capability graphs (in-process NetworkX is the default)

## Create a virtual environment (do NOT install globally)

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e ".[dev,api,semantic]"
```

## Quick start

```bash
# Scan a directory / mcp.json config, offline, deterministic
mcpscan scan --targets ./examples --format sarif --out results.sarif

# Human-readable table + HTML report
mcpscan scan --targets ./examples --format html --out report.html

# Fail CI when high-severity findings exist
mcpscan scan --targets ./examples --fail-on high

# List the rule catalog
mcpscan rules

# Diff two scans (rug-pull / drift detection)
mcpscan diff --base scan-a.json --head scan-b.json
```

## Run the API (optional)

```bash
uvicorn mcpscan.api.app:app --reload --port 8080
# OpenAPI docs at http://localhost:8080/docs
```

## Quality gates

```bash
ruff check .
ruff format --check .
mypy mcpscan
pytest
```

## Notes

- The scanner runs **fully offline by default**. The LLM semantic judge and MCP live-connector
  are optional and behind interfaces; the offline analyzers (static text, schema, capability
  graph, toxic-flow) require no network.
- All analysis is deterministic: identical inputs produce an identical findings hash.
