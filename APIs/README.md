# APIs — MCP Supply-Chain Security Scanner

Three surfaces: **CLI** (primary), **REST** (server mode), **SARIF** (machine output).

## 1. CLI (typer)

```bash
# Discover configs and scan statically
mcpscan scan --targets ./ --format sarif --out results.sarif

# Full scan incl. capability graph + dynamic sandbox + LLM judge
mcpscan scan --targets ./mcp.json --dynamic --llm ollama:qwen2.5-coder \
             --graph-export graph.mmd --format html --out report.html

# Diff two scans for rug-pull / drift detection
mcpscan diff --base scan-2026-01.json --head scan-2026-02.json

# Explain a single tool's risk
mcpscan explain --server filesystem --tool read_file
```

| Flag | Purpose |
|------|---------|
| `--targets` | Files/dirs/config globs to scan |
| `--dynamic` | Enable Docker sandbox ATPA testing |
| `--llm` | Optional semantic judge backend |
| `--fail-on` | Severity threshold for non-zero exit (CI gate) |
| `--format` | `sarif` \| `html` \| `json` |

## 2. REST API (FastAPI)

```mermaid
flowchart LR
    C[Client/UI] -->|POST /scans| API
    API -->|202 + scan_id| C
    C -->|GET /scans/{id}| API
    C -->|GET /scans/{id}/graph| API
    C -->|GET /scans/{id}/report.sarif| API
```

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Start a scan (body: targets, options) → `202` + `scan_id` |
| `GET` | `/api/v1/scans/{id}` | Scan status + summary |
| `GET` | `/api/v1/scans/{id}/findings` | Paginated findings, filterable by severity/OWASP id |
| `GET` | `/api/v1/scans/{id}/graph` | Capability graph (JSON + Mermaid) |
| `GET` | `/api/v1/scans/{id}/report.sarif` | SARIF 2.1 document |
| `POST` | `/api/v1/scans/diff` | Drift diff between two scans |
| `GET` | `/api/v1/rules` | Rule catalog + OWASP MCP mapping |
| `GET` | `/healthz` | Liveness |

### Example request

```http
POST /api/v1/scans
Content-Type: application/json

{
  "targets": ["./mcp.json"],
  "dynamic": true,
  "llm": {"provider": "ollama", "model": "qwen2.5-coder"},
  "fail_on": "high"
}
```

### Example finding (JSON)

```json
{
  "id": "b1c2...",
  "tool": "read_file",
  "server": "filesystem",
  "rule_id": "MCP-TP-001",
  "owasp_mcp_id": "MCP-01",
  "severity": "high",
  "confidence": 0.91,
  "ai_assisted": true,
  "evidence": {"field": "description", "span": [142, 210]}
}
```

## 3. SARIF 2.1 Output Contract

- One `run` per scan; `tool.driver.rules[]` mirrors the rule catalog.
- Each finding → `result` with `ruleId`, `level`, `locations[]` (file/URI + region), and
  `properties.owaspMcpId`, `properties.confidence`.
- Toxic-flow chains → `result` with `codeFlows[]` describing each hop across servers.

## 4. Pydantic Models (contract source of truth)

`ScanRequest`, `ScanSummary`, `Finding`, `Chain`, `Rule`, `GraphExport` — all versioned under
`/api/v1`; OpenAPI auto-published at `/docs`.
