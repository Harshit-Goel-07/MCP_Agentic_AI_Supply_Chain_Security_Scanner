# Infrastructure — MCP Supply-Chain Security Scanner

The tool runs primarily as a **local CLI**, so infra is light. Server mode + the empirical study
add containers and a sandbox host.

## 1. Runtime Topology

```mermaid
flowchart TB
    subgraph Dev/CI Host
      CLI[mcpscan CLI]
      SBX[Docker Sandbox\n--network=none]
    end
    subgraph Server Mode (optional)
      API[FastAPI]
      PG[(PostgreSQL)]
      NEO[(Neo4j)]
      OLL[Ollama (local LLM)]
    end
    CLI --> SBX
    CLI --> API
    API --> PG
    API --> NEO
    API --> OLL
```

## 2. Containers

| Image | Purpose |
|-------|---------|
| `mcpscan` | CLI + API (multi-stage, distroless runtime) |
| `mcpscan-sandbox` | Minimal image used to execute untrusted MCP tools |
| `postgres:16` | Findings/metadata |
| `neo4j:5` | Capability graph |
| `ollama/ollama` | Optional local LLM judge |

## 3. Docker Compose (server mode)

```yaml
services:
  api:
    build: .
    command: uvicorn mcpscan.api.app:app --host 0.0.0.0 --port 8080
    environment:
      - MCPSCAN_PG_DSN=postgresql://scan:scan@pg:5432/mcpscan
      - MCPSCAN_NEO4J_URI=bolt://neo4j:7687
    depends_on: [pg, neo4j]
  pg:
    image: postgres:16
    environment: { POSTGRES_USER: scan, POSTGRES_PASSWORD: scan, POSTGRES_DB: mcpscan }
  neo4j:
    image: neo4j:5
    environment: { NEO4J_AUTH: neo4j/scanscan }
```

## 4. Sandbox Isolation (dynamic analysis)

- `--network=none` by default; opt-in egress goes through a logging HTTP proxy only.
- `--read-only` rootfs, `--cap-drop=ALL`, `--pids-limit`, memory/CPU quotas.
- No host bind mounts; inputs injected via a scratch tmpfs volume.
- Seccomp + AppArmor profile restricting syscalls.

## 5. IaC

- **Dockerfiles** for `mcpscan` and `mcpscan-sandbox`.
- **docker-compose.yml** for local server mode.
- Optional **Terraform** module to stand up a single VM for the empirical study run
  (spot instance, ephemeral, auto-destroy).

## 6. Empirical Study Harness

A batch runner iterates over a curated list of public MCP servers, scans each in an isolated
sandbox, and aggregates anonymized findings into the `Evaluation/` dataset.
