# MCP / Agentic-AI Tool Supply-Chain Security Scanner

> Project #18 — Agentic-AI Security track
> A scanner that audits **Model Context Protocol (MCP)** servers and agent tool surfaces for
> tool poisoning, prompt injection, rug-pulls, and **cross-server "toxic-flow" attack chains**,
> mapped to the **OWASP MCP Top 10**.

---

## 1. Elevator Pitch

MCP exploded to 10,000+ servers in 2025 with 25+ documented CVEs. Agentic AI is the newest,
least-governed attack surface. Individually benign tools chain into exfiltration paths across
servers (a data-reading tool on server A + an egress tool on server B = a data-exfil chain).

This project builds a scanner that:

- **Statically** analyzes MCP tool descriptions, schemas, and prompts for injection, hidden
  Unicode, special-token injection, and excessive scopes.
- Builds a **cross-server capability graph** and searches for **toxic cross-server flows**.
- **Dynamically** fuzzes tools in a Docker sandbox and detects behavioral (runtime) poisoning
  such as benign-then-malicious "time-bomb" (rug-pull) tools.
- Emits **SARIF 2.1** + HTML reports, mapped to the **OWASP MCP Top 10**, for CI/CD gating.

## 2. The Frontier Differentiator

Most scanners read a single tool's description in isolation. The **cross-server capability-graph
toxic-flow analysis** plus **behavioral runtime poisoning detection** is the frontier.

## 3. Pipeline Structure (this repository)

```
18-MCP-Agentic-AI-Supply-Chain-Security-Scanner/
├── Architecture/          # C4 + component views, tech decisions
├── System Design/         # scan lifecycle, sequence + data-flow diagrams
├── Database Design/       # capability-graph + findings schema
├── APIs/                  # REST + CLI + SARIF contracts
├── Frontend Structure/    # React report UI + graph visualizer
├── Backend Structure/     # scanner engine module layout
├── Infrastructure/        # sandbox, containers, IaC
├── CI-CD/                 # GitHub Actions, SARIF upload, self-scan
├── Deployment/            # CLI distribution, server mode, action
├── Monitoring/            # observability, scan telemetry
├── Documentation/         # user + dev docs, ADRs, runbooks
├── Threat-Model/          # OWASP MCP Top 10 mapping + attack catalog
└── Evaluation/            # empirical study methodology + metrics
```

Each folder contains a detailed `README.md` covering explanations, diagrams, component
interactions, folder hierarchy, deployment strategy, and roadmap contributions.

## 4. Tech Stack Summary

| Layer | Choice |
|-------|--------|
| Core scanner | Python 3.12 (typer CLI), optional Rust perf core |
| MCP integration | Official MCP Python SDK |
| Static analysis | AST/JSON-schema walkers, Unicode/homoglyph detectors |
| Semantic detection | TF-IDF/GloVe similarity + optional `Llama-Prompt-Guard-2` (local) |
| LLM judge | Claude / local Ollama (Qwen) |
| Graph | NetworkX in-proc + Neo4j (persisted) + Mermaid export |
| Dynamic analysis | Docker sandbox fuzzer, seccomp/network egress capture |
| Output | SARIF 2.1, HTML/React report |
| Backend API | FastAPI + Pydantic v2 |
| DB | PostgreSQL (metadata) + Neo4j (graph) |
| CI | GitHub Actions (SARIF upload to code scanning) |

## 5. Implementation Roadmap (12 weeks, light pace)

| Phase | Weeks | Deliverable |
|-------|-------|-------------|
| Static scanner | 1–3 | Config discovery, tool description/schema scan, Unicode + scope heuristics |
| Capability graph | 4–6 | Cross-server capability graph + toxic-flow detection |
| Semantic + LLM judge | 7–9 | Similarity + LLM semantic poisoning judge, SARIF/HTML report |
| Empirical study | 10–12 | Scan N public MCP servers, dynamic ATPA sandbox, writeup |

## 6. Measurable Outcomes

- Fraction of real MCP servers carrying poisoning/injection risk.
- Precision/recall of static + semantic detectors on a labeled corpus.
- Cross-server exfil chains surfaced by the capability graph.
- Time-bomb (rug-pull) tools caught by behavioral testing that static analysis misses.

## 7. Authenticity Grounding

Modeled on 2025–2026 tools: `mcp-tool-auditor` (ATPA, OWASP MCP Top 10),
`MCP-Lattice` (cross-server capability graph), `mcp-fence`, `MCP Armor`, `fuzzd`.
