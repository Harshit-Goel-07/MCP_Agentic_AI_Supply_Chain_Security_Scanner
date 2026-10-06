# Documentation — MCP Supply-Chain Security Scanner

## 1. Documentation Map

```
Documentation/
├── user-guide/          # install, first scan, CI setup
├── concepts/            # MCP basics, capability model, toxic flows
├── rules/               # every rule id, rationale, OWASP MCP mapping
├── dev-guide/           # architecture, writing analyzers/rules
├── adr/                 # architecture decision records
├── runbooks/            # server-mode ops, incident response
└── research/            # empirical study paper + datasets
```

## 2. User Guide (outline)

- **Install**: `pipx install mcpscan` / Docker / Action.
- **First scan**: `mcpscan scan --targets ./` and reading the report.
- **CI integration**: adding the Action, interpreting SARIF in code scanning.
- **Interpreting findings**: severity, confidence, evidence spans, OWASP MCP ids.

## 3. Concepts

- What MCP is (servers, tools, prompts, resources, transports).
- **Capability model**: `READ_SENSITIVE`, `READ_UNTRUSTED`, `EGRESS`, `WRITE_STATE`, `EXECUTE`.
- **Toxic flows**: why individually-benign tools chain into exfiltration.
- **ATPA / rug-pull**: time-bomb tools and behavioral detection.

## 4. Rules Reference

Auto-generated from `rules/catalog.yaml`; each entry documents id, title, severity,
OWASP MCP mapping, detection method, examples (positive/negative), and remediation.

## 5. Developer Guide

- Repo layout (see `Backend Structure/`).
- **Writing an analyzer**: implement the `Analyzer` protocol + register + add fixtures.
- **Adding a rule**: YAML entry + test samples + OWASP mapping (Detection-as-Code).
- Local dev: `docker compose up`, `pytest`, `ruff`, `mypy`.

## 6. ADRs (initial)

| ADR | Decision |
|-----|----------|
| 0001 | Python-first core, optional Rust hot path |
| 0002 | NetworkX at scan time, Neo4j for persistence |
| 0003 | LLM optional + cached for reproducibility |
| 0004 | SARIF 2.1 as primary machine format |
| 0005 | Sandbox `--network=none` default for dynamic analysis |

## 7. Runbooks

- Server-mode deploy/upgrade/rollback.
- Handling a discovered active-malicious tool (containment + disclosure).
- Rotating LLM keys, purging the LLM cache.

## 8. Research Output

The `research/` folder holds the empirical-study paper draft, methodology, anonymized dataset,
and reproducibility scripts — the publication/interview centerpiece.

## 9. Docs Tooling

MkDocs Material (or Docusaurus) built and deployed via CI to GitHub Pages; Mermaid diagrams
rendered inline; rules page generated from the catalog at build time.
