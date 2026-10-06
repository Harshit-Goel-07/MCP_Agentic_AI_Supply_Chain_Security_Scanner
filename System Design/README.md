# System Design — MCP Supply-Chain Security Scanner

## 1. Scan Lifecycle (State Machine)

```mermaid
stateDiagram-v2
    [*] --> Discover
    Discover --> Connect: configs found
    Connect --> Normalize: tools enumerated
    Normalize --> StaticScan
    StaticScan --> SemanticScan
    SemanticScan --> GraphBuild
    GraphBuild --> ToxicFlowSearch
    ToxicFlowSearch --> DynamicScan: --dynamic
    ToxicFlowSearch --> Score: static-only
    DynamicScan --> Score
    Score --> Report
    Report --> [*]
```

## 2. End-to-End Sequence

```mermaid
sequenceDiagram
    participant U as User/CI
    participant C as CLI (typer)
    participant D as Discovery
    participant M as MCP Connector
    participant A as Analyzers
    participant G as Graph Engine
    participant J as LLM Judge (opt)
    participant R as Report Writer

    U->>C: mcpscan scan --targets ./ --dynamic
    C->>D: locate MCP configs
    D-->>C: server list
    C->>M: connect + list tools/prompts/resources
    M-->>C: normalized tool models
    C->>A: run static + semantic analyzers
    A->>J: ambiguous case -> semantic verdict
    J-->>A: poisoning score + rationale
    A-->>C: findings[]
    C->>G: build capability graph + search toxic flows
    G-->>C: cross-server chains[]
    C->>R: aggregate + score
    R-->>U: SARIF + HTML report (exit code by severity)
```

## 3. Data-Flow Diagram (DFD Level 1)

```mermaid
flowchart LR
    A[MCP Configs] -->|paths| P1((Discovery))
    P1 -->|servers| P2((Connector))
    MCP[[MCP Servers]] -->|tool specs| P2
    P2 -->|Tool Model JSON| P3((Static/Semantic))
    P3 -->|Findings| DS1[(Findings Store)]
    P2 -->|capabilities| P4((Graph Build))
    P4 -->|graph| DS2[(Neo4j)]
    P4 -->|chains| P5((Toxic-Flow Search))
    P5 -->|chain findings| DS1
    DS1 -->|aggregate| P6((Scorer/Reporter))
    P6 -->|SARIF/HTML| OUT[Reports]
```

## 4. Toxic-Flow Detection Model

Each tool is tagged with **capabilities**: `READ_UNTRUSTED`, `READ_SENSITIVE`, `EGRESS`,
`WRITE_STATE`, `EXECUTE`. A **toxic flow** is any path where untrusted/sensitive data can reach
an egress capability, potentially across servers:

```mermaid
flowchart LR
    T1[Tool A: read_file\nREAD_SENSITIVE] --> AG{Agent Context}
    T2[Tool B: fetch_url\nREAD_UNTRUSTED] --> AG
    AG --> T3[Tool C: http_post\nEGRESS]
    style T3 fill:#f88
```

Detection = reachability query over the capability graph where a `READ_SENSITIVE`/`READ_UNTRUSTED`
node can influence an `EGRESS` node (same or different server), ranked by confidence.

## 5. Behavioral (ATPA) Testing

Adversarial Tool Poisoning Attack detection: invoke a tool repeatedly with benign inputs over
time/iterations and watch for description mutation, response drift, or new egress attempts —
catching **rug-pull** tools that pass static checks initially.

## 6. Non-Functional Requirements

| NFR | Requirement |
|-----|-------------|
| Safety | Dynamic runs isolated (`--network=none`, no host FS) |
| Reproducibility | Deterministic findings hash; LLM responses cached |
| Performance | 100 tools static-scanned < 30s |
| Portability | Runs as CLI, library, server, and GitHub Action |
| Auditability | Every finding carries rule id, evidence span, OWASP MCP mapping |
