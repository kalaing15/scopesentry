# Architecture and Data Flow

These diagrams describe the implemented local PoC. Synthetic adapters do not contact commercial providers.

## Overall architecture

```mermaid
flowchart TB
  UI[Local dashboard /demo] --> API[FastAPI routers]
  API --> ANALYSIS[Analysis and exposure planner]
  API --> COMPOSE[Composition engines]
  API --> GATEWAY[Contract and gateway services]
  ANALYSIS --> CATALOG[Provider and intent catalogues]
  ANALYSIS --> GRAPH[Capability graph]
  ANALYSIS --> SYNTH[Least-privilege synthesizer]
  COMPOSE --> CATALOG
  GATEWAY --> REPO[Process-local contract repository]
  API --> EVIDENCE[Tamper-evident evidence service]
  EVIDENCE --> JSONL[Local JSON Lines chain]
```

## Trust boundaries

```mermaid
flowchart LR
  U[Untrusted API input] --> V[Schema and reference validation]
  F[Immutable local fixtures] --> V
  V --> T[Trusted normalized catalogues and policies]
  T --> D[Backend decision]
  D --> R[Redacted evidence boundary]
  D --> B[Same-origin dashboard display]
```

Untrusted values do not become authority solely because they are syntactically valid. Unknown scopes remain untrusted. Catalogue and fixture correctness is a PoC trust assumption.

## Intent-to-contract workflow

```mermaid
flowchart LR
  I[User intent] --> M[map_provider_intents]
  M --> Q[Provider-qualified required authority]
  G[Granted scopes] --> CG[build_capability_graph]
  Q --> CG
  CG --> X[calculate_exposure_differential]
  X --> S[synthesize_least_privilege]
  S -->|complete| C[Provider/grant-bound contract]
  S -->|manual review or incomplete| N[No active contract]
```

## Runtime gateway workflow

```mermaid
flowchart TB
  A[Capability attempt] --> K{Known usable contract?}
  K -->|No| B[Block]
  K -->|Yes| ID{Provider, principal, grant match?}
  ID -->|No| B
  ID -->|Yes| SC{Observed scopes exact?}
  SC -->|Unexpected| Q[Quarantine]
  SC -->|Missing| B
  SC -->|Exact| CAP{Capability allowed and enabled?}
  CAP -->|No| B
  CAP -->|Yes| AL[Allow]
```

## Cross-provider composition

```mermaid
flowchart LR
  SG[Source provider / principal / grant / capability] --> O[Observed data-flow link]
  O --> TG[Target provider / principal / grant / capability]
  O --> C{Exact authorized-flow contract?}
  C -->|All fields match| OK[Authorized observed flow]
  C -->|Absent or mismatch| U[Unauthorized path and remediation]
```

Observed links represent possible flow, not permission. There are no wildcard authorizations.

## Evidence chain

```mermaid
flowchart LR
  R1[Record 1: genesis previous hash] -->|record hash| R2[Record 2: previous hash]
  R2 -->|record hash| R3[Record N: previous hash]
  P[Redacted request/result/decision hashes] --> R1
  P --> R2
  P --> R3
```

Verification recomputes every record hash and checks JSON, sequence, genesis, and predecessor continuity.

## Scenario execution sequence

```mermaid
sequenceDiagram
  participant UI as Dashboard/API caller
  participant DR as DemoRunner
  participant P as Planner/Composition
  participant G as Gateway
  participant E as Evidence
  UI->>DR: Run named static scenario (empty body)
  DR->>P: Discover grants, map intent, analyze and synthesize
  P-->>DR: Exposure and plan
  DR->>P: Analyze observed/authorized flows if present
  DR->>G: Create isolated contract(s) when safe and complete
  DR->>G: Evaluate simulated attempts
  G->>E: Append decision evidence
  DR->>E: Verify chain and append demo completion
  DR-->>UI: Ordered timeline and backend decisions
```

## Module map

- API boundary: `app/api` and `app/main.py`
- Provider identity, catalogue, and fixtures: `app/providers`
- Planning and graphs: `app/planner`
- Contracts and runtime enforcement: `app/gateway`
- Evidence: `app/evidence`
- Demo orchestration: `app/orchestrator/demo_runner.py`
- Evaluation-only baseline and corpora: `app/evaluation`
- Read-only release verification: `app/release`
