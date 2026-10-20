# ScopeSentry-R Submission Diagrams

These reviewed diagrams describe the implemented local proof of concept. Dashed or labelled boundaries distinguish synthetic providers, process-local state, supplied observations, and simulated enforcement. Module references are repository-relative and do not imply real-provider integration.

## Figure 1 — Overall architecture

```mermaid
flowchart TB
    U[Declared user intent and mock grants] --> API[FastAPI service layer]
    subgraph SYN[Synthetic-provider boundary]
      REG[Provider registry and catalogues]
      DEMO[Deterministic scenario fixtures]
    end
    API --> MAP[Provider-qualified intent mapping]
    REG --> MAP
    MAP --> GRAPH[Capability graph]
    GRAPH --> EXP[Exposure differential]
    EXP --> SYNTH[Bounded least-privilege synthesis]
    SYNTH --> CONTRACT[Process-local isolated contracts]
    OBS[Supplied runtime observations] --> GATE[Simulated runtime enforcement]
    CONTRACT --> GATE
    GRAPH --> COMP[Observed vs authorized flow analysis]
    GATE --> EVID[Local tamper-evident evidence]
    COMP --> EVID
    API --> DASH[Same-origin explainability dashboard]
```

**Caption.** Implemented pipeline from declared intent to evidence-linked decisions. Synthetic adapters do not contact commercial providers; runtime observations are caller-supplied; contracts are process-local. Implementation: `app/providers/registry.py`, `app/catalogue.py`, `app/planner/`, `app/gateway/`, `app/evidence/`, `app/static/dashboard/`.

## Figure 2 — Processing sequence

```mermaid
sequenceDiagram
    actor User
    participant Adapter as Synthetic adapter
    participant Analysis as Analysis services
    participant Planner as Synthesizer
    participant Contract as Process-local repository
    participant Gateway as Policy engine
    participant Evidence as Evidence service
    User->>Adapter: Select declared local grant
    Adapter-->>Analysis: Provider-qualified scopes and intent
    Analysis->>Analysis: Map intent, build graph, calculate exposure
    Analysis->>Planner: Required capabilities and catalogue
    Planner-->>Analysis: Exact bounded scope plan
    Analysis->>Evidence: Append redacted analysis decision
    Analysis->>Contract: Create isolated temporary contract
    User->>Gateway: Supply observed identity/scopes and attempted capability
    Gateway->>Contract: Load stored binding
    Gateway->>Gateway: Evaluate ordered fail-closed rules
    Gateway->>Evidence: Append runtime decision
    Gateway-->>User: allow, block, or quarantine
```

**Caption.** The gateway evaluates supplied observations; it does not intercept a real OAuth operation. Implementation: `app/services/analysis_service.py`, `app/planner/least_privilege_synthesizer.py`, `app/gateway/contracts.py`, `app/gateway/policy_engine.py`, `app/evidence/service.py`.

## Figure 3 — Provider-qualified capability graph

```mermaid
flowchart LR
    subgraph G[Canonical authority provider: google]
      GS[scope\nprovider=google\nprincipal=P1\ngrant=G1]
      GC[capability\nprovider=google\nprincipal=P1\ngrant=G1]
      GS --> GC
    end
    subgraph E[Canonical authority provider: mock-enterprise]
      ES[scope: content.read\nprincipal=P1\ngrant=G1]
      EC[capability: read_profile\nprincipal=P1\ngrant=G1]
      ES --> EC
    end
    subgraph C[Canonical authority provider: mock-code-host]
      CS[scope: content.read\nprincipal=P1\ngrant=G1]
      CC[capability: read_profile\nprincipal=P1\ngrant=G1]
      CS --> CC
    end
```

**Caption.** Identical textual scope or capability names do not merge authority across canonical providers. NetworkX node IDs are deterministic encodings; structured attributes are authoritative. Implementation: `app/graph/capability_graph.py`, `app/schemas/identity.py`.

## Figure 4 — Contract isolation

```mermaid
flowchart TB
    A[Analysis result] --> C1[Contract A\nprovider + principal + grant IDs\nscopes + capabilities]
    A --> C2[Contract B\nprovider + principal + grant IDs\nscopes + capabilities]
    C1 -. no authority union .- C2
    C1 --> R1[(Process-local repository)]
    C2 --> R1
    R1 --> P[Policy engine loads stored identity]
```

**Caption.** Contracts bind one provider/grant authority boundary; unrelated providers are not combined into a global contract. Repository persistence ends with the process. Implementation: `app/gateway/contracts.py`, `app/gateway/repository.py`, `app/services/gateway_service.py`.

## Figure 5 — Runtime decision flow

```mermaid
flowchart TD
    S[Supplied evaluation request] --> K{Known contract?}
    K -- no --> N[HTTP 404]
    K -- yes --> ST{revoked, quarantined, or expired?}
    ST -- yes --> B[Block]
    ST -- no --> PI{provider identity matches?}
    PI -- no --> B
    PI -- yes --> PR{principal matches?}
    PR -- no --> B
    PR -- yes --> GR{grant context matches?}
    GR -- no --> B
    GR -- yes --> SC{unexpected observed scope?}
    SC -- yes --> Q[Quarantine]
    SC -- no --> MS{required observed scope missing?}
    MS -- yes --> B
    MS -- no --> CA{capability contract permits attempt?}
    CA -- no --> B
    CA -- yes --> AL[Allow in simulator]
```

**Caption.** Identity checks precede scope and capability checks. Unknown or malformed states never default to allow. This is runtime capability-decision enforcement within the credential-free simulator. Implementation: `app/gateway/policy_engine.py`, `app/services/gateway_service.py`.

## Figure 6 — Evidence chain

```mermaid
flowchart LR
    R1[Record 1\nprevious = 64 zeroes] -->|record hash| R2[Record 2\nprevious = hash 1]
    R2 -->|record hash| R3[Record 3\nprevious = hash 2]
    RED[Recursive sensitive-field redaction] --> R1
    CAN[Canonical UTF-8 JSON] --> R1
    CAN --> R2
    CAN --> R3
    V[Read-only verifier] --> R1
    V --> R2
    V --> R3
```

**Caption.** Each canonical record hashes all record fields except `record_hash` and links to its predecessor. The storage is tamper-evident under documented single-process/local-file assumptions, not tamper-proof. Implementation: `app/evidence/canonical.py`, `app/evidence/hash_chain.py`, `app/evidence/service.py`.

## Diagram interpretation limits

- Synthetic-provider boxes represent local catalogues, not real-provider compatibility.
- “Allow” means a simulator decision, not proof that an external provider operation occurred.
- Composition detection evaluates declared observed links; it is not autonomous network-flow discovery.
- Evidence integrity detects covered mutations during verification but does not protect against privileged replacement of the entire file and trust anchor.
