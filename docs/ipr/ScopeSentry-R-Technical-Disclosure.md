# ScopeSentry-R Technical Disclosure

> **Technical annex.** The canonical Phase 7 submission wording is `docs/ipr/submission/01-Invention-Disclosure.md`. This annex supplies implementation detail and must be read with the submission glossary and qualifications.

## Title and technical field

**ScopeSentry-R: Intent-Locked, Provider-Qualified OAuth Capability Security.** The implementation is a credential-free local proof of concept for authorization analysis, bounded least-privilege planning, runtime capability-decision enforcement within the simulator, cross-grant composition analysis, and tamper-evident decision evidence.

## Background, technical problem, and static-checking limitations

Conventional static OAuth checks ask whether granted scopes cover scopes required by an action. This is useful but does not, by itself, minimize unrelated authority, bind later operations to intent, notice runtime authority drift, distinguish identical names across providers, or identify an unauthorized path formed by composing grants. ScopeSentry-R addresses that combined technical problem in a synthetic local environment. It does not claim that static checking is incorrectly implemented; the comparison baseline intentionally represents its normal required-scope coverage behavior.

## Implemented system summary

The implemented processing combination is:

```text
User intent
→ provider-qualified required authority
→ capability graph
→ exposure differential
→ least-privilege contract
→ runtime identity/scope/capability enforcement
→ observed-versus-authorized flow comparison
→ cross-provider path containment
→ tamper-evident evidence
```

The FastAPI API and local dashboard are presentation boundaries. The authoritative logic resides in `app/providers`, `app/planner`, `app/gateway`, and `app/evidence`; the browser does not reproduce policy logic.

## Architecture and trust boundaries

Requests and static fixture definitions are untrusted inputs. Pydantic schemas validate identifiers, scopes, capabilities, flow references, and closed expectation fields. `ProviderRegistry` distinguishes adapter IDs from canonical authority IDs. The normalized local catalogues and intent catalogue are trusted PoC configuration. Contracts are process-local stored objects returned as defensive copies. Evidence is a local append-only JSON Lines file protected by an in-process lock. The dashboard receives backend decisions through same-origin APIs.

## Core data structures

- `ProviderMetadata` separates adapter identity, canonical authority, aliases, and simulation status.
- `GrantIdentity`, scope-node attributes, and capability-node attributes preserve provider, principal, grant, scope, capability, and source scope provenance.
- Analysis schemas carry required, matched, excessive, missing, available, and missing-capability facts.
- `CapabilityContract` binds canonical provider, principal, source grants, selected scopes, allowed capabilities, expiry, state, fingerprint, and source evidence.
- `ScenarioDataFlowLink` represents an observed/possible flow; `AuthorizedFlow` represents an exact allowed flow declaration. They are deliberately separate.
- `EvidenceRecord` links hashes of the redacted request, result, decision, and previous record.

## Intent, graph, exposure, and synthesis

`map_provider_intents` selects only mappings for the canonical provider. Unsupported provider/intent combinations require manual review. `build_capability_graph` creates deterministic provider-qualified scope and capability nodes. `calculate_exposure_differential` reports authority relative to intent. `synthesize_least_privilege` exhaustively evaluates the small catalogue and orders valid candidates by total risk, unnecessary capabilities, scope count, and alphabetical tie-break. It recommends authority; it never revokes real provider permissions.

## Runtime enforcement and drift

Contract creation reuses analysis and synthesis, accepts only complete coverage, and derives authority from selected scopes. `evaluate_capability_attempt` checks unknown or terminal contract state, provider, principal, grant, observed-scope drift or absence, then capability authorization. Extra scope causes quarantine; missing scope and unauthorized capability cause block. Once quarantined, a contract remains quarantined. This is simulated enforcement with no real tokens.

## Composition and provider qualification

`analyze_provider_qualified_composition` resolves capability sources inside each canonical provider catalogue. An observed cross-provider link is not authorization. A flow is allowed only when source and target provider, principal, grant, capability, and data type exactly match an explicit authorization. Otherwise the path is reported with deterministic remediation and unsafe scenario execution is skipped. The original Google-compatible composition behavior remains supported without using Drive/Gmail names as the generic decision rule.

## Fail-closed processing

Unknown providers, unknown intent, malformed fixture references, wrong-provider collisions, identity mismatch, unexpected scope, missing required authority, unsupported capability, malformed decisions, and unauthorized flows never default to allow. The PoC may return manual review, incomplete, block, quarantine, or skipped/risk-detected outcomes depending on the processing stage.

## Tamper-evident evidence

Canonical UTF-8 JSON recursively sorts object keys and preserves list order. Sensitive field names are recursively redacted before SHA-256 hashing. Each record includes the previous hash; verification checks JSON parsing, sequence continuity, genesis, previous hash, and recomputed record hash. This provides tamper evidence, not tamper-proof storage or nonrepudiation. It does not use distributed locking.

## Dashboard and explainability

`/demo` uses local semantic HTML, CSS, and JavaScript, same-origin relative fetches, safe DOM methods, and a restrictive CSP. It visualizes backend-supplied scope differences, capabilities, composition paths, timelines, decisions, and evidence status. Unknown or malformed decisions render as unsafe/unrecognized.

## Detailed processing workflow

1. Resolve adapter alias to canonical authority; validate request or immutable fixture.
2. Normalize intents and map them within the canonical provider.
3. Resolve granted scopes through that provider's catalogue and build provenance-bearing graph nodes.
4. calculate required, matched, excessive, missing, and capability exposure.
5. Synthesize an exact deterministic least-privilege scope set.
6. If complete, create separate contracts for each provider/grant authority boundary.
7. Compare runtime identity and observed scopes with stored bindings before capability authorization.
8. Compare observed composition paths with exact authorized-flow declarations.
9. Redact and append successful analyses and decisions to the evidence chain.
10. Return proof-oriented facts to APIs and the local dashboard.

## Demonstrated scenarios

The original five scenarios demonstrate exact file reading, excessive Gmail read authority, runtime scope drift, composed file-to-email exfiltration, and missing send permission. Nine provider-generalization scenarios demonstrate enterprise exact/excessive/drift cases, code-host exact/excessive cases, wrong-provider scope and capability-name collisions, an exactly authorized cross-provider workflow, and unauthorized enterprise-file-to-webhook exfiltration. All use synthetic local data; `mock-google`, `mock-enterprise`, and `mock-code-host` are not commercial-provider integrations.

## Experimental method and observed results

V1 contains 24 author-defined cases. V2 freezes those cases and adds 12 provider-qualified cases for 36 total. Positive means unsafe and requires containment for a true positive. The captured V2 report records ScopeSentry-R at 25 TP, 11 TN, 0 FP, and 0 FN; the static baseline records 7 TP, 11 TN, 0 FP, and 18 FN. These are observations on a threat-heavy, author-defined corpus, not statistical or formal security proof. Ground truth remains pending independent human review. Timing is local PoC measurement and not a production guarantee.

## Technical effects

On the declared corpus, the combination preserves exact safe access while exposing or containing excessive authority, drift, capability mismatch, provider collisions, and unauthorized composition that required-scope coverage alone does not model. Provider qualification prevents text-name collisions from merging authority. Evidence links the inputs and decisions used in each successful operation.

## Candidate Technical Claim Elements — For IPR/Patent-Attorney Review

Potential technical elements for professional review include intent-conditioned provider capability modelling; provider-qualified authority identities; exposure differential calculation; deterministic least-privilege contract synthesis; runtime authority-drift detection; observed-versus-authorized flow comparison; cross-provider composition path detection; contract-bound capability enforcement; and evidence-linked security decisions. These are not final legal claims and this document makes no conclusion about novelty, inventive step, patentability, freedom to operate, or legal scope.

## Alternative embodiments

Possible future embodiments could use persistent contract storage, real provider adapters, independently maintained semantic catalogues, authenticated callers, distributed evidence coordination, hardware-backed signing, streamed runtime observations, or a more scalable exact/constraint optimizer. These alternatives are not implemented.

## Known limitations and future directions

The current system has synthetic catalogues, author-defined ground truth, process-local contracts, unauthenticated contract identifiers, declared rather than externally observed flows, local file evidence, in-process locking, and no resilience or load validation. It has no real OAuth, provider SDK, database, authentication, distributed lock, external telemetry, or provider revocation. Future work should start with independent ground-truth review, then real-provider semantic validation in an isolated test environment, authenticated persistent contracts, multi-process evidence design, and adversarial/load evaluation.
