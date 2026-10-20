# ScopeSentry-R Invention Disclosure

## Abstract

ScopeSentry-R is a credential-free local proof of concept for relating declared user intent to provider-qualified authorization authority. It maps normalized intent to required scopes and capabilities, constructs capability representations with provider/principal/grant provenance, calculates an exposure differential, and selects an exact least-privilege scope combination within a configured finite local catalogue and risk model. The selected authority is bound to process-local capability contracts. A simulator evaluates supplied runtime observations against those stored contracts and returns allow, block, or quarantine decisions. Separately declared observed data flows are compared with narrowly defined authorized-flow declarations; unmatched paths are detected and skipped by the demonstration orchestrator with a remediation recommendation. Successful analyses and security decisions are linked through redacted, canonical, tamper-evident evidence records under documented local-storage assumptions. The implementation is demonstrated on an author-defined deterministic local corpus and does not use real OAuth credentials or commercial-provider APIs.

## Technical field

The work concerns computer authorization analysis, OAuth-style scope modelling, least-privilege planning, capability-based policy decisions, cross-grant and cross-provider composition analysis, and tamper-evident security-decision evidence.

## Background

A conventional static scope check determines whether granted scopes cover scopes required for a selected action. That check is useful but does not necessarily identify unrelated granted authority, construct a reduced execution contract, compare later observations with the original intent boundary, distinguish same-name authority across providers and principals, or evaluate a data path formed by composing separately granted capabilities.

ScopeSentry-R preserves required-scope checking while adding an intent-conditioned and provider-qualified analysis pipeline. The current implementation uses only synthetic local providers and normalized internal aliases. It is not a real-provider integration.

## Problem statement

An application may receive authority that is individually valid yet broader than the user's stated action. Separately valid grants may also form a data path that was not authorized by intent. At runtime, observed identity or scope state may differ from the contract created at analysis time. A technical mechanism is needed to:

1. preserve provider, principal, and grant provenance;
2. express required authority from intent;
3. identify matched, excessive, and missing exposure;
4. synthesize a bounded least-privilege contract;
5. evaluate supplied runtime observations against the stored boundary;
6. distinguish observed flows from expressly authorized flows; and
7. produce verifiable decision evidence without recording credentials.

## Objectives

- Normalize supported intent without inheriting another provider's mapping.
- Model scopes and capabilities with qualified authority provenance.
- Fail closed on unknown intent, provider, scope authority, identity mismatch, missing authority, drift, or unauthorized flow.
- Select the safest supported scope combination deterministically.
- Keep unrelated provider/grant contracts isolated.
- Evaluate runtime authority in a deterministic rule order.
- Detect an observed, unauthorized compositional path and recommend remediation.
- Link redacted request, result, and decision hashes in a verifiable chain.
- Explain decisions through local APIs and a safe same-origin dashboard.

## Definitions

- **Adapter ID:** provider-simulator implementation identifier, such as `mock-google`.
- **Canonical authority provider ID:** normalized security namespace, such as `google`.
- **Complete grant identity:** canonical provider, principal, and grant ID.
- **Capability:** normalized action enabled by one or more catalogue scopes.
- **Exposure differential:** matched, excessive, and missing scope/capability authority relative to declared intent.
- **Capability contract:** process-local, expiring binding of identity, selected scopes, and allowed capabilities.
- **Observed flow:** a declared possible data movement; its presence does not grant authorization.
- **Authorized flow:** an exact declaration of allowed source and target identity, capability, and data type.
- **Containment:** simulated prevention through block, quarantine, incomplete contract, or orchestrator skip.
- **Evidence chain:** JSON Lines records linked by SHA-256 hashes after recursive redaction and canonical serialization.

## Trust and authority model

API inputs and runtime observations are untrusted. Pydantic schemas validate their shape and safe identifiers. Well-formed unknown public scopes remain untrusted rather than becoming authority. Immutable local catalogues, intent mappings, and scenario fixtures are trusted PoC configuration and are author-defined.

The process and its filesystem access controls are trusted. Contracts are held in a thread-safe, process-local repository and disappear on restart. The evidence service uses an in-process per-path lock; it does not provide distributed locking, trusted time, signing, immutable storage, or external anchoring.

## Architecture

The implemented pipeline is:

```text
intent
→ provider-qualified required authority
→ capability graph and exposure differential
→ bounded least-privilege synthesis
→ isolated process-local contract
→ runtime capability-decision enforcement in the simulator
→ observed-versus-authorized flow comparison
→ simulated containment and remediation recommendation
→ tamper-evident decision evidence
```

Implementation references: `app/providers`, `app/planner`, `app/gateway`, `app/evidence`, and `app/orchestrator/demo_runner.py`. Figures are in `03-Submission-Diagrams.md`.

## Provider-qualified identity model

`ProviderRegistry` resolves controlled aliases to a canonical authority provider and rejects duplicate adapter IDs, canonical IDs, and ambiguous aliases. Internally, `GrantIdentity`, `ScopeIdentity`, and `CapabilityIdentity` retain canonical provider, principal, grant, scope, capability, and source-scope attributes. Deterministic string node IDs are serialized from structured identities, but structured attributes remain authoritative.

This prevents identical strings such as `content.read` or `read_profile` from merging authority across providers or principals.

## Intent-to-authority mapping

`map_provider_intents` selects requirements only from the canonical provider's intent catalogue. Unsupported provider/intent combinations are returned for manual review and cannot silently inherit Google-compatible mappings. Mapped scopes are resolved through the same provider's authoritative local capability catalogue.

## Capability graph

`build_capability_graph` constructs a NetworkX directed graph for single-provider analysis, with scope nodes, capability nodes, and `ENABLES` edges. Nodes contain classification and provider attributes. Provider-qualified composition constructs an equivalent deterministic serializable graph retaining provider/principal/grant provenance and adds `OBSERVED_FLOW` edges only for explicitly declared observed links. No implicit cross-provider edge is created.

## Exposure differential

`calculate_exposure_differential` and graph-derived analysis report required, matched, excessive, and missing authority. Unknown scopes enable no trusted capability. Missing capabilities are derived from the same mapping and catalogue rather than a scenario-specific rule.

The differential describes modelled exposure; it does not prove exploitability or complete security.

## Bounded least-privilege synthesis

`synthesize_least_privilege` exhaustively evaluates supported scope subsets in the small local catalogue. A candidate must cover every required capability. Candidates are ordered by:

1. total configured risk weight;
2. number of unnecessary capabilities;
3. number of selected scopes; and
4. alphabetical tie-break.

The result is exact within the configured finite local catalogue and risk model. Risk weights and mappings are author-defined PoC configuration. An unknown intent returns manual review; an uncovered requirement returns incomplete. The module recommends authority and never revokes provider permissions.

## Contract generation and isolation

A contract is created only for a supported provider, recognized intent, complete least-privilege plan, and covered required capabilities. Selected scopes come from synthesis, not directly from the grant. Allowed capabilities are resolved from those selected scopes.

Contracts bind canonical provider, principal, source grant IDs, selected scopes, allowed capabilities, fingerprint, source evidence, creation time, expiry, and state. Multi-provider demonstrations create separate contracts at provider/grant authority boundaries; no global cross-provider contract is created.

## Runtime decision ordering

Runtime capability-decision enforcement within the credential-free simulator evaluates supplied runtime observations against a stored contract. The effective order is:

1. unknown contract at the service boundary;
2. revoked, quarantined, or expired state;
3. provider mismatch;
4. principal mismatch;
5. grant mismatch;
6. unexpected observed scope, causing quarantine;
7. missing contract scope, causing block;
8. capability outside the contract, causing block;
9. capability not enabled by observed scopes, causing block; and
10. allow only when the capability is both allowed and enabled.

Omitted additive identity fields do not widen stored authority. This is a simulated decision service and does not intercept a real provider operation or collect autonomous provider telemetry.

## Observed-versus-authorized flow analysis

`analyze_provider_qualified_composition` treats every declared observed flow as possible data movement, not permission. Authorization requires an exact match across source provider, principal, grant, capability, data type, target provider, principal, grant, and capability. Wildcard authorization is not implemented. Any component mismatch leaves the path unauthorized.

## Cross-provider composition analysis

The composition engine resolves both endpoints in their own catalogues, checks that the stated capabilities are enabled by their grants, and emits provider-qualified nodes, edges, observed paths, unauthorized paths, and deterministic remediation recommendations.

An unauthorized path is detected and skipped by the demonstration orchestrator. The current FastAPI analysis interface reports analysis; it does not break a real data path, revoke provider authority, or automatically remediate an external system.

## Tamper-evident evidence

Before hashing, recursively named sensitive fields are replaced with `[REDACTED]`. Canonical UTF-8 JSON sorts dictionary keys, preserves list order, uses compact separators, and rejects unsupported values. Each record contains request, result, decision, and previous-record hashes. The first record uses a 64-zero genesis hash. Verification checks JSON parsing, continuous sequence, genesis, predecessor linkage, and recomputed record hashes.

The file follows append-only behavior under normal service operation and is flushed and synchronized after writes. It is tamper-evident under the documented storage assumptions, not tamper-proof, signed, externally anchored, or safe for concurrent multi-process writers.

## Explainability

The FastAPI responses and `/demo` dashboard display backend-supplied scope differential, capabilities, contract state, runtime decision, composition paths, timeline, recommendation, and evidence status. The frontend uses same-origin local assets, safe DOM APIs, and a restrictive Content Security Policy. It does not calculate authorization independently.

## End-to-end workflow

1. Validate provider and request or immutable fixture.
2. Normalize intent and obtain provider-qualified requirements.
3. Resolve scopes and construct capability provenance.
4. Calculate exposure and missing authority.
5. Synthesize a bounded least-privilege plan.
6. Create isolated contracts only when complete and safe.
7. Compare declared observed flows with exact authorized-flow declarations.
8. Evaluate supplied runtime identity, scope, and capability observations.
9. Return a simulated security decision and explanation.
10. Append redacted tamper-evident evidence for successful analyses and runtime decisions.

## Implemented scenarios

Fourteen deterministic scenarios cover exact safe access, excessive authority, missing permission, runtime scope drift, unauthorized capability, legacy composed exfiltration, enterprise and code-host provider semantics, same-name scope/capability collisions, an exactly authorized cross-provider workflow, and unauthorized enterprise-content-to-webhook flow.

All providers are synthetic local simulators. Scenario fixtures contain no credentials and do not contact commercial services.

## Experimental methodology and results

The Phase 4 / V1 / legacy corpus contains 24 author-defined cases: 8 safe and 16 unsafe. The Phase 5 / V2 / provider-qualified corpus preserves V1 and adds 12 cases, yielding 36 total: 11 safe and 25 unsafe. The static baseline performs provider-aware required-scope coverage but does not synthesize contracts or model runtime drift and composition paths.

On the frozen V2 report:

| System | TP | TN | FP | FN | Unsafe prevention | Safe allow rate |
|---|---:|---:|---:|---:|---:|---:|
| Static scope baseline | 7 | 11 | 0 | 18 | 28.00% (7/25) | 100.00% (11/11) |
| ScopeSentry-R | 25 | 11 | 0 | 0 | 100.00% (25/25) | 100.00% (11/11) |

Authority was reduced in 16 of 36 V2 cases. Mean scope-count exposure reduction was approximately 0.3519; median was 0.0 and maximum was 1.0. Scope count is one exposure indicator, not a complete security measure.

These are results demonstrated on an author-defined deterministic local corpus. The corpus is threat-heavy, not statistically representative, and pending independent review. Local timings exclude evidence, report, HTTP, UUID, and cleanup costs and are not production performance guarantees.

## Technical effects

Within the implemented local model, the combined pipeline:

- preserves authority provenance across provider, principal, and grant boundaries;
- identifies unnecessary and missing authority relative to intent;
- deterministically reduces executable authority when a narrower supported combination exists;
- prevents supplied identity or scope drift from becoming an allow decision;
- distinguishes observed data movement from explicit authorization;
- detects provider-qualified unauthorized composition paths;
- preserves safe exact-authority cases in the declared corpus; and
- links decisions to redacted, verifiable evidence records.

## Qualified novelty comparison

The comparison is technical characterization, not a prior-art conclusion.

| Capability | Static scope coverage baseline | ScopeSentry-R implementation | Qualification |
|---|---|---|---|
| Required-scope coverage | Yes | Yes | Provider-aware local catalogues |
| Excess-authority differential | No | Yes | Relative to declared intent and local catalogue |
| Bounded least-privilege synthesis | No | Yes | Exact only in the finite configured model |
| Provider/principal/grant provenance | Limited | Yes | Synthetic providers validated |
| Runtime scope/capability decision | No | Yes | Supplied observations; simulated enforcement |
| Observed-versus-authorized flow comparison | No | Yes | Declared flows; exact tuple match |
| Unauthorized-path response | No | Yes | Recommendation and orchestrator skip, not real revocation |
| Tamper-evident decision chain | No | Yes | Local file and in-process lock assumptions |

## Candidate claim concepts

Candidate material is provided in `02-Novelty-and-Claim-Concepts.md`. It consists only of technical concepts for professional patent-counsel/IPR review, not finalized legal claims or a conclusion that any concept is novel or patentable.

## Alternative embodiments

Conceptual future embodiments could use real-provider adapters, persistent authenticated contracts, a provider telemetry collector, distributed or hardware-backed evidence storage, signed timestamps, real enforcement proxies, provider revocation, independently maintained semantic catalogues, and scalable constraint optimization. None of these embodiments is implemented or experimentally validated here.

## Limitations

- Synthetic providers and author-defined mappings/risk weights only.
- Author-defined ground truth pending independent review.
- Process-local, unauthenticated contracts lost on restart.
- Supplied runtime observations rather than autonomous monitoring.
- Declared flows rather than observed external telemetry.
- Decision and demonstration containment rather than real operation interception.
- Remediation recommendation rather than automatic provider revocation.
- File-backed, unsigned evidence with in-process locking only.
- No database, distributed deployment, resilience, load, or adversarial host testing.
- No prior-art search or legal patentability conclusion in the software repository.

## Reproducibility

From an activated Python 3.12 project environment:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m pytest -q -p no:cacheprovider --basetemp .test-tmp\pytest-full
python -m app.release.verify --output-dir reports\release
```

The verified Phase 6 baseline, and therefore the Phase 7 starting baseline, was 255 passing tests with one existing TestClient deprecation warning. After the Phase 7 documentation, traceability, and cross-platform frozen-report tests were added, the complete Phase 7 suite is 279 passing tests with that same warning. Frozen evaluation reproduction commands are documented in `docs/ipr/Experimental-Methodology.md`; rerunning them changes timing and timestamp metadata and is not part of release verification.

## Traceability

`docs/ipr/traceability.json` is the canonical machine-readable mapping from candidate element to source symbols, schemas, exact tests, scenarios, frozen evaluation support, metrics, evidence events, qualifications, and limitations. `docs/ipr/Novelty-Traceability-Matrix.md` is its generated human-readable projection.

## Review status

This disclosure does not establish patentability, novelty, inventive step, freedom to operate, formal verification, production readiness, or independent validation.

- Implementation status: local proof of concept complete for the traced features.
- Release verification: `ready_for_local_ipr_demo` at the Phase 7 starting commit.
- Ground truth: author-defined; independent review pending.
- Prior art: professional search pending.
- Patentability and legal claims: professional patent-counsel/IPR review pending.
- Inventor/faculty approval: pending completion of `05-Inventor-Faculty-Review-Checklist.md`.
