# ScopeSentry-R Threat Model

## Scope, protected assets, and assumptions

Protected assets are intent-to-authority bindings, provider/principal/grant provenance, least-privilege contract integrity, runtime decision integrity, observed-flow classification, and evidence-chain continuity. Entry points are FastAPI request bodies, path/query parameters, static fixture loading, dashboard responses, local evidence storage, and release/evaluation CLI arguments.

The adversary may submit malformed or excessive scope sets, attempt an unauthorized capability, present mismatched runtime identity, cause scope drift, compose grants into a data path, tamper with evidence bytes, or place unsafe strings in rendered data. The PoC assumes its process, normalized catalogues, Python environment, and local filesystem access controls are trusted. It does not assume that an observed flow is authorized.

## Trust boundaries

1. Client/dashboard to FastAPI validation.
2. Validated identifiers to canonical provider catalogues.
3. Analysis result to process-local contract repository.
4. Runtime observation to stored contract binding.
5. Decision objects to redaction and evidence storage.
6. Backend JSON to safe dashboard DOM rendering.

## STRIDE-style analysis

| Threat / class | Current status | Implemented mitigation | Supporting test or scenario | Residual risk |
|---|---|---|---|---|
| Excessive OAuth scope / Elevation | Mitigated in PoC analysis | Exposure differential and deterministic least-privilege synthesis exclude unrelated authority | `overprivileged-file-reader`; `test_remove_excessive_scope` | No real-provider revocation occurs |
| Missing permission / Denial | Mitigated | Incomplete plan prevents active executable contract | `missing-required-permission`; `test_complete_plan_is_required` | Provider semantics are synthetic |
| Runtime scope drift / Elevation | Mitigated | Unexpected observed scope quarantines stored contract | `runtime-scope-drift`; `enterprise-runtime-drift` | Observation is supplied by simulator/client boundary |
| Capability mismatch / Elevation | Mitigated | Allowed capability and observed-scope enablement are checked after identity | `test_unauthorized_capability_returns_block` | No real resource-side enforcement |
| Wrong-provider name collision / Spoofing | Mitigated | Canonical provider-qualified identities and catalogue-local resolution | `wrong-provider-scope-collision` | Real aliases and provider changes are not modeled |
| Wrong principal or grant / Spoofing | Mitigated | Stored binding precedes scope/capability authorization | `test_runtime_identity_mismatches_fail_closed_before_authority_checks` | Caller itself is not authenticated |
| Contract replay or ID theft / Spoofing | Not implemented / future work | Expiry, revoke, and quarantine limit state, but no caller authentication exists | Expiry/revoke gateway tests | A stolen active contract ID can be replayed locally |
| Cross-provider exfiltration / Information disclosure | Mitigated for declared flows | Observed flow requires exact separate authorization; otherwise path is contained/skipped | `unauthorized-cross-provider-exfiltration` | Flow discovery is not integrated with real telemetry |
| Evidence content tampering / Tampering | Detected | Canonical hash chain verifies sequence, genesis, prior hash, and record hash | evidence modification/deletion/reorder tests | Storage is tamper-evident, not immutable or signed |
| Malformed fixture references / Tampering | Mitigated | Atomic model/reference validation occurs before registry exposure | Phase 2 fixture validation tests | A malicious code maintainer can change trusted catalogue source |
| Unknown provider / Spoofing | Mitigated | Registry lookup is controlled and never falls back to Google | provider registry tests | Catalogue authenticity is not externally attested |
| Dashboard injection / Information disclosure | Mitigated for current renderer | `textContent`/safe DOM, local assets, CSP, no external dependencies | dashboard source/security-header tests | Browser and dependency vulnerabilities remain possible |
| Denial of service | Detected but operationally out of scope | Bounded list inputs/limits and schema validation reduce obvious abuse | API validation tests | No authentication, rate limit, quotas, or capacity engineering |
| Concurrent evidence writes / Tampering | Partially mitigated | Per-path in-process lock, flush, and `fsync` | evidence concurrency-safe append design | Multiple processes have no shared file lock |
| Process restart / Availability | Not implemented / future work | None for contracts; evidence remains file-backed | repository documentation | Process-local contracts are lost on restart |
| Real-provider semantic drift / Tampering | Not implemented / future work | Synthetic catalogue validation only | catalogue validation tests | No real provider metadata refresh or semantic verification |

## Abuse-case decision ordering

Runtime handling is fail-closed in this order: unknown contract; revoked/quarantined/expired contract; provider mismatch; principal mismatch; grant mismatch; missing/unexpected scopes; capability authorization. Unknown or malformed outcomes are not converted to allow. Cross-provider links are unauthorized by default unless every authorization component matches.

## Evidence and repudiation limits

The evidence chain records hashes and redacted decision summaries, supporting detection of later byte modification. It does not authenticate the human/operator, establish trusted time, sign records, prevent deletion of the entire log, or provide external anchoring. Those are residual repudiation and tampering risks.

## Out of scope

Real OAuth protocols, token custody, commercial-provider integration, distributed deployment, network adversaries, authentication/authorization of API callers, persistent contract storage, operational revocation, malware on the host, formal verification, and comprehensive vulnerability audit are out of scope.
