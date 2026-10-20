# ScopeSentry-R Novelty Context and Claim Concepts

## Review status

This document contains **technical concepts for professional patent-counsel/IPR review**. It does not contain finalized legal claims and does not establish novelty, inventive step, patentability, or freedom to operate. Prior-art searching and professional claim drafting remain pending.

Ground truth status: **author-defined; independent review pending**.

## Qualified comparison

The comparison below is limited to the conventional static scope-checking baseline implemented in `app/evaluation/baseline.py` and evaluated by the frozen V1 and V2 reports. It is not a comparison with every commercial or published authorization system.

| Technical behavior | Evaluation static-scope baseline | ScopeSentry-R local PoC |
|---|---|---|
| Provider-aware required-scope coverage | V2 only | Yes |
| Identification of excessive granted scopes | No | Yes |
| Bounded least-privilege scope synthesis | No | Yes |
| Provider/principal/grant-qualified authority | No | Yes |
| Evaluation of supplied runtime observations | No | Yes |
| Identity, scope, and capability contract checks | No | Yes |
| Observed-versus-authorized flow comparison | No | Yes |
| Cross-provider unauthorized-path detection | No | Yes |
| Tamper-evident local evidence records | No | Yes |

“Yes” means implemented and exercised within the configured credential-free simulator. It does not mean real-provider interception, universal attack prevention, or formal verification.

## Candidate combination concept

A candidate technical combination, for professional review, comprises:

1. receiving declared intent and provider-qualified grant authority;
2. mapping the intent to provider-qualified required scopes and capabilities;
3. constructing capability data with provider, principal, grant, scope, and capability provenance;
4. calculating an intent-conditioned exposure differential;
5. selecting, exactly within a configured finite catalogue and risk model, a lower-risk scope subset that covers required capabilities;
6. creating isolated, time-bounded capability contracts per authority boundary;
7. evaluating supplied runtime identity, observed scopes, and attempted capability against the stored contract in a fail-closed order;
8. separately comparing observed data flows with exact authorized-flow declarations; and
9. recording redacted decisions in a canonical hash chain.

The possible inventive significance of this combination, and the breadth supportable by the disclosure, require professional prior-art and legal analysis.

## Candidate dependent concepts

The following are possible narrowing or supporting concepts, not finalized claims:

- deterministic tie-breaking after capability coverage, risk, unnecessary capabilities, and scope count;
- provider-qualified graph nodes retaining structured provenance while using collision-safe deterministic NetworkX identifiers;
- contract identity checks preceding observed-scope and capability authorization;
- quarantine on unexpected observed authority, with no automatic reactivation;
- exact flow authorization matching provider, principal, grant, and capability endpoints without wildcard authorization;
- distinct treatment of observed or possible flow versus intent-authorized flow;
- deterministic remediation recommendations for unauthorized composition paths;
- evidence references that bind analysis IDs and canonical decision records without circular result hashing;
- canonical JSON, recursive secret redaction, sequence continuity, and previous-record hashes;
- explainability that presents backend-derived scope, capability, path, contract, and evidence facts without duplicating policy in the browser.

## Implementation-status boundaries

### Fully implemented in the local PoC

- provider-qualified catalogue and intent lookup for three synthetic authority namespaces;
- exact bounded least-privilege synthesis;
- process-local isolated contracts;
- runtime capability-decision enforcement within the credential-free simulator;
- observed-versus-authorized flow comparison for declared flows;
- tamper-evident JSON Lines evidence under documented storage assumptions;
- deterministic scenario and evaluation tooling using local mock data.

### Partially implemented

- runtime monitoring: observations are supplied to the simulator; no provider telemetry collector exists;
- containment: unsafe demo execution is blocked, quarantined, or skipped within the simulator; no external provider operation is intercepted;
- append-only evidence: normal application behavior appends and verifies a local file, but operating-system administrators can replace or truncate storage and multi-process locking is not implemented;
- remediation: the system produces a recommendation, not automatic real-provider revocation or flow reconfiguration.

### Conceptual future embodiments

- real provider adapters and semantic conformance testing;
- authenticated principals and protected contract identifiers;
- persistent/distributed contract storage;
- provider telemetry ingestion and operation interception;
- durable, access-controlled or externally anchored evidence;
- administrative remediation workflows.

These future embodiments must not be described as current implementation.

## Concepts unsuitable for standalone claiming

The following are established or generic building blocks and should not be presented alone as the invention: SHA-256 hashing, JSON Lines storage, Pydantic validation, NetworkX graph storage, a conventional required-scope inclusion check, a generic dashboard, ordinary REST routing, or enumeration of OAuth scopes. Their relevance here is in the disclosed technical combination and data relationships, subject to professional review.

## Prior-art questions for counsel

- Which publications disclose intent-conditioned reduction from granted OAuth scopes to capability contracts?
- Which systems bind provider, principal, grant, scope, and capability provenance throughout graph and runtime enforcement?
- Which systems distinguish observed cross-provider flows from independently authorized flow declarations?
- Which systems combine deterministic synthesis, runtime drift decisions, cross-grant composition, and evidence-linked explainability?
- Which elements are likely conventional individually, and which combinations may be material?

Use `06-Prior-Art-Review-Worksheet.md` to record sourced findings. Do not convert an absence found in a limited search into a novelty conclusion.
