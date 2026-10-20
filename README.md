# ScopeSentry-R

ScopeSentry-R is an intent-conditioned OAuth exposure analysis and runtime
enforcement proof of concept. It maps declared user intent to capabilities,
builds proof-oriented capability graphs, synthesizes least-privilege scopes,
creates temporary intent-locked contracts, evaluates runtime actions, and
records decisions in a tamper-evident hash chain.

## Run the API

From `C:\scopesentry`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open Swagger at <http://127.0.0.1:8000/docs>. The **Demo Scenarios** section
lists and runs the complete demonstrations without external accounts.

## Explainable security dashboard

Open <http://127.0.0.1:8000/demo> after starting the API. The local dashboard
shows the complete ScopeSentry-R workflow from declared intent and granted
scope exposure through least-privilege synthesis, runtime enforcement, and
tamper-evident evidence verification.

Use **Run Scenario** on an individual card to execute one deterministic
scenario. Use **Run All Scenarios** to execute all scenarios in the backend-provided
order. Run-all is sequential so its progress and evidence records remain easy
to follow; a failed request is displayed as an execution error and is never
treated as an allowed result.

The dashboard uses same-origin API calls and local HTML, CSS, and JavaScript.
It loads no CDN, external font, analytics, tracking script, or provider API.
Dynamic values are rendered with safe DOM methods, the dashboard document has
a restrictive Content Security Policy, and unknown decisions are displayed as
unsafe rather than allowed. No OAuth credentials are required or accepted.

## Credential-free simulator

The `mock-google`, `mock-enterprise`, and `mock-code-host` adapters are
deterministic, credential-free simulators. `mock-google` is an explicit adapter
alias for the canonical `google` authority namespace; the other two names are
canonical synthetic namespaces. Their scopes are internal normalized aliases
backed by immutable local catalogues. They are not real provider integrations,
contact no external service, and require no
account, client ID, client secret, authorization code, or OAuth token.

## Demo scenarios

- **Safe file reader** — correctly scoped Drive reading is allowed.
- **Overprivileged file reader** — unnecessary Gmail reading is removed and
  the runtime mismatch is blocked or quarantined.
- **Runtime scope drift** — unexpected Gmail send authority quarantines the
  contract.
- **Composed exfiltration path** — separate Drive-read and email-send grants
  create an unauthorized data path with explicit remediation.
- **Missing required permission** — Gmail sending is recommended but an
  active contract is not issued until the permission is actually present.

List scenarios:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/demo/scenarios
```

Run one scenario:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/demo/scenarios/safe-file-reader/run
```

The response contains a chronological timeline covering discovery, intent,
analysis, graph construction, exposure, synthesis, optional composition,
contract enforcement, runtime decisions, and evidence-chain verification.

## Backend Quality Gate

Demo expectations use a closed, strongly typed schema that rejects unknown
keys and incorrect value types. Scenario fixtures are validated atomically:
grant and data-flow IDs must be nonempty and unique, runtime and link
references must belong to the scenario and mock catalogue, links cannot point
to themselves, and static scopes and capabilities must exist in the catalogue.
Invalid fixture configuration is rejected before any scenario can execute.

Public scope inputs accept normalized aliases and well-formed provider or URL
scope formats. Empty, whitespace-only, control-containing, and malformed scope
values are rejected. Well-formed unknown public scopes remain untrusted and
are handled fail-closed as excess authority. Public duplicate scopes continue
to be normalized for compatibility; duplicates in immutable fixtures are
configuration errors.

The scenario-run endpoint accepts only an empty request body. Any nonempty
body, including `{}` or whitespace, returns HTTP 400. Timeline status values
are exposed as an OpenAPI enum. The similar legacy values `complete` and
`completed` are both retained to preserve response compatibility.

Analysis and demo responses report sorted `missing_capabilities` derived from
the capability graph. Unexpected scopes quarantine contracts, missing scopes
cannot create an executable demo contract, and unauthorized capabilities are
blocked. Validation failures never default to an allow decision or partial
scenario execution.

Run the complete quality gate with:

```powershell
python -m pytest -q
```

## Reproducible security evaluation

Phase 4 provides a CLI-only, deterministic comparison between ScopeSentry-R
and a conventional provider-aware static OAuth scope checker. The static
baseline permits an intent when each required scope is present or is covered
by a catalogue-defined broader scope. It deliberately does not perform
exposure analysis, least-privilege synthesis, runtime enforcement, scope-drift
detection, composition-path analysis, or evidence generation.

The immutable local corpus contains 24 hand-authored cases: 8 safe and 16
unsafe. Ground truth is declared with each case before either system runs and
is included in a stable canonical corpus hash. The corpus covers exact access,
multiple intents, excessive and unknown authority, missing permissions,
runtime drift, capability mismatch, contract blocking/quarantine, and safe and
unsafe multi-grant composition. It is intentionally threat-heavy and is not a
statistically representative sample of all OAuth deployments.

Run the reproducible evaluation from the project root:

```powershell
python -m app.evaluation.runner --iterations 50 --warmups 5 --output-dir reports\evaluation
```

The command writes:

- `reports/evaluation/scope_sentry_evaluation.json`
- `reports/evaluation/scope_sentry_evaluation.csv`
- `reports/evaluation/scope_sentry_evaluation.md`

Positive means an unsafe case. A true positive requires effective containment,
not merely risk detection; a false negative is unsafe authority that reaches
execution. Reports include raw TP/TN/FP/FN counts, false-allow and false-block
rates, safe-case allow and unsafe-case prevention rates, per-category results,
scope-count exposure reduction, composition and drift results, and local
median/p95/min/max timing observations. Every rate includes its numerator and
denominator, and zero-denominator rates are reported as not applicable.

Correctness evidence is written to a temporary isolated hash chain and verified
before the run succeeds. The normal evidence file is hashed before and after
evaluation (or confirmed to remain absent), while repeated timing iterations
perform no evidence writes. Generated measurements use only the local mock
catalogue, require no network or OAuth credentials, are not production
performance guarantees, and are not a formal security or patentability proof.

## Provider-agnostic security validation

Phase 5 separates the adapter implementation ID from the canonical authority
provider ID. Provider, principal, and grant identity travel with scope and
capability provenance. Contracts stay inside one provider/grant boundary, and
runtime identity mismatches are blocked before scope or capability checks.
The same scope or capability text in two provider catalogues never shares
authority.

The dashboard displays provider badges, qualified grants and capabilities,
and cross-provider flow warnings using backend-supplied data. Observed links
are not authorizations: an allowed cross-provider flow must exactly match a
separate authorization across source and target provider, principal, grant,
capability, and data type. No wildcard flow authorization is supported.

The V2 evaluation reuses the Phase 4 engine and its frozen 24-case corpus, then
adds 12 provider-qualified cases for a total of 36. It writes separate output
files and records hashes of the existing Phase 4 reports before and after the
run:

```powershell
python -m app.evaluation.runner_v2 --iterations 50 --warmups 5 --output-dir reports\evaluation
```

Generated V2 reports are:

- `reports/evaluation/scope_sentry_evaluation_v2.json`
- `reports/evaluation/scope_sentry_evaluation_v2.csv`
- `reports/evaluation/scope_sentry_evaluation_v2.md`

Evaluation evidence uses a temporary isolated JSONL chain; performance loops
do not write evidence. The normal evidence log and existing Phase 4 reports
are not modified. The corpus remains author-defined until a human completes
`docs/evaluation-ground-truth-review.md`.

## Phase 6 — IPR technical disclosure and release verification

Documentation index:

- `docs/ipr/ScopeSentry-R-Technical-Disclosure.md`
- `docs/ipr/Architecture-and-Data-Flow.md`
- `docs/ipr/Threat-Model.md`
- `docs/ipr/Novelty-Traceability-Matrix.md`
- `docs/ipr/Experimental-Methodology.md`
- `docs/ipr/Demo-Runbook.md`
- `docs/ipr/Reproducibility-Guide.md`
- `docs/ipr/traceability.json` (machine-readable source)

Run the read-only verifier from the repository root:

```powershell
python -m app.release.verify --output-dir reports\release
```

It writes only JSON and Markdown manifests in the selected output directory.
`ready_for_local_ipr_demo` means required local technical checks passed; it
does not mean production readiness, formal verification, patentability,
real-provider compatibility, or independent validation. Ground truth remains
author-defined until the blank review record is completed. The verifier reads
but does not modify normal evidence, contracts, scenarios, evaluation state,
source, or frozen reports.

## Phase 7 — Final IPR Cell submission package

The canonical tracked submission begins at
`docs/ipr/submission/00-Submission-Index.md`. Its invention disclosure,
qualified claim concepts, reviewed diagrams, demo guide, human-review
checklist, and blank prior-art worksheet consolidate the Phase 6 annexes
without changing the security implementation or frozen reports.

`docs/ipr/traceability.json` is the schema-version 1.1 machine-readable source
for candidate-element status, claim suitability, exact source symbols and
tests, scenario support, frozen-report references, checked metric JSON paths,
evidence events, qualifications, and limitations. The Markdown traceability
matrix is its generated human-readable projection.

The verified Phase 6 baseline was 255 passing tests. After the Phase 7
documentation, traceability, and cross-platform frozen-report tests were added,
the complete Phase 7 suite is 279 passing tests with one existing deprecation
warning. The two counts describe different verification milestones.
The release verifier also validates the Phase 7 package and traceability references:

```powershell
python -m app.release.verify --output-dir reports\release
```

Candidate claim material is only technical concepts for professional
patent-counsel/IPR review. No repository document establishes novelty,
patentability, production readiness, formal verification, real-provider
compatibility, universal prevention, or independent validation.
