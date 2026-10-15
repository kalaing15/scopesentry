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
scenario. Use **Run All Scenarios** to execute all five in the backend-provided
order. Run-all is sequential so its progress and evidence records remain easy
to follow; a failed request is displayed as an execution error and is never
treated as an allowed result.

The dashboard uses same-origin API calls and local HTML, CSS, and JavaScript.
It loads no CDN, external font, analytics, tracking script, or provider API.
Dynamic values are rendered with safe DOM methods, the dashboard document has
a restrictive Content Security Policy, and unknown decisions are displayed as
unsafe rather than allowed. No OAuth credentials are required or accepted.

## Credential-free simulator

The current `mock-google` provider is a deterministic, credential-free
simulator. Its scope names are internal normalized aliases backed by the mock
catalogue. It is not Google OAuth, does not contact Google, and requires no
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
