# ScopeSentry-R Live Technical Demonstration

Target duration: 10–15 minutes. This demonstration uses deterministic local simulators. It requires no OAuth credentials and makes no request to a commercial provider.

## Before the audience arrives

From PowerShell:

```powershell
cd C:\scopesentry
.\tools\demo\start_demo.ps1
```

Wait for the preflight to report `ready_for_local_ipr_demo`, then open:

- Dashboard: `http://127.0.0.1:8000/demo`
- Swagger backup: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`

Keep the PowerShell window visible. Do not reset or delete `runtime/evidence.jsonl`.

## Opening statement, about 45 seconds

“ScopeSentry-R compares declared user intent with provider-qualified OAuth authority. It builds a capability graph, calculates excessive and missing authority, synthesizes a bounded least-privilege plan, evaluates supplied runtime observations against a process-local contract, detects unauthorized composition paths, and links decisions through tamper-evident evidence.”

State the boundaries before running anything:

- Providers are deterministic local simulators.
- Runtime observations are supplied to the gateway.
- Enforcement decisions are simulated.
- Contracts are process-local.
- Evaluation uses an author-defined corpus pending independent review.
- This proof of concept does not claim production readiness or universal security.

## Dashboard orientation, about 45 seconds

Point out the backend-health indicator, provider inventory, scenario cards, result panel, scope differential, capability display, timeline, composition path, plain-language explanation, and evidence status.

Explain that the browser displays backend results. It does not reproduce policy logic in JavaScript.

## Curated scenario sequence

Run each scenario individually in this order. Wait for the timeline and evidence status to finish before continuing.

### 1. Safe least-privilege access

Scenario ID: `safe-file-reader`

Click **Run Scenario** on **Safe file reader**.

Audience should observe:

- Intent: read files.
- Granted and selected scope: `drive.readonly`.
- No excessive or missing scope.
- Drive-reading capability is available.
- A process-local contract is created.
- Runtime decision: `allow`.
- Evidence-chain verification remains valid.

Reason: the provider-qualified authority exactly covers the declared intent and the supplied runtime observation matches the stored contract.

### 2. Excessive authority

Scenario ID: `overprivileged-file-reader`

Click **Run Scenario** on **Overprivileged file reader**.

Audience should observe:

- Intent: read files.
- Granted scopes include `drive.readonly` and unrelated `gmail.readonly`.
- `gmail.readonly` is marked excessive.
- Synthesized scope set contains only `drive.readonly`.
- Gmail-reading authority does not enter the least-privilege contract.
- Runtime decision: `quarantine` because the supplied observation still contains the unexpected Gmail scope.

Reason: email-reading capability is not required by the file-reading intent. Scope possession does not make that authority intent-authorized, and presenting the extra scope at runtime quarantines the contract.

### 3. Runtime scope drift

Scenario ID: `runtime-scope-drift`

Click **Run Scenario** on **Runtime scope drift**.

Audience should observe:

- The initial contract allows Drive reading.
- The supplied runtime observation includes unexpected `gmail.send` authority.
- Runtime decision: `quarantine`.
- Contract state becomes `quarantined`.
- Later requests remain blocked until the contract is replaced.

Reason: the observed authority differs from the contract fingerprint. The gateway fails closed before evaluating the attempted capability as allowed.

### 4. Missing required permission

Scenario ID: `missing-required-permission`

Click **Run Scenario** on **Missing required permission**.

Audience should observe:

- Intent: send email.
- Granted authority contains only Drive reading.
- Required scope `gmail.send` and capability `send_email_messages` are missing.
- The plan recommends adding `gmail.send`.
- No active executable contract is created.
- Runtime execution is skipped rather than presented as allowed.

Reason: a least-privilege recommendation can identify missing authority, but the system cannot safely create a runnable contract until every required capability is covered.

### 5. Unauthorized composed exfiltration

Scenario ID: `composed-exfiltration-path`

Click **Run Scenario** on **Composed exfiltration path**.

Audience should observe:

- One grant can read Drive content and another can send email.
- The provider-qualified capability graph preserves both grant identities.
- An observed file-to-mail path appears in the composition view.
- Unauthorized path count: `1`.
- Unsafe execution is skipped.
- Remediation recommends breaking the observed data-flow link or removing unnecessary email-sending authority.

Reason: individually valid grants can compose into a capability path that the declared intent did not authorize.

### 6. Unauthorized cross-provider flow

Scenario ID: `unauthorized-cross-provider-exfiltration`

Click **Run Scenario** on **Unauthorized cross-provider exfiltration**.

Audience should observe:

- The source and target retain distinct canonical provider, principal, grant, scope, and capability provenance.
- Separate contracts are used; no global cross-provider contract is created.
- An observed enterprise-content-to-code-host-webhook path has no exact matching flow authorization.
- Unauthorized path count: `1`.
- Unsafe execution is skipped or prevented.

Reason: an observed link is not authorization. A permitted cross-provider flow must match every provider, principal, grant, capability, and data-type component.

## Evidence verification, about 45 seconds

Open `http://127.0.0.1:8000/api/v1/evidence/verify` or run:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/evidence/verify
```

Expected result: `valid` is `true`, `first_invalid_sequence` is null, and `records_checked` reflects the current append-only local log. Do not quote a fixed record count.

## Swagger backup demonstration

If the dashboard fails but `/docs` works:

1. Open `http://127.0.0.1:8000/docs`.
2. Expand **Demo Scenarios**.
3. Use `GET /api/v1/demo/scenarios` to confirm the exact IDs.
4. Expand `POST /api/v1/demo/scenarios/{scenario_id}/run`.
5. Select **Try it out**, enter one curated scenario ID, and select **Execute**.
6. Send no request body. Do not send `{}` and do not add credentials.
7. Inspect `passed`, `analysis_summary`, `composition_summary`, `contract_summary`, `gateway_decisions`, `timeline`, and `evidence_chain_valid`.
8. Use `GET /api/v1/evidence/verify` to show the final chain status.

An HTTP error or malformed response is an execution error. Never describe it as an allow decision.

## Closing explanation, 30 seconds

“The technical contribution demonstrated here is the combination of provider-qualified intent mapping, capability-level graph analysis, exact bounded least-privilege synthesis, contract-bound runtime evaluation, and an explicit comparison between observed and authorized cross-provider flows. Each simulated decision is linked to tamper-evident evidence. The current implementation proves this workflow with local deterministic data; real-provider interception, persistent contracts, authentication, and production deployment remain future work.”
