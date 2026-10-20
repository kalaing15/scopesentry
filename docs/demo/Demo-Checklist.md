# ScopeSentry-R Live Demo Checklist

## Preflight

- [ ] Repository path is `C:\scopesentry`.
- [ ] `.venv\Scripts\python.exe` exists.
- [ ] Port 8000 is free.
- [ ] `tools\demo\start_demo.ps1` reports `ready_for_local_ipr_demo`.
- [ ] Dashboard opens at `http://127.0.0.1:8000/demo`.
- [ ] Swagger opens at `http://127.0.0.1:8000/docs`.
- [ ] Health endpoint returns successfully at `http://127.0.0.1:8000/health`.
- [ ] Browser zoom and projector resolution keep scope chips, paths, and timeline text readable.

## Required boundary statement

- [ ] Deterministic local simulator providers.
- [ ] Supplied runtime observations.
- [ ] Simulated enforcement decisions.
- [ ] Process-local contracts.
- [ ] Author-defined evaluation corpus pending independent review.
- [ ] No production-readiness or universal-security claim.

## Curated sequence

| Order | Scenario ID | Expected high-level result |
|---:|---|---|
| 1 | `safe-file-reader` | Contract created; Drive read allowed |
| 2 | `overprivileged-file-reader` | Gmail read scope removed; unexpected runtime scope quarantines the contract |
| 3 | `runtime-scope-drift` | Unexpected Gmail send scope quarantines the contract |
| 4 | `missing-required-permission` | `gmail.send` reported missing; no active contract |
| 5 | `composed-exfiltration-path` | One unauthorized Drive-to-email path detected; execution skipped |
| 6 | `unauthorized-cross-provider-exfiltration` | One unauthorized provider-qualified path detected; execution skipped |

## For every scenario

- [ ] Show declared intent and provider-qualified grant identity.
- [ ] Show granted, required, matched, excessive, and missing scopes.
- [ ] Show required, available, missing, and attempted capabilities.
- [ ] Show synthesized least-privilege scopes.
- [ ] Show contract creation, quarantine, rejection, or skip.
- [ ] Show runtime allow, block, or quarantine result when applicable.
- [ ] Show composition path and remediation when applicable.
- [ ] Read the plain-language explanation.
- [ ] Confirm the timeline remains ordered.
- [ ] Confirm evidence status is valid.

## Close

- [ ] Verify `http://127.0.0.1:8000/api/v1/evidence/verify`.
- [ ] State that record count is not fixed.
- [ ] Give the 30-second technical-contribution summary.
- [ ] Stop Uvicorn with `Ctrl+C`.
- [ ] Do not delete or reset the evidence file.

Operator: ____________________  Date: ____________________

Faculty reviewer: ____________________  Signature: ____________________
