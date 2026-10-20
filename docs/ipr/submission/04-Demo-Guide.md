# ScopeSentry-R IPR Cell Demo Guide

## Purpose and boundaries

This 10–15 minute demonstration shows the credential-free simulator, local dashboard, deterministic scenarios, frozen evaluation results, and tamper-evident evidence verification. It requires no internet connection, OAuth credential, or commercial-provider account.

Do not describe simulator decisions as real-provider interception or the author-defined corpus as independent validation.

## 1. Verify the local release

From the repository root in PowerShell:

```powershell
python -m app.release.verify --output-dir reports\release
```

Expected status: `ready_for_local_ipr_demo`. A dirty Git warning does not change the technical status if all required checks pass. Ground truth remains author-defined and pending independent review.

## 2. Start the application

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/demo`. The root API response and Swagger remain at `/` and `/docs`.

## 3. Explain the pipeline

Use the dashboard workflow:

> User intent → provider-qualified authority → capability graph → exposure differential → bounded least-privilege contract → supplied runtime observation → simulator decision → tamper-evident evidence.

Emphasize that browser code presents backend results and does not reproduce policy logic.

## 4. Demonstrate representative scenarios

Run scenarios one at a time. Each run appends legitimate demo evidence to the configured evidence file; use a copied or designated demonstration environment when evidence preservation matters.

| Demonstration | Scenario | Expected high-level result | Talking point |
|---|---|---|---|
| Exact authority | `safe-file-reader` | Allow | Required scope matches intent and synthesized contract. |
| Excessive authority | `overprivileged-file-reader` | Excess Gmail authority removed; unauthorized attempt blocked | Exposure differs from functional necessity. |
| Runtime drift | `runtime-scope-drift` | Quarantine | A newly supplied unexpected scope changes contract state. |
| Cross-grant path | `composed-exfiltration-path` | Unauthorized path detected and skipped | Individually usable grants can compose into an unauthorized path. |
| Provider collision | `wrong-provider-scope-collision` | Wrong-provider scope does not satisfy authority | Text equality does not collapse provider identity. |
| Authorized workflow | `authorized-cross-provider-workflow` | Declared flow accepted | Observed flow and exact authorization are separate records. |
| Unauthorized workflow | `unauthorized-cross-provider-exfiltration` | Path detected and skipped; remediation recommended | Known providers and an observed link do not imply authorization. |

The complete registry contains fourteen deterministic scenarios; the table selects those most useful in a short review.

## 5. Show evidence verification

Use the dashboard evidence panel or:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/evidence/verify
```

Explain that verification checks JSON parsing, sequence continuity, predecessor links, and recomputed record hashes. It is tamper-evident under the documented storage assumptions, not tamper-proof.

## 6. Show frozen evaluation results

Open locally:

- `reports/evaluation/scope_sentry_evaluation.md` (V1/Phase 4, 24 cases)
- `reports/evaluation/scope_sentry_evaluation_v2.md` (V2/Phase 5, 36 provider-qualified cases)

V2 records ScopeSentry-R at 25 true positives, 11 true negatives, 0 false positives, and 0 false negatives on the author-defined deterministic local corpus. The static baseline records 7 true positives, 11 true negatives, 0 false positives, and 18 false negatives. These observations are not universal security or production-performance guarantees.

## 7. Close with limitations

- synthetic providers and internal normalized scope aliases;
- supplied observations rather than provider telemetry;
- process-local contracts;
- local JSON Lines evidence with an in-process lock;
- no authentication, real OAuth, database, distributed enforcement, or automatic revocation;
- author-defined ground truth and limited baseline comparison;
- prior-art and professional legal review pending.

## Troubleshooting

- If the dashboard is unavailable, confirm Uvicorn is running on `127.0.0.1:8000` and inspect startup output.
- If port 8000 is occupied, stop the known local process or select another local port and update the browser URL.
- If release verification fails, read the named failed check; do not regenerate frozen reports or evidence as a workaround.
- If pytest cannot access the system temporary directory, use the repository-local ignored `.test-tmp` approach documented in `Reproducibility-Guide.md`; do not weaken Windows ACLs.

## Safe restart

Stop Uvicorn with `Ctrl+C` and run the start command again. Contract state is process-local and therefore resets on restart. Evidence does not reset automatically. Do not delete evidence or reports during a review.
