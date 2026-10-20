# Faculty and IPR Demonstration Runbook

Target duration: 10–15 minutes. Everything runs locally with synthetic data; internet access and OAuth credentials are neither needed nor used.

## 1. Environment verification (1 minute)

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m app.release.verify --output-dir reports\release
```

Expected: tests pass; verifier reports `ready_for_local_ipr_demo`. A dirty-tree warning is permitted. Ground truth must be described as author-defined and pending independent review.

## 2. Start FastAPI (1 minute)

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/demo`. Optionally show `/docs` and the unchanged root response at `/`.

Talking point: the dashboard uses local assets and same-origin APIs; security decisions remain in Python services.

## 3. Explain the workflow (1 minute)

```text
intent → provider authority → graph → exposure → contract
       → runtime enforcement → flow containment → evidence
```

Adapter names and canonical authority identities are distinct. Synthetic providers are not commercial integrations.

## 4. Run representative scenarios (7–9 minutes)

Run each dashboard card individually so its timeline and evidence are visible.

1. `safe-file-reader`: exact scope match and `allow`.
2. `overprivileged-file-reader`: Gmail read authority excluded; unauthorized use blocked/quarantined.
3. `runtime-scope-drift`: unexpected Gmail send authority quarantines the contract.
4. `composed-exfiltration-path`: file-to-email path detected and unsafe execution skipped.
5. `wrong-provider-scope-collision`: same-text authority from the wrong provider fails closed.
6. `safe-authorized-cross-provider-workflow`: separate contracts and an exact authorized flow succeed.
7. `unauthorized-cross-provider-exfiltration`: enterprise-content-to-webhook flow is contained.

An observed link is not permission. Exact authorization needs both provider/principal/grant/capability endpoints and data type. No global cross-provider contract is created.

## 5. Evidence verification (1 minute)

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/evidence/verify
```

Expected: `valid` is true and `first_invalid_sequence` is null. Record count may increase after legitimate demonstrations and is not fixed.

## 6. V2 comparison metrics (1 minute)

Open `reports/evaluation/scope_sentry_evaluation_v2.md`. Explain the frozen author-defined 36-case corpus and baseline assumptions. Do not present local timing as production performance or classification as formal proof.

## 7. Limitations (1 minute)

State: synthetic providers; author-defined ground truth; no real tokens or OAuth; process-local unauthenticated contracts; declared flows; file-backed tamper-evident—not tamper-proof—evidence; in-process locking; no database, distributed deployment, or production claim.

## Troubleshooting and safe restart

- Connection refused: keep Uvicorn open and ensure port 8000 is free.
- Import failure: activate `.venv` and run from the repository root.
- Dashboard unavailable: verify `/health` and `/docs` first.
- Scenario error: do not reinterpret it as allow; retain the error response.
- Evidence invalid: stop. Do not append, delete, repair, or recompute the log.
- Verifier failure: inspect its named failed check; it never repairs artifacts.

Stop Uvicorn with `Ctrl+C` and restart with the command above. Restarting clears process-local contracts but does not reset evidence. Do not delete `runtime/evidence.jsonl`.
