# ScopeSentry-R Live Demo Troubleshooting

## Preflight reports the wrong Python interpreter

Run the launcher rather than invoking the checker with a global Python installation:

```powershell
cd C:\scopesentry
.\tools\demo\start_demo.ps1
```

The launcher uses `C:\scopesentry\.venv\Scripts\python.exe` explicitly. Do not install packages during the demonstration.

## Port 8000 is unavailable

The launcher stops before starting Uvicorn and identifies the unavailable address. Find the process through normal Windows administration and decide whether it is safe to stop. The launcher never kills a process automatically. Do not change or weaken permissions.

## Backend connection fails

Keep the PowerShell window open and check for a Uvicorn startup error. Verify:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/demo`

If health and Swagger work but the dashboard does not, use the Swagger backup flow in `docs/demo/Live-Demo-Script.md`.

## Dashboard scenario fails

Do not reinterpret an error as a successful or allowed decision. Record the scenario ID, HTTP status, and visible error text. Retry only after checking backend logs and confirming the request is bodyless.

The scenario run endpoint accepts no request body. `{}`, whitespace, text, and binary bodies produce HTTP 400.

## Evidence verification fails

Stop the demonstration. Do not append, delete, edit, truncate, reset, or recompute `runtime/evidence.jsonl`. Preserve the verifier output and investigate from a copy.

## Release-profile or frozen-hash check fails

Do not regenerate either evaluation corpus or report. Compare the named file with the approved canonical and HEAD hashes. A line-ending-only V2 checkout should still pass because the verifier uses LF-canonicalized report identity.

## Scenario list differs

Stop and use `GET /api/v1/demo/scenarios` to inspect the live registry. Do not invent or rename a scenario ID during the presentation.

## Contract behavior after restart

Contracts are process-local and disappear when Uvicorn stops. Evidence remains file-backed and is not reset by a normal restart. Rerun a scenario to create a new temporary contract; do not edit repository state manually.

## Safe shutdown

Press `Ctrl+C` once in the Uvicorn PowerShell window. The launcher does not terminate other processes and does not alter evidence or evaluation reports.
