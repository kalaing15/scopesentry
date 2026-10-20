# Reproducibility Guide

> **Reproducibility annex and glossary.** Phase 4/V1/legacy means the frozen 24-case corpus. Phase 5/V2/provider-qualified means V1 plus 12 provider-qualified cases. An adapter ID names a local implementation (for example `mock-google`); a canonical authority provider ID names the security namespace (`google`).

## Environment

The captured release-candidate environment uses Python 3.12. From the repository root in Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Initial dependency installation may require package access. Runtime tests, scenarios, evaluation, dashboard, and release verification require no external provider or OAuth network access.

## Quality gate and application

```powershell
python -m pytest -q
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Dashboard: `http://127.0.0.1:8000/demo`  
OpenAPI: `http://127.0.0.1:8000/docs`

The final verified Phase 6 baseline, and Phase 7 starting baseline, was 255 passing tests. After the Phase 7 documentation, traceability, and cross-platform frozen-report tests were added, the complete Phase 7 suite is 279 passing tests. Both runs contain the same existing Starlette TestClient/httpx deprecation warning. The deterministic registry contains 14 scenarios and three canonical authority identities: `google`, `mock-code-host`, and `mock-enterprise`.

## Evaluation reproduction

```powershell
python -m app.evaluation.runner --iterations 50 --warmups 5 --output-dir reports\evaluation
python -m app.evaluation.runner_v2 --iterations 50 --warmups 5 --output-dir reports\evaluation
```

Expected corpus hashes:

- V1: `00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b`
- V2: `070b0b607dcc1170a9f49250943c09df42f005ee279ed6b7e721ef4a0a15b06d`

Reports are `reports/evaluation/scope_sentry_evaluation.{json,csv,md}` and `reports/evaluation/scope_sentry_evaluation_v2.{json,csv,md}`. Reproduction changes timestamps and timing samples; preserve frozen review artifacts before rerunning.

Evaluation correctness evidence uses a temporary isolated chain. Timing repetitions do not write evidence. Normal evidence and frozen reports are guarded by before/after hashes.

## Release verification

```powershell
python -m app.release.verify --output-dir reports\release
```

The verifier reads source, registries, corpus definitions, frozen reports, dashboard/OpenAPI structure, and normal evidence. It does not run scenarios/evaluations, create contracts, append evidence, or use the network. Its only writes are atomic manifests in the selected directory.

`ready_for_local_ipr_demo` means required local technical checks passed. It does not mean production-ready, formally verified, independently validated, patentable, or real-provider compatible. Dirty Git state and incomplete human review are visible warnings.

## Determinism and platform sensitivity

Scenario decisions, normalized outcomes, ordering, and corpus hashes are deterministic. UUIDs, timestamps, Git metadata, environment versions, current evidence state, and performance timing may vary. Timing depends on platform and load and is not a production service-level result.

## Data and credential boundary

Only synthetic fixtures are used. No Google account, client ID, client secret, OAuth token, or provider SDK is required. The three mock adapters are not implementations of commercial services.
