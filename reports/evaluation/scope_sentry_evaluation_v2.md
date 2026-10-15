# ScopeSentry-R Reproducible Security Evaluation

## Executive summary

This local, deterministic corpus contains 36 cases: 11 safe and 25 unsafe. It is intentionally threat-heavy and is not statistically representative of every OAuth deployment.

ScopeSentry-R unsafe-case prevention: **100.00% (25/25)**. Static baseline unsafe-case prevention: **28.00% (7/25)**.

## Methodology

Immutable declared ground truth is evaluated independently against a provider-aware static scope baseline and the production ScopeSentry-R services. Baseline disagreements are measured results; ScopeSentry-R disagreements fail the evaluation.

## Corpus composition

Corpus SHA-256: `070b0b607dcc1170a9f49250943c09df42f005ee279ed6b7e721ef4a0a15b06d`

| Category | Cases |
|---|---:|
| authorized_cross_provider_flow | 1 |
| exact_least_privilege | 6 |
| excessive_authority_without_misuse | 1 |
| excessive_read_authority | 1 |
| excessive_write_authority | 2 |
| manual_review | 1 |
| missing_permission | 2 |
| missing_runtime_scope | 1 |
| multiple_legitimate_intents | 1 |
| multiple_missing_permissions | 1 |
| principal_mismatch | 1 |
| provider_capability_collision | 1 |
| provider_capability_mismatch | 1 |
| provider_excessive_authority | 2 |
| provider_missing_permission | 1 |
| provider_runtime_drift | 1 |
| provider_safe_access | 2 |
| provider_scope_collision | 1 |
| runtime_capability_mismatch | 2 |
| runtime_scope_drift | 2 |
| safe_multi_grant_composition | 1 |
| unauthorized_composition | 2 |
| unauthorized_cross_provider_flow | 1 |
| unknown_public_scope | 1 |

## Metric definitions

Positive means unsafe. TP: unsafe authority contained; FN: unsafe authority permitted; TN: safe action permitted; FP: safe action prevented. Detection alone is insufficient: successful unsafe handling requires effective containment.

## Comparison

| Capability | Static scope baseline | ScopeSentry-R |
|---|---:|---:|
| Required-scope checking | Yes | Yes |
| Excessive-scope detection | No | Yes |
| Least-privilege synthesis | No | Yes |
| Runtime drift detection | No | Yes |
| Capability-level enforcement | No | Yes |
| Cross-grant composition detection | No | Yes |
| Unauthorized-path remediation | No | Yes |
| Tamper-evident evidence | No | Yes |

| System | TP | TN | FP | FN | False-allow rate | Safe allow rate |
|---|---:|---:|---:|---:|---:|---:|
| Static baseline | 7 | 11 | 0 | 18 | 72.00% (18/25) | 100.00% (11/11) |
| ScopeSentry-R | 25 | 11 | 0 | 0 | 0.00% (0/25) | 100.00% (11/11) |

## Security findings

Operational outcomes remain distinct from binary normalization. Remediated cases execute only through synthesized scopes; blocked, quarantined, incomplete, composition-skipped, and manual-review cases do not execute unsafe authority.

## Least-privilege findings

Authority was reduced in 16 cases. Mean scope-count exposure reduction was 0.3519. Scope count is one measurable exposure indicator, not a complete security guarantee.

## Performance observations

Timings use `time.perf_counter_ns()` after warm-up. Evidence I/O, report I/O, HTTP, UUID creation, and temporary cleanup are excluded. These are local PoC observations, not production performance guarantees. The baseline performs materially less security work, so timing is not a functional-equivalence comparison.

| Stage | Samples | Median (ns) | p95 (ns) | Min | Max |
|---|---:|---:|---:|---:|---:|
| composition_analysis | 150 | 20436000.0 | 24424000 | 18596500 | 34289200 |
| contract_synthesis | 1200 | 20367150.0 | 23704500 | 4900 | 91152700 |
| end_to_end_scope_sentry | 1200 | 21083450.0 | 44540000 | 71400 | 98023600 |
| exposure_calculation | 1200 | 5900.0 | 11300 | 3900 | 46200 |
| intent_analysis | 1200 | 2400.0 | 3700 | 1700 | 116800 |
| runtime_gateway_decision | 900 | 7700.0 | 9700 | 5600 | 1207500 |
| static_baseline | 1200 | 13300.0 | 19300 | 7300 | 312500 |
| end_to_end_scope_sentry_provider_qualified | 600 | 1035650.0 | 2306400 | 494700 | 4624000 |
| static_baseline_provider_qualified | 600 | 14200.0 | 21700 | 8300 | 191700 |

## Evidence integrity

Temporary evaluation chain valid: **True**; isolated records: **36**. Normal evidence state remained unchanged: **True**.

## Limitations

- The corpus and ground truth are author-defined until independently reviewed.
- All providers are deterministic local simulators; no real provider interoperability is claimed.
- Scope counts are one exposure indicator and not a complete security measure.
- Local PoC timings exclude evidence and report I/O and are not production guarantees.
- This evaluation is technical evidence, not a formal security proof or legal proof of patentability.

## Reproduction

```powershell
python -m app.evaluation.runner_v2 --iterations 50 --warmups 5 --output-dir reports\evaluation
```
