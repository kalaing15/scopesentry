# ScopeSentry-R Reproducible Security Evaluation

## Executive summary

This local, deterministic corpus contains 24 cases: 8 safe and 16 unsafe. It is intentionally threat-heavy and is not statistically representative of every OAuth deployment.

ScopeSentry-R unsafe-case prevention: **100.00% (16/16)**. Static baseline unsafe-case prevention: **25.00% (4/16)**.

## Methodology

Immutable declared ground truth is evaluated independently against a provider-aware static scope baseline and the production ScopeSentry-R services. Baseline disagreements are measured results; ScopeSentry-R disagreements fail the evaluation.

## Corpus composition

Corpus SHA-256: `00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b`

| Category | Cases |
|---|---:|
| exact_least_privilege | 6 |
| excessive_authority_without_misuse | 1 |
| excessive_read_authority | 1 |
| excessive_write_authority | 2 |
| manual_review | 1 |
| missing_permission | 2 |
| missing_runtime_scope | 1 |
| multiple_legitimate_intents | 1 |
| multiple_missing_permissions | 1 |
| runtime_capability_mismatch | 2 |
| runtime_scope_drift | 2 |
| safe_multi_grant_composition | 1 |
| unauthorized_composition | 2 |
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
| Static baseline | 4 | 8 | 0 | 12 | 75.00% (12/16) | 100.00% (8/8) |
| ScopeSentry-R | 16 | 8 | 0 | 0 | 0.00% (0/16) | 100.00% (8/8) |

## Security findings

Operational outcomes remain distinct from binary normalization. Remediated cases execute only through synthesized scopes; blocked, quarantined, incomplete, composition-skipped, and manual-review cases do not execute unsafe authority.

## Least-privilege findings

Authority was reduced in 10 cases. Mean scope-count exposure reduction was 0.3194. Scope count is one measurable exposure indicator, not a complete security guarantee.

## Performance observations

Timings use `time.perf_counter_ns()` after warm-up. Evidence I/O, report I/O, HTTP, UUID creation, and temporary cleanup are excluded. These are local PoC observations, not production performance guarantees. The baseline performs materially less security work, so timing is not a functional-equivalence comparison.

| Stage | Samples | Median (ns) | p95 (ns) | Min | Max |
|---|---:|---:|---:|---:|---:|
| composition_analysis | 150 | 12221550.0 | 17164800 | 9221100 | 20430700 |
| contract_synthesis | 1200 | 14470850.0 | 18142100 | 4500 | 88975400 |
| end_to_end_scope_sentry | 1200 | 15523850.0 | 29928200 | 60600 | 107154100 |
| exposure_calculation | 1200 | 4400.0 | 6100 | 2800 | 30600 |
| intent_analysis | 1200 | 1500.0 | 2200 | 800 | 13200 |
| runtime_gateway_decision | 900 | 5000.0 | 7900 | 3300 | 37800 |
| static_baseline | 1200 | 9600.0 | 14200 | 5900 | 75900 |

## Evidence integrity

Temporary evaluation chain valid: **True**; isolated records: **24**. Normal evidence state remained unchanged: **True**.

## Limitations

- The deterministic corpus is hand-authored and limited to one local mock provider catalogue.
- Scope counts are an authority-exposure indicator, not a complete security measure.
- Local PoC timings exclude persistence and network I/O and are not production guarantees.
- The static baseline intentionally lacks runtime, synthesis, composition-path, and evidence functionality, so timing is not functionally equivalent.
- This evaluation is technical evidence, not a formal security proof or legal proof of patentability.

## Reproduction

```powershell
python -m app.evaluation.runner --iterations 50 --warmups 5 --output-dir reports\evaluation
```
