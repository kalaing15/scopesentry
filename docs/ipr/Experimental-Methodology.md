# Experimental Methodology

> **Experimental annex.** Phase 4, V1, and legacy corpus refer to the frozen 24-case evaluation. Phase 5, V2, and provider-qualified corpus refer to V1 plus 12 provider-qualified cases (36 total). These terms describe report generations, not production releases.

## Status and purpose

**Ground truth is author-defined; independent review is pending.** The deterministic corpus is intentionally threat-heavy and is not statistically representative. Results demonstrate reproducible behavior of this local PoC; they are not formal security guarantees or evidence of patentability.

## Corpora

V1 defines 24 cases in `app/evaluation/corpus.py`: 8 safe and 16 unsafe. V2 in `app/evaluation/corpus_v2.py` preserves those 24 definitions and adds 12 provider-qualified cases, yielding 11 safe and 25 unsafe cases. Each case declares its inputs, classification, high-level outcome, and rationale before either system runs.

- V1 canonical SHA-256: `00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b`
- V2 canonical SHA-256: `070b0b607dcc1170a9f49250943c09df42f005ee279ed6b7e721ef4a0a15b06d`

The human-review template is `docs/evaluation-ground-truth-review.md`; its reviewer fields remain blank.

## Comparison baseline

`StaticScopeBaseline` performs provider-aware required-scope coverage. It permits when required scopes are present or covered by a broader scope inside the same canonical provider and principal grouping, and prevents when required authority is missing. It ignores unrelated extra scopes, does not synthesize a reduced contract, does not enforce runtime drift/capability use, and does not analyze cross-grant paths. It receives the same case inputs as ScopeSentry-R and is not called by production APIs.

## Decision normalization and containment

Positive means unsafe. `allow` is permitted. `block` and `quarantine` are prevented. Missing authority with no contract, manual review, and unsafe-composition skip are prevented/incomplete. An execution error or malformed decision is an evaluation error and never a successful containment. Therefore TP is unsafe and effectively contained; FN is unsafe but permitted; TN is safe and permitted; FP is safe but prevented.

The reports provide recall, precision, false-allow rate, false-block rate, safe-case allow rate, unsafe-case prevention rate, overall accuracy, attack-category coverage, and category-specific drift, composition, missing-permission, and excessive-scope rates. Each percentage retains numerator and denominator; zero denominators are reported not applicable.

## Exposure and path measures

Per-case scope fields include original, required, matched, excessive, missing, synthesized, and removed scope counts. Exposure-reduction ratio is removed excessive scopes divided by original unique granted scopes; a zero denominator is not applicable. Scope count is only one authority-exposure indicator. Capability/path fields are read from evaluated graph results, including required/available/missing capabilities, attempted unauthorized capabilities, provider-qualified path endpoints, detected path counts, and remediation.

## Captured results

The frozen V1 report records ScopeSentry-R at 16 TP, 8 TN, 0 FP, and 0 FN, compared with 4 TP, 8 TN, 0 FP, and 12 FN for the static baseline. The frozen V2 report records ScopeSentry-R at 25 TP, 11 TN, 0 FP, and 0 FN, compared with 7 TP, 11 TN, 0 FP, and 18 FN for the baseline. V2 unsafe-case prevention is 25/25 for ScopeSentry-R and 7/25 for the baseline on this author-defined corpus.

## Performance measurement

The runners use `time.perf_counter_ns()`, configurable excluded warm-ups, and configurable measured iterations. They report nanosecond minimum, maximum, median, and nearest-rank p95 for intent analysis, exposure, synthesis, runtime gateway, composition, end-to-end ScopeSentry-R, and baseline stages where applicable. Metadata records Python, operating system, timestamp, warm-ups, and iterations. Repeated timing excludes evidence I/O; correctness evaluation uses temporary evidence. Captured values are platform-sensitive local observations, not production benchmarks or thresholds.

## Evidence isolation

Evaluation creates a temporary JSON Lines evidence chain, verifies it, and cleans its temporary context. Timing repetitions are evidence-free. The runner hashes normal evidence before and after and fails if it changes. Phase 5 also hashes V1 reports before and after V2 generation. The release verifier does not rerun either evaluation.

## Reproduction

```powershell
python -m app.evaluation.runner --iterations 50 --warmups 5 --output-dir reports\evaluation
python -m app.evaluation.runner_v2 --iterations 50 --warmups 5 --output-dir reports\evaluation
```

Existing captured reports are under `reports/evaluation/`. Re-running changes timestamp and timing metadata, so preserve frozen review artifacts before reproduction.

## Threats to validity

The catalogue, intent mappings, cases, and ground truth are author-defined; providers are synthetic; the corpus is small and threat-heavy; flows and runtime observations are simulated; safe/unsafe classification has not been independently reviewed; timing is machine-dependent; and perfect corpus classification does not imply complete attack coverage. The static baseline is deliberately limited to its documented scope-coverage purpose but is not artificially denied that capability.
