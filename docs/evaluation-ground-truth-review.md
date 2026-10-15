# ScopeSentry-R Evaluation Ground-Truth Review

Status: **Author-defined corpus; independent review pending.**

This document supports human review of the declared ground truth used by the
local Phase 5 evaluation. The reviewer should assess each case independently
of ScopeSentry-R output. A passing automated evaluation is not a substitute
for that review and is not a formal security or patentability proof.

## Reviewer record

- Reviewer name:
- Affiliation or role:
- Review date:
- Review methodology:
- Approval:
- Signature:
- Independent-validation conclusion:

## Review criteria

For every case, confirm that its safe/unsafe classification, intended actions,
provider and principal boundaries, granted scopes, runtime attempt, observed
flow, exact flow authorization, expected operational outcome, and rationale
are internally consistent. An observed cross-provider flow is unauthorized by
default unless every identity and capability field exactly matches a declared
flow authorization.

## Frozen Phase 4 cases

The 24 Phase 4 cases are retained byte-for-byte in V2. Their canonical corpus
hash remains:

`00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b`

Review source: `app/evaluation/corpus.py`

## Provider-qualified Phase 5 cases

| Case ID | Category | Reviewer classification | Reviewer notes |
|---|---|---|---|
| `v2-enterprise-safe-read` | Provider-safe access |  |  |
| `v2-enterprise-broad-read` | Provider excessive authority |  |  |
| `v2-enterprise-runtime-drift` | Provider runtime drift |  |  |
| `v2-code-safe-read` | Provider-safe access |  |  |
| `v2-code-excess-webhook` | Provider excessive authority |  |  |
| `v2-wrong-provider-scope-collision` | Provider scope collision |  |  |
| `v2-capability-name-collision` | Provider capability collision |  |  |
| `v2-safe-authorized-cross-flow` | Authorized cross-provider flow |  |  |
| `v2-unauthorized-cross-exfiltration` | Unauthorized cross-provider flow |  |  |
| `v2-enterprise-missing-mail` | Provider missing permission |  |  |
| `v2-code-unauthorized-webhook` | Provider capability mismatch |  |  |
| `v2-runtime-principal-mismatch` | Principal mismatch |  |  |

Review source: `app/evaluation/corpus_v2.py`

## Review outcome

- Cases reviewed:
- Cases accepted without change:
- Cases requiring revision:
- Conflicts of interest disclosed:
- Additional observations:

