# ScopeSentry-R Final IPR Cell Submission Package

## Package status

This tracked Markdown package describes the ScopeSentry-R credential-free local proof of concept at commit `a31bbf9dfb737f30ec20fb32fd4f1dc5435f0151`. It is prepared for inventor, faculty, IPR Cell, and professional patent-counsel review. It does not establish novelty, inventive step, patentability, freedom to operate, production readiness, formal verification, or independent validation.

Ground truth status: **author-defined; independent review pending**.

## Canonical and supporting documents

| Order | Document | Purpose |
|---:|---|---|
| 1 | `01-Invention-Disclosure.md` | Canonical technical submission document |
| 2 | `02-Novelty-and-Claim-Concepts.md` | Qualified comparison and technical concepts for professional review |
| 3 | `03-Submission-Diagrams.md` | Reviewed architecture and workflow figures |
| 4 | `04-Demo-Guide.md` | Concise local demonstration procedure |
| 5 | `05-Inventor-Faculty-Review-Checklist.md` | Blank technical and ownership review record |
| 6 | `06-Prior-Art-Review-Worksheet.md` | Blank professional search and comparison worksheet |

The existing documents directly under `docs/ipr/` are technical annexes. If wording differs, `01-Invention-Disclosure.md` is the canonical submission wording, while source code, automated tests, and frozen evaluation reports remain the authority for implemented behavior and measured results.

## Technical evidence inventory

- Machine-readable traceability: `docs/ipr/traceability.json`
- Human-readable traceability: `docs/ipr/Novelty-Traceability-Matrix.md`
- Ground-truth review template: `docs/evaluation-ground-truth-review.md`
- Phase 4 / V1 reports: `reports/evaluation/scope_sentry_evaluation.{json,csv,md}`
- Phase 5 / V2 reports: `reports/evaluation/scope_sentry_evaluation_v2.{json,csv,md}`
- Release verifier: `app/release/verify.py`
- Local dashboard: `/demo`

## Terminology

- **Phase 4 / V1 / legacy corpus:** the original 24-case single-provider evaluation.
- **Phase 5 / V2 / provider-qualified corpus:** V1 plus 12 provider-qualified cases, for 36 cases total.
- **Adapter ID:** simulation implementation name, for example `mock-google`.
- **Canonical authority provider ID:** security namespace used internally, for example `google`.
- **Runtime enforcement:** capability-decision enforcement within the credential-free simulator; it does not intercept a commercial-provider operation.
- **Monitoring:** evaluation of supplied runtime observations, not autonomous provider telemetry.
- **Containment:** a simulated block, quarantine, incomplete contract, or demonstration-orchestrator skip.
- **Remediation:** a recommendation; no real provider permission is revoked.
- **Exact synthesis:** exact within the configured finite local catalogue and risk model.
- **Evidence:** tamper-evident under the documented storage assumptions, not tamper-proof.

## Review order

1. Review the canonical disclosure and diagrams.
2. Check every candidate concept against the traceability matrix.
3. Review the author-defined ground truth independently.
4. Conduct and record a prior-art search.
5. Complete the inventor/faculty checklist.
6. Obtain professional patent-counsel/IPR review before drafting legal claims.

No DOCX or PDF is generated in this phase.
