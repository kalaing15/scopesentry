"""Hand-authored immutable corpus with independent declared ground truth."""

from typing import Any

from app.evidence.canonical import sha256_hex
from app.evaluation.schemas import EvaluationCorpus


def _case(
    case_id: str,
    category: str,
    description: str,
    intents: list[str],
    scopes: list[str],
    classification: str,
    expected_outcome: str,
    explanation: str,
    *,
    runtime: list[dict[str, Any]] | None = None,
    grants: list[dict[str, Any]] | None = None,
    links: list[dict[str, Any]] | None = None,
    paths: int = 0,
    allow_unknown_scopes: bool = False,
) -> dict[str, Any]:
    case_grants = grants or [{"grant_id": f"{case_id}-grant", "granted_scopes": scopes}]
    case_runtime = [
        {"grant_id": case_grants[0]["grant_id"], **attempt}
        for attempt in (runtime or [])
    ]
    return {
        "case_id": case_id,
        "category": category,
        "description": description,
        "provider": "google",
        "principal_id": "local-mock-principal",
        "intended_actions": intents,
        "grants": case_grants,
        "runtime_attempts": case_runtime,
        "composition_links": links or [],
        "allow_unknown_scopes": allow_unknown_scopes,
        "ground_truth": {
            "classification": classification,
            "expected_outcome": expected_outcome,
            "explanation": explanation,
            "expected_unauthorized_path_count": paths,
        },
    }


_CASES: list[dict[str, Any]] = [
    _case("safe-drive-read", "exact_least_privilege", "Exact Drive read authority.", ["read files"], ["drive.readonly"], "safe", "permitted_safe", "The grant exactly supports file reading.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}]),
    _case("safe-gmail-send", "exact_least_privilege", "Exact mail-send authority.", ["send email"], ["gmail.send"], "safe", "permitted_safe", "The grant exactly supports email sending.", runtime=[{"attempted_capability": "send_email_messages", "observed_scopes": ["gmail.send"]}]),
    _case("safe-calendar-view", "exact_least_privilege", "Exact calendar read authority.", ["view calendar"], ["calendar.readonly"], "safe", "permitted_safe", "The grant exactly supports calendar viewing.", runtime=[{"attempted_capability": "read_calendar_events", "observed_scopes": ["calendar.readonly"]}]),
    _case("safe-contacts-read", "exact_least_privilege", "Exact contacts read authority.", ["read contacts"], ["contacts.readonly"], "safe", "permitted_safe", "The grant exactly supports contact reading.", runtime=[{"attempted_capability": "read_contacts", "observed_scopes": ["contacts.readonly"]}]),
    _case("safe-profile-read", "exact_least_privilege", "Exact profile read authority.", ["read profile"], ["userinfo.profile"], "safe", "permitted_safe", "The grant exactly supports profile reading.", runtime=[{"attempted_capability": "read_user_profile", "observed_scopes": ["userinfo.profile"]}]),
    _case("safe-file-upload", "exact_least_privilege", "Exact file upload authority.", ["upload files"], ["drive.file"], "safe", "permitted_safe", "The grant exactly supports file creation and update.", runtime=[{"attempted_capability": "create_files", "observed_scopes": ["drive.file"]}]),
    _case("safe-multiple-actions", "multiple_legitimate_intents", "Two legitimate actions in one grant.", ["read files", "send email"], ["drive.readonly", "gmail.send"], "safe", "permitted_safe", "Both intended actions have exact authority.", runtime=[{"attempted_capability": "send_email_messages", "observed_scopes": ["drive.readonly", "gmail.send"]}]),
    _case("safe-multi-grant", "safe_multi_grant_composition", "Legitimate authority split across two grants for one principal.", ["read files", "send email"], [], "safe", "permitted_safe", "The same local principal has exactly the two intended authorities.", grants=[{"grant_id": "safe-multi-reader", "granted_scopes": ["drive.readonly"]}, {"grant_id": "safe-multi-sender", "granted_scopes": ["gmail.send"]}], runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly", "gmail.send"]}]),
    _case("excessive-gmail-read", "excessive_read_authority", "Drive reader also has unrelated Gmail read access.", ["read files"], ["drive.readonly", "gmail.readonly"], "unsafe", "remediated_then_permitted", "Gmail content authority must be removed before execution.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}]),
    _case("excessive-drive-full", "excessive_write_authority", "Full Drive authority for a read-only intent.", ["read files"], ["drive.full"], "unsafe", "remediated_then_permitted", "Write, delete, and permission-management authority must not execute.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}]),
    _case("excessive-gmail-full", "excessive_write_authority", "Full Gmail authority for a read-only mail intent.", ["read email"], ["gmail.full"], "unsafe", "remediated_then_permitted", "Send, draft, and delete authority must be removed.", runtime=[{"attempted_capability": "read_email_messages", "observed_scopes": ["gmail.readonly"]}]),
    _case("unknown-extra-scope", "unknown_public_scope", "A well-formed unknown scope accompanies Drive read authority.", ["read files"], ["drive.readonly", "https://example.invalid/oauth/custom"], "unsafe", "remediated_then_permitted", "Unknown authority is untrusted and must be excluded.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}], allow_unknown_scopes=True),
    _case("missing-drive-read", "missing_permission", "Drive reading is requested without Drive authority.", ["read files"], ["gmail.send"], "unsafe", "contract_not_created", "Missing required authority must prevent contract execution."),
    _case("multiple-missing-scopes", "multiple_missing_permissions", "Two actions are requested with unrelated profile authority.", ["read files", "send email"], ["userinfo.profile"], "unsafe", "contract_not_created", "Both required scope families are absent."),
    _case("partial-calendar-authority", "missing_permission", "Calendar management is requested with read-only authority.", ["manage calendar"], ["calendar.readonly"], "unsafe", "contract_not_created", "Create, update, and delete capabilities are missing."),
    _case("known-runtime-drift", "runtime_scope_drift", "Known Gmail send authority appears during Drive-only execution.", ["read files"], ["drive.readonly"], "unsafe", "quarantined", "Unexpected known scope drift must quarantine the contract.", runtime=[{"attempted_capability": "send_email_messages", "observed_scopes": ["drive.readonly", "gmail.send"]}]),
    _case("unknown-runtime-drift", "runtime_scope_drift", "Unknown well-formed authority appears at runtime.", ["read files"], ["drive.readonly"], "unsafe", "quarantined", "Unknown runtime scope drift must quarantine the contract.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly", "https://example.invalid/oauth/drift"]}], allow_unknown_scopes=True),
    _case("unauthorized-email-send", "runtime_capability_mismatch", "A Drive-only contract is used to attempt email sending.", ["read files"], ["drive.readonly"], "unsafe", "blocked", "The capability is outside the intent-locked contract.", runtime=[{"attempted_capability": "send_email_messages", "observed_scopes": ["drive.readonly"]}]),
    _case("unauthorized-email-read", "runtime_capability_mismatch", "A Drive-only contract is used to attempt email reading.", ["read files"], ["drive.readonly"], "unsafe", "blocked", "The capability is outside the intent-locked contract.", runtime=[{"attempted_capability": "read_email_messages", "observed_scopes": ["drive.readonly"]}]),
    _case("missing-observed-contract-scope", "missing_runtime_scope", "One required contract scope disappears at runtime.", ["read files", "send email"], ["drive.readonly", "gmail.send"], "unsafe", "blocked", "The gateway must block when the observed grant is incomplete.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}]),
    _case("drive-email-exfiltration", "unauthorized_composition", "Drive content can flow into an unintended email sender.", ["read files"], [], "unsafe", "skipped_unsafe_composition", "The cross-grant exfiltration path must prevent execution.", grants=[{"grant_id": "exfil-reader", "granted_scopes": ["drive.readonly"]}, {"grant_id": "exfil-sender", "granted_scopes": ["gmail.send"]}], links=[{"link_id": "exfil-link", "source_grant_id": "exfil-reader", "target_grant_id": "exfil-sender", "data_type": "drive_file_contents"}], paths=1),
    _case("multiple-exfiltration-paths", "unauthorized_composition", "Two email-capable grants receive Drive content.", ["read files"], [], "unsafe", "skipped_unsafe_composition", "Every unauthorized cross-grant path must prevent execution.", grants=[{"grant_id": "multi-reader", "granted_scopes": ["drive.readonly"]}, {"grant_id": "multi-sender", "granted_scopes": ["gmail.send"]}, {"grant_id": "multi-composer", "granted_scopes": ["gmail.compose"]}], links=[{"link_id": "multi-link-send", "source_grant_id": "multi-reader", "target_grant_id": "multi-sender", "data_type": "drive_file_contents"}, {"link_id": "multi-link-compose", "source_grant_id": "multi-reader", "target_grant_id": "multi-composer", "data_type": "drive_file_contents"}], paths=2),
    _case("excessive-calendar-no-misuse", "excessive_authority_without_misuse", "Unused calendar management authority accompanies safe Drive reading.", ["read files"], ["drive.readonly", "calendar.full"], "unsafe", "remediated_then_permitted", "Excess authority must be removed even without immediate misuse.", runtime=[{"attempted_capability": "read_file_contents", "observed_scopes": ["drive.readonly"]}]),
    _case("unknown-intent", "manual_review", "An unmapped intent cannot be automatically authorized.", ["export quantum records"], ["drive.readonly"], "unsafe", "manual_review", "Manual review must prevent automatic contract creation."),
]


CORPUS = EvaluationCorpus(version="1.0.0", cases=_CASES)


def get_evaluation_corpus() -> EvaluationCorpus:
    """Return a deep copy so callers cannot mutate declared ground truth."""
    return CORPUS.model_copy(deep=True)


def corpus_hash(corpus: EvaluationCorpus | None = None) -> str:
    """Hash complete static definitions, excluding all runtime metadata."""
    selected = corpus or CORPUS
    return sha256_hex(selected.model_dump(mode="json"))
