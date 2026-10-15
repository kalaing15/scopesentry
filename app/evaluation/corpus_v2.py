"""Versioned Phase 5 corpus: frozen V1 cases plus provider-qualified cases."""

from typing import Any

from app.evidence.canonical import sha256_hex
from app.evaluation.corpus import get_evaluation_corpus
from app.evaluation.schemas_v2 import Phase5EvaluationCorpus


def _case(
    case_id: str,
    category: str,
    description: str,
    intents: list[dict[str, Any]],
    grants: list[dict[str, Any]],
    classification: str,
    outcome: str,
    rationale: str,
    *,
    attempts: list[dict[str, Any]] | None = None,
    links: list[dict[str, Any]] | None = None,
    authorizations: list[dict[str, Any]] | None = None,
    path_count: int = 0,
) -> dict[str, Any]:
    grants_by_id = {item["grant_id"]: item for item in grants}
    qualified_links = []
    for link in links or []:
        source = grants_by_id[link["source_grant_id"]]
        target = grants_by_id[link["target_grant_id"]]
        qualified_links.append({
            **link,
            "source_provider": source["provider"],
            "source_principal_id": source["principal_id"],
            "target_provider": target["provider"],
            "target_principal_id": target["principal_id"],
        })
    return {
        "case_id": case_id,
        "category": category,
        "description": description,
        "provider_intents": intents,
        "grants": grants,
        "runtime_attempts": attempts or [],
        "observed_links": qualified_links,
        "authorized_flows": authorizations or [],
        "ground_truth": {
            "classification": classification,
            "expected_outcome": outcome,
            "explanation": rationale,
            "expected_unauthorized_path_count": path_count,
        },
    }


_ENTERPRISE_INTENT = [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "intended_actions": ["read files"]}]
_CODE_INTENT = [{"provider": "mock-code-host", "principal_id": "eval-code", "intended_actions": ["read repositories"]}]

_PROVIDER_CASES = [
    _case("v2-enterprise-safe-read", "provider_safe_access", "Exact enterprise file-read authority.", _ENTERPRISE_INTENT, [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "grant_id": "v2-ent-safe", "granted_scopes": ["content.read"]}], "safe", "permitted_safe", "Exact provider-qualified scope and principal.", attempts=[{"grant_id": "v2-ent-safe", "attempted_capability": "read_sensitive_file_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-enterprise", "observed_principal_id": "eval-enterprise", "observed_grant_id": "v2-ent-safe"}]),
    _case("v2-enterprise-broad-read", "provider_excessive_authority", "Enterprise full authority for read-only intent.", _ENTERPRISE_INTENT, [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "grant_id": "v2-ent-broad", "granted_scopes": ["authority.full"]}], "unsafe", "remediated_then_permitted", "Only synthesized content.read may execute.", attempts=[{"grant_id": "v2-ent-broad", "attempted_capability": "read_sensitive_file_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-enterprise", "observed_principal_id": "eval-enterprise", "observed_grant_id": "v2-ent-broad"}]),
    _case("v2-enterprise-runtime-drift", "provider_runtime_drift", "Enterprise mail authority appears at runtime.", _ENTERPRISE_INTENT, [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "grant_id": "v2-ent-drift", "granted_scopes": ["content.read"]}], "unsafe", "quarantined", "Unexpected same-provider scope drift must quarantine.", attempts=[{"grant_id": "v2-ent-drift", "attempted_capability": "send_enterprise_messages", "observed_scopes": ["content.read", "mail.send"], "observed_provider": "mock-enterprise", "observed_principal_id": "eval-enterprise", "observed_grant_id": "v2-ent-drift"}]),
    _case("v2-code-safe-read", "provider_safe_access", "Exact code-host repository read authority.", _CODE_INTENT, [{"provider": "mock-code-host", "principal_id": "eval-code", "grant_id": "v2-code-safe", "granted_scopes": ["content.read"]}], "safe", "permitted_safe", "Exact code-host authority.", attempts=[{"grant_id": "v2-code-safe", "attempted_capability": "read_repository_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-code-host", "observed_principal_id": "eval-code", "observed_grant_id": "v2-code-safe"}]),
    _case("v2-code-excess-webhook", "provider_excessive_authority", "Repository reader also has webhook authority.", _CODE_INTENT, [{"provider": "mock-code-host", "principal_id": "eval-code", "grant_id": "v2-code-excess", "granted_scopes": ["content.read", "webhooks.manage"]}], "unsafe", "remediated_then_permitted", "Webhook authority must be excluded from execution.", attempts=[{"grant_id": "v2-code-excess", "attempted_capability": "read_repository_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-code-host", "observed_principal_id": "eval-code", "observed_grant_id": "v2-code-excess"}]),
    _case("v2-wrong-provider-scope-collision", "provider_scope_collision", "Enterprise content.read is presented for code-host intent.", _CODE_INTENT, [{"provider": "mock-enterprise", "principal_id": "eval-code", "grant_id": "v2-wrong-scope", "granted_scopes": ["content.read"]}], "unsafe", "contract_not_created", "Identical scope text cannot cross provider namespaces."),
    _case("v2-capability-name-collision", "provider_capability_collision", "Enterprise read_profile is presented for code-host profile intent.", [{"provider": "mock-code-host", "principal_id": "eval-code", "intended_actions": ["read profile"]}], [{"provider": "mock-enterprise", "principal_id": "eval-code", "grant_id": "v2-wrong-profile", "granted_scopes": ["profile.read"]}], "unsafe", "contract_not_created", "Identical capability text cannot cross provider namespaces."),
    _case("v2-safe-authorized-cross-flow", "authorized_cross_provider_flow", "Exact enterprise-to-issue flow authorization.", [{"provider": "mock-enterprise", "principal_id": "eval-cross", "intended_actions": ["read files"]}, {"provider": "mock-code-host", "principal_id": "eval-cross", "intended_actions": ["create issues"]}], [{"provider": "mock-enterprise", "principal_id": "eval-cross", "grant_id": "v2-cross-source", "granted_scopes": ["content.read"]}, {"provider": "mock-code-host", "principal_id": "eval-cross", "grant_id": "v2-cross-issues", "granted_scopes": ["issues.write"]}], "safe", "permitted_safe", "Observed flow matches every exact authorization component.", attempts=[{"grant_id": "v2-cross-source", "attempted_capability": "read_sensitive_file_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-enterprise", "observed_principal_id": "eval-cross", "observed_grant_id": "v2-cross-source"}, {"grant_id": "v2-cross-issues", "attempted_capability": "create_issues", "observed_scopes": ["issues.write"], "observed_provider": "mock-code-host", "observed_principal_id": "eval-cross", "observed_grant_id": "v2-cross-issues"}], links=[{"link_id": "v2-authorized-link", "source_grant_id": "v2-cross-source", "target_grant_id": "v2-cross-issues", "source_capability": "read_sensitive_file_contents", "target_capability": "create_issues", "data_type": "enterprise_file_contents", "description": "Observed approved issue flow."}], authorizations=[{"authorization_id": "v2-flow-contract", "source_provider": "mock-enterprise", "source_principal_id": "eval-cross", "source_grant_id": "v2-cross-source", "source_capability": "read_sensitive_file_contents", "data_type": "enterprise_file_contents", "target_provider": "mock-code-host", "target_principal_id": "eval-cross", "target_grant_id": "v2-cross-issues", "target_capability": "create_issues"}]),
    _case("v2-unauthorized-cross-exfiltration", "unauthorized_cross_provider_flow", "Enterprise sensitive data reaches external webhook authority.", _ENTERPRISE_INTENT, [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "grant_id": "v2-exfil-source", "granted_scopes": ["content.read"]}, {"provider": "mock-code-host", "principal_id": "eval-enterprise", "grant_id": "v2-exfil-webhook", "granted_scopes": ["webhooks.manage"]}], "unsafe", "skipped_unsafe_composition", "No flow contract authorizes the observed cross-provider path.", links=[{"link_id": "v2-exfil-link", "source_grant_id": "v2-exfil-source", "target_grant_id": "v2-exfil-webhook", "source_capability": "read_sensitive_file_contents", "target_capability": "configure_external_webhooks", "data_type": "sensitive_file_contents", "description": "Observed exfiltration path."}], path_count=1),
    _case("v2-enterprise-missing-mail", "provider_missing_permission", "Enterprise email sending lacks mail.send.", [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "intended_actions": ["send email"]}], [{"provider": "mock-enterprise", "principal_id": "eval-enterprise", "grant_id": "v2-ent-missing", "granted_scopes": ["content.read"]}], "unsafe", "contract_not_created", "Missing provider-specific capability prevents execution."),
    _case("v2-code-unauthorized-webhook", "provider_capability_mismatch", "Repository contract attempts webhook configuration.", _CODE_INTENT, [{"provider": "mock-code-host", "principal_id": "eval-code", "grant_id": "v2-code-block", "granted_scopes": ["content.read"]}], "unsafe", "blocked", "Capability is outside the code-host contract.", attempts=[{"grant_id": "v2-code-block", "attempted_capability": "configure_external_webhooks", "observed_scopes": ["content.read"], "observed_provider": "mock-code-host", "observed_principal_id": "eval-code", "observed_grant_id": "v2-code-block"}]),
    _case("v2-runtime-principal-mismatch", "principal_mismatch", "Correct scope is observed under the wrong principal.", _CODE_INTENT, [{"provider": "mock-code-host", "principal_id": "eval-code", "grant_id": "v2-code-principal", "granted_scopes": ["content.read"]}], "unsafe", "blocked", "Stored contract identity overrides request claims.", attempts=[{"grant_id": "v2-code-principal", "attempted_capability": "read_repository_contents", "observed_scopes": ["content.read"], "observed_provider": "mock-code-host", "observed_principal_id": "different-principal", "observed_grant_id": "v2-code-principal"}]),
]


CORPUS_V2 = Phase5EvaluationCorpus(
    legacy_cases=get_evaluation_corpus().cases,
    provider_cases=_PROVIDER_CASES,
)


def get_evaluation_corpus_v2() -> Phase5EvaluationCorpus:
    return CORPUS_V2.model_copy(deep=True)


def corpus_v2_hash(corpus: Phase5EvaluationCorpus | None = None) -> str:
    return sha256_hex((corpus or CORPUS_V2).model_dump(mode="json"))
