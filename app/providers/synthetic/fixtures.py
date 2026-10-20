"""Synthetic enterprise/code-host grants and provider-aware scenarios."""

from typing import Dict, List

from app.providers.catalog import get_catalog
from app.schemas.provider import DemoScenarioDefinition, MockGrant


_GRANTS = {
    "enterprise-safe-reader": {"application_name": "Enterprise Safe Reader", "provider": "mock-enterprise", "principal_id": "enterprise-demo", "declared_intended_actions": ["read files"], "granted_scopes": ["content.read"], "observed_scopes": ["content.read"], "status": "active", "description": "Synthetic enterprise reader."},
    "enterprise-over-reader": {"application_name": "Enterprise Broad Reader", "provider": "mock-enterprise", "principal_id": "enterprise-demo", "declared_intended_actions": ["read files"], "granted_scopes": ["authority.full"], "observed_scopes": ["authority.full"], "status": "active", "description": "Synthetic broad enterprise authority."},
    "enterprise-drift-reader": {"application_name": "Enterprise Drift Reader", "provider": "mock-enterprise", "principal_id": "enterprise-demo", "declared_intended_actions": ["read files"], "granted_scopes": ["content.read"], "observed_scopes": ["content.read", "mail.send"], "status": "drifted", "description": "Synthetic enterprise runtime drift."},
    "code-safe-reader": {"application_name": "Code Safe Reader", "provider": "mock-code-host", "principal_id": "code-demo", "declared_intended_actions": ["read repositories"], "granted_scopes": ["content.read"], "observed_scopes": ["content.read"], "status": "active", "description": "Synthetic repository reader."},
    "code-webhook-reader": {"application_name": "Code Webhook Reader", "provider": "mock-code-host", "principal_id": "code-demo", "declared_intended_actions": ["read repositories"], "granted_scopes": ["content.read", "webhooks.manage"], "observed_scopes": ["content.read", "webhooks.manage"], "status": "active", "description": "Repository reader with unnecessary webhook authority."},
    "enterprise-collision-reader": {"application_name": "Enterprise Collision Reader", "provider": "mock-enterprise", "principal_id": "collision-principal", "declared_intended_actions": ["read files"], "granted_scopes": ["content.read"], "observed_scopes": ["content.read"], "status": "active", "description": "Enterprise half of a textual scope collision."},
    "enterprise-profile": {"application_name": "Enterprise Profile", "provider": "mock-enterprise", "principal_id": "collision-principal", "declared_intended_actions": ["read profile"], "granted_scopes": ["profile.read"], "observed_scopes": ["profile.read"], "status": "active", "description": "Enterprise profile capability collision fixture."},
    "cross-enterprise-reader": {"application_name": "Cross Enterprise Reader", "provider": "mock-enterprise", "principal_id": "cross-demo", "declared_intended_actions": ["read files"], "granted_scopes": ["content.read"], "observed_scopes": ["content.read"], "status": "active", "description": "Cross-provider source grant."},
    "cross-code-issues": {"application_name": "Cross Code Issues", "provider": "mock-code-host", "principal_id": "cross-demo", "declared_intended_actions": ["create issues"], "granted_scopes": ["issues.write"], "observed_scopes": ["issues.write"], "status": "active", "description": "Authorized cross-provider issue destination."},
    "cross-code-webhook": {"application_name": "Cross Code Webhook", "provider": "mock-code-host", "principal_id": "cross-demo", "declared_intended_actions": [], "granted_scopes": ["webhooks.manage"], "observed_scopes": ["webhooks.manage"], "status": "active", "description": "Unauthorized external webhook destination."},
}
for _grant_id, _payload in _GRANTS.items():
    _payload["grant_id"] = _grant_id


_SCENARIOS = {
    "safe-enterprise-file-reader": {"scenario_name": "Safe enterprise file reader", "description": "Exact synthetic enterprise file-read authority.", "provider": "mock-enterprise", "providers": ["mock-enterprise"], "risk_category": "low", "intended_actions": ["read files"], "provider_intents": [{"provider": "mock-enterprise", "intended_actions": ["read files"]}], "grant_ids": ["enterprise-safe-reader"], "runtime_attempts": [{"grant_id": "enterprise-safe-reader", "capability": "read_sensitive_file_contents"}], "expected_outcome": "Enterprise file reading is allowed.", "expected_values": {"decision": "allow", "excessive_scopes": []}},
    "overprivileged-enterprise-file-reader": {"scenario_name": "Overprivileged enterprise file reader", "description": "Broad enterprise authority is reduced.", "provider": "mock-enterprise", "providers": ["mock-enterprise"], "risk_category": "excessive_authority", "intended_actions": ["read files"], "provider_intents": [{"provider": "mock-enterprise", "intended_actions": ["read files"]}], "grant_ids": ["enterprise-over-reader"], "runtime_attempts": [{"grant_id": "enterprise-over-reader", "capability": "read_sensitive_file_contents"}], "expected_outcome": "Broad authority is rejected until the synthesized narrow scope is granted.", "expected_values": {"excessive_scope": "authority.full", "selected_scopes": ["content.read"], "scope_to_add": "content.read"}},
    "enterprise-runtime-drift": {"scenario_name": "Enterprise runtime scope drift", "description": "Mail-send authority appears during file reading.", "provider": "mock-enterprise", "providers": ["mock-enterprise"], "risk_category": "runtime_drift", "intended_actions": ["read files"], "provider_intents": [{"provider": "mock-enterprise", "intended_actions": ["read files"]}], "grant_ids": ["enterprise-drift-reader"], "runtime_attempts": [{"grant_id": "enterprise-drift-reader", "capability": "send_enterprise_messages"}], "expected_outcome": "Enterprise scope drift quarantines the contract.", "expected_values": {"decision": "quarantine", "contract_state": "quarantined"}},
    "safe-code-repository-reader": {"scenario_name": "Safe code repository reader", "description": "Exact synthetic repository-read authority.", "provider": "mock-code-host", "providers": ["mock-code-host"], "risk_category": "low", "intended_actions": ["read repositories"], "provider_intents": [{"provider": "mock-code-host", "intended_actions": ["read repositories"]}], "grant_ids": ["code-safe-reader"], "runtime_attempts": [{"grant_id": "code-safe-reader", "capability": "read_repository_contents"}], "expected_outcome": "Repository reading is allowed.", "expected_values": {"decision": "allow", "excessive_scopes": []}},
    "excessive-code-webhook-authority": {"scenario_name": "Excessive code-host webhook authority", "description": "Webhook configuration is unrelated to repository reading.", "provider": "mock-code-host", "providers": ["mock-code-host"], "risk_category": "excessive_authority", "intended_actions": ["read repositories"], "provider_intents": [{"provider": "mock-code-host", "intended_actions": ["read repositories"]}], "grant_ids": ["code-webhook-reader"], "runtime_attempts": [{"grant_id": "code-webhook-reader", "capability": "configure_external_webhooks"}], "expected_outcome": "Unexpected webhook authority quarantines the contract.", "expected_values": {"excessive_scope": "webhooks.manage", "decision": "quarantine"}},
    "wrong-provider-scope-collision": {"scenario_name": "Wrong-provider scope collision", "description": "Enterprise content.read cannot satisfy code-host repository intent.", "provider": "mock-code-host", "providers": ["mock-enterprise", "mock-code-host"], "risk_category": "provider_collision", "intended_actions": ["read repositories"], "provider_intents": [{"provider": "mock-code-host", "principal_id": "collision-principal", "intended_actions": ["read repositories"]}], "grant_ids": ["enterprise-collision-reader"], "expected_outcome": "Wrong-provider textual scope collision is rejected.", "expected_values": {"missing_scope": "content.read", "scope_to_add": "content.read"}},
    "same-name-capability-collision": {"scenario_name": "Same-name capability collision", "description": "Enterprise read_profile cannot satisfy code-host profile intent.", "provider": "mock-code-host", "providers": ["mock-enterprise", "mock-code-host"], "risk_category": "provider_collision", "intended_actions": ["read profile"], "provider_intents": [{"provider": "mock-code-host", "principal_id": "collision-principal", "intended_actions": ["read profile"]}], "grant_ids": ["enterprise-profile"], "expected_outcome": "Same-name capabilities remain provider isolated.", "expected_values": {"missing_scope": "profile.read", "scope_to_add": "profile.read"}},
    "safe-authorized-cross-provider-workflow": {"scenario_name": "Safe authorized cross-provider workflow", "description": "Enterprise content reaches issue creation under an exact flow authorization.", "provider": "mock-enterprise", "providers": ["mock-enterprise", "mock-code-host"], "risk_category": "cross_provider", "intended_actions": ["read files", "create issues"], "provider_intents": [{"provider": "mock-enterprise", "principal_id": "cross-demo", "intended_actions": ["read files"]}, {"provider": "mock-code-host", "principal_id": "cross-demo", "intended_actions": ["create issues"]}], "grant_ids": ["cross-enterprise-reader", "cross-code-issues"], "runtime_attempts": [{"grant_id": "cross-enterprise-reader", "capability": "read_sensitive_file_contents"}, {"grant_id": "cross-code-issues", "capability": "create_issues"}], "data_flow_links": [{"link_id": "authorized-enterprise-to-issue", "source_provider": "mock-enterprise", "source_principal_id": "cross-demo", "source_grant_id": "cross-enterprise-reader", "target_provider": "mock-code-host", "target_principal_id": "cross-demo", "target_grant_id": "cross-code-issues", "source_capability": "read_sensitive_file_contents", "target_capability": "create_issues", "data_type": "enterprise_file_contents", "description": "Observed authorized issue-creation flow."}], "authorized_flows": [{"authorization_id": "allow-enterprise-to-issue", "source_provider": "mock-enterprise", "source_principal_id": "cross-demo", "source_grant_id": "cross-enterprise-reader", "source_capability": "read_sensitive_file_contents", "data_type": "enterprise_file_contents", "target_provider": "mock-code-host", "target_principal_id": "cross-demo", "target_grant_id": "cross-code-issues", "target_capability": "create_issues"}], "expected_outcome": "Exact provider-qualified flow authorization permits separate contracts.", "expected_values": {"unauthorized_path_count": 0}},
    "unauthorized-cross-provider-exfiltration": {"scenario_name": "Unauthorized cross-provider exfiltration", "description": "Sensitive enterprise files can reach an external webhook.", "provider": "mock-enterprise", "providers": ["mock-enterprise", "mock-code-host"], "risk_category": "cross_provider", "intended_actions": ["read files"], "provider_intents": [{"provider": "mock-enterprise", "principal_id": "cross-demo", "intended_actions": ["read files"]}], "grant_ids": ["cross-enterprise-reader", "cross-code-webhook"], "data_flow_links": [{"link_id": "enterprise-to-external-webhook", "source_provider": "mock-enterprise", "source_principal_id": "cross-demo", "source_grant_id": "cross-enterprise-reader", "target_provider": "mock-code-host", "target_principal_id": "cross-demo", "target_grant_id": "cross-code-webhook", "source_capability": "read_sensitive_file_contents", "target_capability": "configure_external_webhooks", "data_type": "sensitive_file_contents", "description": "Observed unauthorized exfiltration path."}], "expected_outcome": "Unauthorized cross-provider flow is detected and execution is skipped.", "expected_values": {"unauthorized_path_count": 1}},
}
for _scenario_id, _payload in _SCENARIOS.items():
    _payload["scenario_id"] = _scenario_id


def _validated_grants() -> Dict[str, MockGrant]:
    result: Dict[str, MockGrant] = {}
    for grant_id, payload in _GRANTS.items():
        grant = MockGrant.model_validate(payload)
        catalog = get_catalog(grant.authority_provider or grant.provider)
        unknown = sorted((set(grant.granted_scopes) | set(grant.observed_scopes)) - set(catalog))
        if unknown:
            raise ValueError(f"Synthetic grant '{grant_id}' has unknown scopes {unknown}")
        result[grant_id] = grant
    return result


_VALIDATED_GRANTS = _validated_grants()
_VALIDATED_SCENARIOS = {
    key: DemoScenarioDefinition.model_validate(value)
    for key, value in _SCENARIOS.items()
}


def get_synthetic_grants(provider: str | None = None) -> Dict[str, MockGrant]:
    return {
        key: value.model_copy(deep=True)
        for key, value in _VALIDATED_GRANTS.items()
        if provider is None or value.provider == provider
    }


def list_synthetic_scenarios() -> List[DemoScenarioDefinition]:
    return [_VALIDATED_SCENARIOS[key].model_copy(deep=True) for key in sorted(_VALIDATED_SCENARIOS)]


def get_synthetic_scenario(scenario_id: str) -> DemoScenarioDefinition | None:
    value = _VALIDATED_SCENARIOS.get(scenario_id)
    return value.model_copy(deep=True) if value else None
