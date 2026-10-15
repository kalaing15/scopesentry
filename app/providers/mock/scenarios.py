"""Deterministic, credential-free provider grants and demo scenarios."""

from typing import Dict, List, Mapping

from pydantic import ValidationError

from app.providers.mock.catalog import get_catalog
from app.schemas.provider import DemoScenarioDefinition, MockGrant


_GRANT_FIXTURES = {
    "safe-reader-grant": {
        "grant_id": "safe-reader-grant",
        "application_name": "Safe File Reader",
        "provider": "mock-google",
        "declared_intended_actions": ["read files"],
        "granted_scopes": ["drive.readonly"],
        "observed_scopes": ["drive.readonly"],
        "status": "active",
        "description": "A file reader with only normalized Drive read access.",
    },
    "overprivileged-reader-grant": {
        "grant_id": "overprivileged-reader-grant",
        "application_name": "Overprivileged File Reader",
        "provider": "mock-google",
        "declared_intended_actions": ["read files"],
        "granted_scopes": ["drive.readonly", "gmail.readonly"],
        "observed_scopes": ["drive.readonly", "gmail.readonly"],
        "status": "active",
        "description": "A file reader that also exposes unnecessary email access.",
    },
    "runtime-drift-grant": {
        "grant_id": "runtime-drift-grant",
        "application_name": "Drifted File Reader",
        "provider": "mock-google",
        "declared_intended_actions": ["read files"],
        "granted_scopes": ["drive.readonly"],
        "observed_scopes": ["drive.readonly", "gmail.send"],
        "status": "drifted",
        "description": "A file reader whose runtime authority gained email sending.",
    },
    "composed-reader-grant": {
        "grant_id": "composed-reader-grant",
        "application_name": "Composition File Reader",
        "provider": "mock-google",
        "declared_intended_actions": ["read files"],
        "granted_scopes": ["drive.readonly"],
        "observed_scopes": ["drive.readonly"],
        "status": "active",
        "description": "Reads simulated Drive content for a composed workflow.",
    },
    "composed-mailer-grant": {
        "grant_id": "composed-mailer-grant",
        "application_name": "Composition Mail Sender",
        "provider": "mock-google",
        "declared_intended_actions": [],
        "granted_scopes": ["gmail.send"],
        "observed_scopes": ["gmail.send"],
        "status": "active",
        "description": "Can send email despite that action not being intended.",
    },
    "missing-permission-grant": {
        "grant_id": "missing-permission-grant",
        "application_name": "Underprivileged Mail Sender",
        "provider": "mock-google",
        "declared_intended_actions": ["send email"],
        "granted_scopes": ["drive.readonly"],
        "observed_scopes": ["drive.readonly"],
        "status": "active",
        "description": "Requests email sending but has only Drive read access.",
    },
}


_SCENARIO_FIXTURES = {
    "safe-file-reader": {
        "scenario_id": "safe-file-reader",
        "scenario_name": "Safe file reader",
        "description": "A correctly scoped file-reading workflow.",
        "provider": "mock-google",
        "risk_category": "low",
        "intended_actions": ["read files"],
        "grant_ids": ["safe-reader-grant"],
        "runtime_attempts": [
            {
                "grant_id": "safe-reader-grant",
                "capability": "read_file_contents",
                "resource_reference": "mock-drive:file-001",
            }
        ],
        "expected_outcome": "Drive reading is allowed without excess scope.",
        "expected_values": {"decision": "allow", "excessive_scopes": []},
    },
    "overprivileged-file-reader": {
        "scenario_id": "overprivileged-file-reader",
        "scenario_name": "Overprivileged file reader",
        "description": "Unnecessary email-reading authority is removed.",
        "provider": "mock-google",
        "risk_category": "excessive_authority",
        "intended_actions": ["read files"],
        "grant_ids": ["overprivileged-reader-grant"],
        "runtime_attempts": [
            {
                "grant_id": "overprivileged-reader-grant",
                "capability": "read_email_messages",
                "resource_reference": "mock-mail:message-001",
            }
        ],
        "expected_outcome": (
            "Gmail read access is excessive and the runtime attempt is "
            "blocked or quarantined."
        ),
        "expected_values": {
            "excessive_scope": "gmail.readonly",
            "selected_scopes": ["drive.readonly"],
            "decisions": ["block", "quarantine"],
        },
    },
    "runtime-scope-drift": {
        "scenario_id": "runtime-scope-drift",
        "scenario_name": "Runtime scope drift",
        "description": "Unexpected email-send authority appears at runtime.",
        "provider": "mock-google",
        "risk_category": "runtime_drift",
        "intended_actions": ["read files"],
        "grant_ids": ["runtime-drift-grant"],
        "runtime_attempts": [
            {
                "grant_id": "runtime-drift-grant",
                "capability": "send_email_messages",
                "resource_reference": "mock-mail:outbound-001",
            }
        ],
        "expected_outcome": "Scope drift quarantines the capability contract.",
        "expected_values": {
            "decision": "quarantine",
            "contract_state": "quarantined",
        },
    },
    "composed-exfiltration-path": {
        "scenario_id": "composed-exfiltration-path",
        "scenario_name": "Composed exfiltration path",
        "description": "Separate read and send grants compose into a data path.",
        "provider": "mock-google",
        "risk_category": "composition_risk",
        "intended_actions": ["read files"],
        "grant_ids": ["composed-reader-grant", "composed-mailer-grant"],
        "data_flow_links": [
            {
                "link_id": "drive-read-to-email-send",
                "source_grant_id": "composed-reader-grant",
                "target_grant_id": "composed-mailer-grant",
                "data_type": "drive_file_contents",
                "description": "Read file data can flow into outbound email.",
            }
        ],
        "expected_outcome": (
            "An unauthorized Drive-read-to-email-send path is detected."
        ),
        "expected_values": {"unauthorized_path_count": 1},
    },
    "missing-required-permission": {
        "scenario_id": "missing-required-permission",
        "scenario_name": "Missing required permission",
        "description": "Email sending is intended but its scope is absent.",
        "provider": "mock-google",
        "risk_category": "missing_permission",
        "intended_actions": ["send email"],
        "grant_ids": ["missing-permission-grant"],
        "expected_outcome": (
            "The missing Gmail send capability and required scope are reported."
        ),
        "expected_values": {
            "missing_scope": "gmail.send",
            "scope_to_add": "gmail.send",
        },
    },
}


class MockFixtureValidationError(ValueError):
    """Raised when deterministic fixture configuration fails closed."""


def validate_grant_fixture(grant_id: str, payload: object) -> MockGrant:
    """Validate one static grant, including strict catalogue membership."""
    try:
        grant = MockGrant.model_validate(payload)
    except ValidationError as exc:
        raise MockFixtureValidationError(
            f"Invalid mock grant '{grant_id}': {exc}"
        ) from exc
    if grant.grant_id != grant_id:
        raise MockFixtureValidationError(
            f"Invalid mock grant '{grant_id}': payload grant_id is "
            f"'{grant.grant_id}'"
        )

    catalog = get_catalog("google")
    unknown_scopes = sorted(
        (set(grant.granted_scopes) | set(grant.observed_scopes)) - set(catalog)
    )
    if unknown_scopes:
        raise MockFixtureValidationError(
            f"Invalid mock grant '{grant_id}': unknown catalogue scopes "
            f"{unknown_scopes}"
        )
    return grant


def validate_scenario_fixture(
    scenario_id: str,
    payload: object,
    available_grants: Mapping[str, MockGrant],
) -> DemoScenarioDefinition:
    """Validate a scenario and every reference before it can be exposed."""
    try:
        scenario = DemoScenarioDefinition.model_validate(payload)
    except ValidationError as exc:
        raise MockFixtureValidationError(
            f"Invalid scenario '{scenario_id}': {exc}"
        ) from exc
    if scenario.scenario_id != scenario_id:
        raise MockFixtureValidationError(
            f"Invalid scenario '{scenario_id}': payload scenario_id is "
            f"'{scenario.scenario_id}'"
        )

    unknown_grants = sorted(set(scenario.grant_ids) - set(available_grants))
    if unknown_grants:
        raise MockFixtureValidationError(
            f"Invalid scenario '{scenario_id}': declared grants are absent from "
            f"the mock grant catalogue: {unknown_grants}"
        )

    catalog = get_catalog("google")
    supported_capabilities = {
        capability
        for capabilities in catalog.values()
        for capability in capabilities
    }
    invalid_capabilities = sorted(
        {
            attempt.capability
            for attempt in scenario.runtime_attempts
            if attempt.capability not in supported_capabilities
        }
    )
    if invalid_capabilities:
        raise MockFixtureValidationError(
            f"Invalid scenario '{scenario_id}': unsupported runtime "
            f"capabilities {invalid_capabilities}"
        )
    return scenario


def _build_validated_fixture_registry() -> tuple[
    Dict[str, MockGrant], Dict[str, DemoScenarioDefinition]
]:
    """Build both registries locally, publishing neither on any failure."""
    grants = {
        grant_id: validate_grant_fixture(grant_id, payload)
        for grant_id, payload in _GRANT_FIXTURES.items()
    }
    scenarios = {
        scenario_id: validate_scenario_fixture(scenario_id, payload, grants)
        for scenario_id, payload in _SCENARIO_FIXTURES.items()
    }
    return grants, scenarios


_VALIDATED_GRANTS, _VALIDATED_SCENARIOS = _build_validated_fixture_registry()


def get_grant_fixtures() -> Dict[str, MockGrant]:
    """Return deep copies so callers cannot mutate fixture state."""
    return {
        grant_id: grant.model_copy(deep=True)
        for grant_id, grant in _VALIDATED_GRANTS.items()
    }


def list_scenarios() -> List[DemoScenarioDefinition]:
    return [
        _VALIDATED_SCENARIOS[scenario_id].model_copy(deep=True)
        for scenario_id in sorted(_VALIDATED_SCENARIOS)
    ]


def get_scenario(scenario_id: str) -> DemoScenarioDefinition | None:
    scenario = _VALIDATED_SCENARIOS.get(scenario_id)
    return scenario.model_copy(deep=True) if scenario else None
