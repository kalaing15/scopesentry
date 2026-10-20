"""Atomic aggregate registry for legacy and synthetic demo scenarios."""

from typing import List

from app.providers.catalog import resolve_authority_provider_id
from app.providers.catalog import get_catalog
from app.providers.mock.scenarios import get_grant_fixtures, list_scenarios as list_google
from app.providers.synthetic.fixtures import (
    get_synthetic_grants,
    list_synthetic_scenarios,
)
from app.schemas.provider import DemoScenarioDefinition, ProviderIntentAssignment


_GRANTS = {**get_grant_fixtures(), **get_synthetic_grants()}
if len(_GRANTS) != len(get_grant_fixtures()) + len(get_synthetic_grants()):
    raise ValueError("Demo grant IDs must be globally unique")


def _enrich(scenario: DemoScenarioDefinition) -> DemoScenarioDefinition:
    data = scenario.model_dump(mode="python")
    data["expected_values"] = scenario.expected_values.model_dump(
        mode="python", exclude_unset=True
    )
    if not data["providers"]:
        data["providers"] = [resolve_authority_provider_id(scenario.provider)]
    if not data["provider_intents"]:
        data["provider_intents"] = [
            ProviderIntentAssignment(
                provider=data["providers"][0],
                intended_actions=scenario.intended_actions,
            ).model_dump(mode="python")
        ]
    return DemoScenarioDefinition.model_validate(data)


_SCENARIOS = {
    item.scenario_id: _enrich(item)
    for item in [*list_google(), *list_synthetic_scenarios()]
}
if len(_SCENARIOS) != len(list_google()) + len(list_synthetic_scenarios()):
    raise ValueError("Demo scenario IDs must be globally unique")


def _validate_qualified_references() -> None:
    """Validate all identity-bearing references before exposing the registry."""
    for scenario in _SCENARIOS.values():
        scenario_grants = {grant_id: _GRANTS[grant_id] for grant_id in scenario.grant_ids}
        for assignment in scenario.provider_intents:
            matches = [
                grant for grant in scenario_grants.values()
                if grant.authority_provider == assignment.provider
                and (
                    assignment.principal_id is None
                    or grant.principal_id == assignment.principal_id
                )
            ]
            # A provider intent may deliberately have no matching grant to
            # demonstrate fail-closed missing or wrong-provider authority.
        for link in scenario.data_flow_links:
            source = scenario_grants[link.source_grant_id]
            target = scenario_grants[link.target_grant_id]
            for capability, grant, role in (
                (link.source_capability, source, "source"),
                (link.target_capability, target, "target"),
            ):
                if capability is None:
                    continue  # Legacy fixtures are adapted without changing serialized output.
                enabled = {
                    item
                    for scope in grant.granted_scopes
                    for item in get_catalog(grant.authority_provider or grant.provider).get(scope, ())
                }
                if capability not in enabled:
                    raise ValueError(
                        f"Scenario '{scenario.scenario_id}' link '{link.link_id}' has an invalid {role} capability"
                    )
        for flow in scenario.authorized_flows:
            source = scenario_grants[flow.source_grant_id]
            target = scenario_grants[flow.target_grant_id]
            expected = (
                (source.authority_provider, source.principal_id),
                (target.authority_provider, target.principal_id),
            )
            observed = (
                (flow.source_provider, flow.source_principal_id),
                (flow.target_provider, flow.target_principal_id),
            )
            if observed != expected:
                raise ValueError(
                    f"Scenario '{scenario.scenario_id}' flow authorization '{flow.authorization_id}' has mismatched provider/principal identity"
                )


_validate_qualified_references()


def list_scenarios() -> List[DemoScenarioDefinition]:
    return [_SCENARIOS[key].model_copy(deep=True) for key in sorted(_SCENARIOS)]


def get_scenario(scenario_id: str) -> DemoScenarioDefinition | None:
    value = _SCENARIOS.get(scenario_id)
    return value.model_copy(deep=True) if value else None


def get_grant(grant_id: str):
    value = _GRANTS.get(grant_id)
    if value is None:
        raise LookupError(f"Simulated grant '{grant_id}' was not found")
    return value.model_copy(deep=True)


def grant_adapter_id(grant_id: str) -> str:
    return get_grant(grant_id).provider
