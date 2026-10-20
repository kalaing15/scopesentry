"""Deterministic catalogue-backed adapters for synthetic local providers."""

from typing import Dict, Iterable, List, Optional

from app.gateway.contracts import normalize_capabilities, normalize_scopes
from app.providers.base import ProviderAdapter
from app.providers.catalog import get_catalog
from app.providers.mock.adapter import UnknownMockGrantError
from app.providers.synthetic.fixtures import get_synthetic_grants
from app.schemas.provider import MockGrant, ProviderMetadata, SimulatedCapabilityAttempt


class SyntheticProviderAdapter(ProviderAdapter):
    provider_name: str
    display_name: str

    def __init__(self, provider_name: str, display_name: str) -> None:
        self.provider_name = provider_name
        self.catalog_provider = provider_name
        self.display_name = display_name
        self._grants: Dict[str, MockGrant] = {}
        self.reset()

    def get_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name=self.provider_name,
            display_name=self.display_name,
            catalog_provider=self.catalog_provider,
            authority_provider_id=self.catalog_provider,
            aliases=[],
            simulation_only=True,
            description="Credential-free deterministic synthetic provider; not a real service integration.",
        )

    def list_grants(self, scenario_id: Optional[str] = None) -> List[MockGrant]:
        values = list(self._grants.values())
        if scenario_id is not None:
            from app.providers.scenario_registry import get_scenario
            scenario = get_scenario(scenario_id)
            allowed = set(scenario.grant_ids) if scenario else set()
            values = [item for item in values if item.grant_id in allowed]
        return [item.model_copy(deep=True) for item in sorted(values, key=lambda item: item.grant_id)]

    def get_grant(self, grant_id: str) -> MockGrant:
        value = self._grants.get(grant_id)
        if value is None:
            raise UnknownMockGrantError(f"Simulated grant '{grant_id}' was not found.")
        return value.model_copy(deep=True)

    def discover_scopes(self, grant_id: str) -> List[str]:
        return normalize_scopes(self.get_grant(grant_id).granted_scopes)

    def resolve_scopes(self, scopes: Iterable[str]) -> List[str]:
        catalog = get_catalog(self.catalog_provider)
        return normalize_capabilities(
            capability for scope in normalize_scopes(scopes)
            for capability in catalog.get(scope, ())
        )

    def get_observed_scopes(self, grant_id: str) -> List[str]:
        return normalize_scopes(self.get_grant(grant_id).observed_scopes)

    def simulate_capability_attempt(self, grant_id: str, attempted_capability: str) -> SimulatedCapabilityAttempt:
        grant = self.get_grant(grant_id)
        observed = self.get_observed_scopes(grant_id)
        enabled = self.resolve_scopes(observed)
        attempted = normalize_capabilities([attempted_capability])[0]
        allowed = grant.status != "revoked" and attempted in enabled
        return SimulatedCapabilityAttempt(
            grant_id=grant.grant_id,
            attempted_capability=attempted,
            provider_would_allow=allowed,
            enabled_capabilities=enabled,
            observed_scopes=observed,
            grant_status=grant.status,
            explanation="The synthetic provider would allow the capability." if allowed else "The synthetic provider would not allow the capability.",
            authority_provider=grant.authority_provider,
            principal_id=grant.principal_id,
        )

    def reset(self) -> None:
        self._grants = get_synthetic_grants(self.provider_name)


class MockEnterpriseProviderAdapter(SyntheticProviderAdapter):
    def __init__(self) -> None:
        super().__init__("mock-enterprise", "Synthetic Enterprise Provider")


class MockCodeHostProviderAdapter(SyntheticProviderAdapter):
    def __init__(self) -> None:
        super().__init__("mock-code-host", "Synthetic Code Host Provider")
