"""Credential-free Google-compatible provider simulation adapter."""

import threading
from typing import Dict, Iterable, List, Optional

from app.gateway.contracts import normalize_capabilities, normalize_scopes
from app.providers.base import ProviderAdapter
from app.providers.mock.catalog import get_catalog
from app.providers.mock.scenarios import get_grant_fixtures, get_scenario
from app.schemas.provider import (
    MockGrant,
    ProviderMetadata,
    SimulatedCapabilityAttempt,
)


class UnknownMockGrantError(LookupError):
    pass


class MockGoogleProviderAdapter(ProviderAdapter):
    """In-memory simulation backed by the normalized Google mock catalogue."""

    provider_name = "mock-google"
    catalog_provider = "google"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._grants: Dict[str, MockGrant] = {}
        self.reset()

    @staticmethod
    def _copy(grant: MockGrant) -> MockGrant:
        return grant.model_copy(deep=True)

    def get_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name=self.provider_name,
            display_name="Mock Google-Compatible Provider",
            catalog_provider=self.catalog_provider,
            authority_provider_id=self.catalog_provider,
            aliases=["google"],
            simulation_only=True,
            description=(
                "Credential-free deterministic simulator using internal "
                "normalized aliases, not a real Google OAuth integration."
            ),
        )

    def list_grants(self, scenario_id: Optional[str] = None) -> List[MockGrant]:
        with self._lock:
            if scenario_id is None:
                grant_ids = sorted(self._grants)
            else:
                scenario = get_scenario(scenario_id)
                if scenario is None:
                    return []
                grant_ids = scenario.grant_ids
            return [self._copy(self._grants[grant_id]) for grant_id in grant_ids]

    def get_grant(self, grant_id: str) -> MockGrant:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise UnknownMockGrantError(
                    f"Simulated grant '{grant_id}' was not found."
                )
            return self._copy(grant)

    def discover_scopes(self, grant_id: str) -> List[str]:
        return normalize_scopes(self.get_grant(grant_id).granted_scopes)

    def resolve_scopes(self, scopes: Iterable[str]) -> List[str]:
        catalog = get_catalog(self.catalog_provider)
        return normalize_capabilities(
            capability
            for scope in normalize_scopes(scopes)
            for capability in catalog.get(scope, [])
        )

    def get_observed_scopes(self, grant_id: str) -> List[str]:
        return normalize_scopes(self.get_grant(grant_id).observed_scopes)

    def simulate_capability_attempt(
        self,
        grant_id: str,
        attempted_capability: str,
    ) -> SimulatedCapabilityAttempt:
        grant = self.get_grant(grant_id)
        observed = normalize_scopes(grant.observed_scopes)
        enabled = self.resolve_scopes(observed)
        normalized = normalize_capabilities([attempted_capability])
        attempted = normalized[0] if normalized else ""
        allowed = grant.status != "revoked" and attempted in enabled
        return SimulatedCapabilityAttempt(
            grant_id=grant.grant_id,
            attempted_capability=attempted,
            provider_would_allow=allowed,
            enabled_capabilities=enabled,
            observed_scopes=observed,
            grant_status=grant.status,
            explanation=(
                "The simulated provider would allow this capability from "
                "the observed normalized scopes."
                if allowed
                else "The simulated provider would not allow this capability."
            ),
            authority_provider=grant.authority_provider,
            principal_id=grant.principal_id,
        )

    def reset(self) -> None:
        with self._lock:
            self._grants = {
                grant_id: grant.model_copy(deep=True)
                for grant_id, grant in get_grant_fixtures().items()
            }
