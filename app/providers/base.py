"""Provider-adapter abstraction for credential-free provider simulations."""

from abc import ABC, abstractmethod
from typing import Iterable, List, Optional

from app.schemas.provider import (
    MockGrant,
    ProviderMetadata,
    SimulatedCapabilityAttempt,
)


class ProviderAdapter(ABC):
    """Interface separating provider behaviour from planners and gateways."""

    @abstractmethod
    def get_metadata(self) -> ProviderMetadata:
        """Return immutable metadata describing this provider adapter."""

    @abstractmethod
    def list_grants(self, scenario_id: Optional[str] = None) -> List[MockGrant]:
        """Return copies of the available simulated grants."""

    @abstractmethod
    def get_grant(self, grant_id: str) -> MockGrant:
        """Return a copy of one simulated grant or raise a controlled error."""

    @abstractmethod
    def discover_scopes(self, grant_id: str) -> List[str]:
        """Discover the normalized granted scopes for a simulated grant."""

    @abstractmethod
    def resolve_scopes(self, scopes: Iterable[str]) -> List[str]:
        """Resolve recognized scopes into capabilities."""

    @abstractmethod
    def get_observed_scopes(self, grant_id: str) -> List[str]:
        """Return runtime-observed scopes for the simulated grant."""

    @abstractmethod
    def simulate_capability_attempt(
        self,
        grant_id: str,
        attempted_capability: str,
    ) -> SimulatedCapabilityAttempt:
        """Simulate what the credential-free provider would permit."""

    @abstractmethod
    def reset(self) -> None:
        """Reset only this adapter's in-memory simulation state."""
