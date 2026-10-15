"""Thread-safe, process-local capability-contract repository.

This in-memory implementation is deliberately limited to the credential-free
PoC. Contracts disappear when the process exits and will be moved to
persistent storage in a later milestone.
"""

import threading
from typing import Dict, List, Optional

from app.schemas.gateway import CapabilityContract, ContractState


class ContractRepository:
    """Store defensive copies of contracts behind an in-process lock."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._contracts: Dict[str, CapabilityContract] = {}

    @staticmethod
    def _copy(contract: CapabilityContract) -> CapabilityContract:
        return contract.model_copy(deep=True)

    def create(self, contract: CapabilityContract) -> CapabilityContract:
        with self._lock:
            if contract.contract_id in self._contracts:
                raise ValueError(
                    f"Contract '{contract.contract_id}' already exists."
                )
            self._contracts[contract.contract_id] = self._copy(contract)
            return self._copy(contract)

    def get(self, contract_id: str) -> Optional[CapabilityContract]:
        with self._lock:
            contract = self._contracts.get(contract_id)
            return self._copy(contract) if contract is not None else None

    def update_state(
        self,
        contract_id: str,
        state: ContractState,
    ) -> Optional[CapabilityContract]:
        with self._lock:
            contract = self._contracts.get(contract_id)
            if contract is None:
                return None
            updated = contract.model_copy(update={"state": state}, deep=True)
            self._contracts[contract_id] = updated
            return self._copy(updated)

    def revoke(self, contract_id: str) -> Optional[CapabilityContract]:
        """Idempotently set a known contract to the revoked state."""
        with self._lock:
            contract = self._contracts.get(contract_id)
            if contract is None:
                return None
            if contract.state != "revoked":
                contract = contract.model_copy(
                    update={"state": "revoked"},
                    deep=True,
                )
                self._contracts[contract_id] = contract
            return self._copy(contract)

    def list(self, limit: int = 20) -> List[CapabilityContract]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        with self._lock:
            contracts = sorted(
                self._contracts.values(),
                key=lambda item: (item.created_at, item.contract_id),
                reverse=True,
            )[:limit]
            return [self._copy(contract) for contract in contracts]

    def reset(self) -> None:
        with self._lock:
            self._contracts.clear()


_default_repository = ContractRepository()


def get_contract_repository() -> ContractRepository:
    """FastAPI dependency returning the current process-local repository."""
    return _default_repository


def replace_contract_repository(repository: ContractRepository) -> None:
    """Replace the default repository, primarily for isolated tests."""
    global _default_repository
    _default_repository = repository


def reset_contract_repository() -> None:
    """Reset the default repository to a fresh empty instance."""
    replace_contract_repository(ContractRepository())
