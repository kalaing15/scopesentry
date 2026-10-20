"""Thread-safe provider-adapter registration and lookup."""

import threading
from typing import Dict, List

from app.providers.base import ProviderAdapter
from app.providers.mock.adapter import MockGoogleProviderAdapter
from app.providers.catalog import get_provider_catalogue, resolve_authority_provider_id
from app.schemas.provider import ProviderMetadata
from app.providers.synthetic.adapter import (
    MockCodeHostProviderAdapter,
    MockEnterpriseProviderAdapter,
)


class UnsupportedProviderError(LookupError):
    pass


class DuplicateProviderError(ValueError):
    pass


class ProviderRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._adapters: Dict[str, ProviderAdapter] = {}
        self._aliases: Dict[str, str] = {}
        self._canonical_ids: Dict[str, str] = {}

    @staticmethod
    def _normalize(provider_name: str) -> str:
        return provider_name.strip().lower()

    def register(self, adapter: ProviderAdapter) -> None:
        metadata = adapter.get_metadata()
        name = self._normalize(metadata.provider_name)
        if not name:
            raise ValueError("Provider name must not be blank.")
        with self._lock:
            canonical = resolve_authority_provider_id(metadata.authority_provider_id)
            get_provider_catalogue(canonical)
            if resolve_authority_provider_id(metadata.catalog_provider) != canonical:
                raise ValueError("Adapter/catalogue identity mismatch")
            if name in self._adapters or name in self._aliases:
                raise DuplicateProviderError(
                    f"Provider adapter '{name}' is already registered."
                )
            if canonical in self._canonical_ids:
                raise DuplicateProviderError(
                    f"Canonical provider '{canonical}' is already registered."
                )
            aliases = {self._normalize(alias) for alias in metadata.aliases}
            aliases.add(canonical)
            for alias in aliases:
                owner = self._aliases.get(alias)
                if alias in self._adapters or (owner is not None and owner != name):
                    raise DuplicateProviderError(f"Provider alias '{alias}' is ambiguous.")
            self._adapters[name] = adapter
            self._canonical_ids[canonical] = name
            for alias in aliases:
                self._aliases[alias] = name

    def get(self, provider_name: str) -> ProviderAdapter:
        name = self._normalize(provider_name)
        with self._lock:
            adapter = self._adapters.get(name)
            if adapter is None and name in self._aliases:
                adapter = self._adapters.get(self._aliases[name])
            if adapter is None:
                raise UnsupportedProviderError(
                    f"Unsupported simulated provider '{provider_name}'. "
                    f"Supported providers: {list(self.names())}"
                )
            return adapter

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._adapters))

    def list_metadata(self) -> List[ProviderMetadata]:
        with self._lock:
            return [
                self._adapters[name].get_metadata().model_copy(deep=True)
                for name in sorted(self._adapters)
            ]


_provider_registry = ProviderRegistry()
_provider_registry.register(MockGoogleProviderAdapter())
_provider_registry.register(MockEnterpriseProviderAdapter())
_provider_registry.register(MockCodeHostProviderAdapter())


def get_provider_registry() -> ProviderRegistry:
    return _provider_registry


def register_provider(adapter: ProviderAdapter) -> None:
    """Register an adapter in the application registry."""
    _provider_registry.register(adapter)


def get_provider_adapter(provider_name: str) -> ProviderAdapter:
    """Retrieve an adapter from the application registry."""
    return _provider_registry.get(provider_name)


def list_supported_providers() -> tuple[str, ...]:
    """Return an immutable, deterministically ordered provider-name tuple."""
    return _provider_registry.names()
