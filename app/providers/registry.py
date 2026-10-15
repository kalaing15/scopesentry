"""Thread-safe provider-adapter registration and lookup."""

import threading
from typing import Dict, List

from app.providers.base import ProviderAdapter
from app.providers.mock.adapter import MockGoogleProviderAdapter
from app.schemas.provider import ProviderMetadata


class UnsupportedProviderError(LookupError):
    pass


class DuplicateProviderError(ValueError):
    pass


class ProviderRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._adapters: Dict[str, ProviderAdapter] = {}

    @staticmethod
    def _normalize(provider_name: str) -> str:
        return provider_name.strip().lower()

    def register(self, adapter: ProviderAdapter) -> None:
        name = self._normalize(adapter.get_metadata().provider_name)
        if not name:
            raise ValueError("Provider name must not be blank.")
        with self._lock:
            if name in self._adapters:
                raise DuplicateProviderError(
                    f"Provider adapter '{name}' is already registered."
                )
            self._adapters[name] = adapter

    def get(self, provider_name: str) -> ProviderAdapter:
        name = self._normalize(provider_name)
        with self._lock:
            adapter = self._adapters.get(name)
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
