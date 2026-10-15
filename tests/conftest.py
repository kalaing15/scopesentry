"""Suite-wide isolation for file-backed evidence records."""

from pathlib import Path

import pytest

from app.gateway.repository import (
    get_contract_repository,
    reset_contract_repository,
)
from app.providers.registry import get_provider_registry


@pytest.fixture(autouse=True)
def isolated_evidence_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    evidence_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("SCOPESENTRY_EVIDENCE_PATH", str(evidence_path))
    return evidence_path


@pytest.fixture(autouse=True)
def isolated_contract_repository():
    """Give every test a fresh process-local gateway repository."""
    reset_contract_repository()
    repository = get_contract_repository()
    yield repository
    reset_contract_repository()


@pytest.fixture(autouse=True)
def reset_mock_provider_state():
    """Restore deterministic adapter fixtures around every test."""
    registry = get_provider_registry()
    for provider_name in registry.names():
        registry.get(provider_name).reset()
    yield
    for provider_name in registry.names():
        registry.get(provider_name).reset()
