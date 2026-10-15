"""Capability-contract construction and normalization helpers."""

from datetime import datetime, timedelta, timezone
from typing import Iterable, List
from uuid import uuid4

from app.evidence.canonical import sha256_hex
from app.planner.intent_mapper import normalize_intent
from app.schemas.gateway import CapabilityContract


POLICY_VERSION = "1.0.0"


def normalize_scopes(scopes: Iterable[str]) -> List[str]:
    """Return normalized, deduplicated scopes in deterministic order."""
    return sorted({scope.strip().lower() for scope in scopes if scope.strip()})


def normalize_capabilities(capabilities: Iterable[str]) -> List[str]:
    """Return normalized, deduplicated capabilities in deterministic order."""
    return sorted(
        {
            capability.strip().lower()
            for capability in capabilities
            if capability.strip()
        }
    )


def calculate_scope_fingerprint(scopes: Iterable[str]) -> str:
    """Hash the canonical normalized and alphabetically sorted scope list."""
    return sha256_hex(normalize_scopes(scopes))


def build_contract_payload(
    *,
    provider: str,
    intended_actions: Iterable[str],
    allowed_scopes: Iterable[str],
    allowed_capabilities: Iterable[str],
    ttl_seconds: int,
    now: datetime | None = None,
) -> dict:
    """Build the non-circular contract fields used in creation evidence."""
    created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    normalized_scopes = normalize_scopes(allowed_scopes)
    return {
        "contract_id": str(uuid4()),
        "provider": provider.strip().lower(),
        "intended_actions": sorted(
            {normalize_intent(action) for action in intended_actions}
        ),
        "allowed_scopes": normalized_scopes,
        "allowed_capabilities": normalize_capabilities(allowed_capabilities),
        "scope_fingerprint": calculate_scope_fingerprint(normalized_scopes),
        "created_at": created_at,
        "expires_at": created_at + timedelta(seconds=ttl_seconds),
        "state": "active",
        "policy_version": POLICY_VERSION,
    }


def finalize_contract(
    payload: dict,
    *,
    source_analysis_id: str,
    source_evidence_hash: str,
) -> CapabilityContract:
    """Attach the creation-evidence reference to a contract payload."""
    return CapabilityContract(
        **payload,
        source_analysis_id=source_analysis_id,
        source_evidence_hash=source_evidence_hash,
    )
