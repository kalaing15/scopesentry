"""Deterministic policy evaluation for runtime capability attempts."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Set

from app.gateway.contracts import normalize_capabilities, normalize_scopes
from app.providers.mock.catalog import get_catalog
from app.schemas.gateway import CapabilityContract


def _enabled_capabilities(provider: str, scopes: Iterable[str]) -> Set[str]:
    catalog = get_catalog(provider)
    enabled: Set[str] = set()
    for scope in scopes:
        enabled.update(catalog.get(scope, []))
    return enabled


def evaluate_capability_attempt(
    contract: CapabilityContract,
    *,
    attempted_capability: str,
    observed_scopes: Iterable[str],
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Apply gateway rules in their required precedence order."""
    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    attempted = normalize_capabilities([attempted_capability])
    normalized_attempt = attempted[0] if attempted else ""
    observed = set(normalize_scopes(observed_scopes))
    allowed_scopes = set(contract.allowed_scopes)
    unexpected = sorted(observed - allowed_scopes)
    missing = sorted(allowed_scopes - observed)

    base = {
        "contract_id": contract.contract_id,
        "attempted_capability": normalized_attempt,
        "unexpected_scopes": unexpected,
        "missing_scopes": missing,
        "scope_drift": bool(unexpected or missing),
        "evaluated_at": evaluated_at,
    }

    if contract.state == "revoked":
        return {
            **base,
            "decision": "block",
            "reason_code": "contract_revoked",
            "explanation": "The capability contract has been revoked.",
            "contract_state": "revoked",
            "state_transition": None,
        }

    if contract.state == "quarantined":
        return {
            **base,
            "decision": "block",
            "reason_code": "contract_quarantined",
            "explanation": (
                "The capability contract is quarantined and cannot authorize "
                "runtime actions."
            ),
            "contract_state": "quarantined",
            "state_transition": None,
        }

    if contract.state == "expired" or evaluated_at >= contract.expires_at:
        transition = "expired" if contract.state != "expired" else None
        return {
            **base,
            "decision": "block",
            "reason_code": "contract_expired",
            "explanation": "The capability contract has expired.",
            "contract_state": "expired",
            "state_transition": transition,
        }

    if unexpected:
        return {
            **base,
            "decision": "quarantine",
            "reason_code": "unexpected_scope_drift",
            "explanation": (
                "Observed scopes exceed the contract: "
                f"{', '.join(unexpected)}. The contract is quarantined."
            ),
            "contract_state": "quarantined",
            "state_transition": "quarantined",
        }

    if missing:
        return {
            **base,
            "decision": "block",
            "reason_code": "missing_required_scopes",
            "explanation": (
                "Observed authority is missing contract scopes: "
                f"{', '.join(missing)}."
            ),
            "contract_state": "active",
            "state_transition": None,
        }

    if normalized_attempt not in set(contract.allowed_capabilities):
        return {
            **base,
            "decision": "block",
            "reason_code": "capability_not_allowed",
            "explanation": (
                f"Capability '{normalized_attempt}' is not allowed by the "
                "intent-locked contract."
            ),
            "contract_state": "active",
            "state_transition": None,
        }

    enabled = _enabled_capabilities(contract.provider, observed)
    if normalized_attempt not in enabled:
        return {
            **base,
            "decision": "block",
            "reason_code": "capability_not_enabled",
            "explanation": (
                f"Capability '{normalized_attempt}' is allowed but is not "
                "enabled by the observed scopes."
            ),
            "contract_state": "active",
            "state_transition": None,
        }

    return {
        **base,
        "decision": "allow",
        "reason_code": "capability_allowed",
        "explanation": (
            f"Capability '{normalized_attempt}' is allowed and enabled by "
            "the observed scopes."
        ),
        "contract_state": "active",
        "state_transition": None,
    }
