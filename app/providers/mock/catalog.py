"""Compatibility re-exports for the centralized provider catalogue."""

from app.providers.catalog import (  # noqa: F401
    CODE_HOST_SCOPE_CAPABILITIES,
    CODE_HOST_SCOPE_RISK_WEIGHTS,
    DEFAULT_RISK_WEIGHT,
    ENTERPRISE_SCOPE_CAPABILITIES,
    ENTERPRISE_SCOPE_RISK_WEIGHTS,
    GOOGLE_SCOPE_CAPABILITIES,
    GOOGLE_SCOPE_RISK_WEIGHTS,
    SUPPORTED_PROVIDERS,
    get_catalog,
    get_provider_catalogue,
    get_risk_weights,
    resolve_authority_provider_id,
)
