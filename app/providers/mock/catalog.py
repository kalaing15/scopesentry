"""
Mock scope catalogue for supported OAuth providers.

These are **normalized mock scopes**, not official complete Google OAuth
scope URLs.  They exist so the capability-graph engine can be developed
and tested without a live provider integration.

This module is the single authoritative source for:
  - scope → capability mappings
  - scope risk weights
"""

from typing import Dict, List


# ---------------------------------------------------------------------------
# Google – normalised mock scope → concrete capabilities
#
# These are internal normalized aliases, NOT official OAuth scope URLs.
# Broader scopes (e.g. drive.full, gmail.all) overlap with narrower ones
# so the optimizer can make meaningful least-privilege choices.
# ---------------------------------------------------------------------------

GOOGLE_SCOPE_CAPABILITIES: Dict[str, List[str]] = {
    # --- Drive ---
    "drive.readonly": [
        "list_files",
        "read_file_metadata",
        "read_file_contents",
    ],
    "drive.file": [
        "list_files",
        "read_file_metadata",
        "read_file_contents",
        "create_files",
        "update_files",
    ],
    "drive.full": [
        "list_files",
        "read_file_metadata",
        "read_file_contents",
        "create_files",
        "update_files",
        "delete_files",
        "manage_permissions",
    ],
    # --- Gmail ---
    "gmail.readonly": [
        "list_email_messages",
        "read_email_messages",
    ],
    "gmail.send": [
        "send_email_messages",
    ],
    "gmail.compose": [
        "send_email_messages",
        "draft_email_messages",
    ],
    "gmail.full": [
        "list_email_messages",
        "read_email_messages",
        "send_email_messages",
        "draft_email_messages",
        "delete_email_messages",
    ],
    # --- Calendar ---
    "calendar.readonly": [
        "list_calendar_events",
        "read_calendar_events",
    ],
    "calendar.events": [
        "read_calendar_events",
        "create_calendar_events",
        "update_calendar_events",
        "delete_calendar_events",
    ],
    "calendar.full": [
        "list_calendar_events",
        "read_calendar_events",
        "create_calendar_events",
        "update_calendar_events",
        "delete_calendar_events",
        "manage_calendar_settings",
    ],
    # --- Contacts ---
    "contacts.readonly": [
        "list_contacts",
        "read_contacts",
    ],
    # --- Profile ---
    "userinfo.profile": [
        "read_user_profile",
    ],
}

# ---------------------------------------------------------------------------
# Risk weights – single authoritative source
#
# Higher weight = more sensitive / dangerous scope.
# ---------------------------------------------------------------------------

GOOGLE_SCOPE_RISK_WEIGHTS: Dict[str, float] = {
    "drive.readonly": 2.0,
    "drive.file": 3.0,
    "drive.full": 5.0,
    "gmail.readonly": 4.0,
    "gmail.send": 4.0,
    "gmail.compose": 4.5,
    "gmail.full": 6.0,
    "calendar.readonly": 1.5,
    "calendar.events": 2.5,
    "calendar.full": 3.5,
    "contacts.readonly": 2.0,
    "userinfo.profile": 1.0,
}

DEFAULT_RISK_WEIGHT = 2.0

# ---------------------------------------------------------------------------
# Provider registry – add new providers here
# ---------------------------------------------------------------------------

PROVIDER_CATALOGS: Dict[str, Dict[str, List[str]]] = {
    "google": GOOGLE_SCOPE_CAPABILITIES,
}

PROVIDER_RISK_WEIGHTS: Dict[str, Dict[str, float]] = {
    "google": GOOGLE_SCOPE_RISK_WEIGHTS,
}

SUPPORTED_PROVIDERS = set(PROVIDER_CATALOGS.keys())


def get_catalog(provider: str) -> Dict[str, List[str]]:
    """Return the scope-capability catalogue for *provider*.

    Raises ``ValueError`` if the provider is not supported.
    """
    provider_lower = provider.strip().lower()
    if provider_lower not in PROVIDER_CATALOGS:
        raise ValueError(
            f"Unsupported provider '{provider}'. "
            f"Supported providers: {sorted(SUPPORTED_PROVIDERS)}"
        )
    return PROVIDER_CATALOGS[provider_lower]


def get_risk_weights(provider: str) -> Dict[str, float]:
    """Return the scope risk-weight map for *provider*.

    Raises ``ValueError`` if the provider is not supported.
    """
    provider_lower = provider.strip().lower()
    if provider_lower not in PROVIDER_RISK_WEIGHTS:
        raise ValueError(
            f"Unsupported provider '{provider}'. "
            f"Supported providers: {sorted(SUPPORTED_PROVIDERS)}"
        )
    return PROVIDER_RISK_WEIGHTS[provider_lower]
