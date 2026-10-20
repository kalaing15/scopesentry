"""Immutable, authoritative catalogues for local synthetic providers.

Adapter IDs identify implementations. Authority provider IDs identify security
namespaces. Only the explicit ``mock-google`` compatibility alias maps to a
different canonical authority provider.
"""

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Mapping, Sequence


DEFAULT_RISK_WEIGHT = 2.0


@dataclass(frozen=True)
class ProviderCatalogue:
    authority_provider_id: str
    scopes: Mapping[str, tuple[str, ...]]
    risk_weights: Mapping[str, float]


def _catalogue(
    provider: str,
    scopes: Mapping[str, Sequence[str]],
    weights: Mapping[str, float],
) -> ProviderCatalogue:
    if not provider or set(scopes) != set(weights):
        raise ValueError(f"Catalogue '{provider}' must define one risk weight per scope")
    normalized: dict[str, tuple[str, ...]] = {}
    for scope, capabilities in sorted(scopes.items()):
        raw_values = tuple(capabilities)
        values = tuple(sorted(set(raw_values)))
        if not scope or not values or any(not value for value in values):
            raise ValueError(f"Catalogue '{provider}' contains an empty scope definition")
        if len(values) != len(raw_values):
            raise ValueError(f"Catalogue '{provider}' scope '{scope}' repeats a capability")
        weight = weights[scope]
        if not isinstance(weight, (int, float)) or isinstance(weight, bool) or not math.isfinite(weight) or weight <= 0:
            raise ValueError(f"Catalogue '{provider}' scope '{scope}' has invalid risk metadata")
        normalized[scope] = values
    return ProviderCatalogue(
        authority_provider_id=provider,
        scopes=MappingProxyType(normalized),
        risk_weights=MappingProxyType(dict(sorted(weights.items()))),
    )


GOOGLE_SCOPE_CAPABILITIES = {
    "drive.readonly": ("list_files", "read_file_metadata", "read_file_contents"),
    "drive.file": ("list_files", "read_file_metadata", "read_file_contents", "create_files", "update_files"),
    "drive.full": ("list_files", "read_file_metadata", "read_file_contents", "create_files", "update_files", "delete_files", "manage_permissions"),
    "gmail.readonly": ("list_email_messages", "read_email_messages"),
    "gmail.send": ("send_email_messages",),
    "gmail.compose": ("send_email_messages", "draft_email_messages"),
    "gmail.full": ("list_email_messages", "read_email_messages", "send_email_messages", "draft_email_messages", "delete_email_messages"),
    "calendar.readonly": ("list_calendar_events", "read_calendar_events"),
    "calendar.events": ("read_calendar_events", "create_calendar_events", "update_calendar_events", "delete_calendar_events"),
    "calendar.full": ("list_calendar_events", "read_calendar_events", "create_calendar_events", "update_calendar_events", "delete_calendar_events", "manage_calendar_settings"),
    "contacts.readonly": ("list_contacts", "read_contacts"),
    "userinfo.profile": ("read_user_profile",),
}

GOOGLE_SCOPE_RISK_WEIGHTS = {
    "drive.readonly": 2.0, "drive.file": 3.0, "drive.full": 5.0,
    "gmail.readonly": 4.0, "gmail.send": 4.0, "gmail.compose": 4.5,
    "gmail.full": 6.0, "calendar.readonly": 1.5,
    "calendar.events": 2.5, "calendar.full": 3.5,
    "contacts.readonly": 2.0, "userinfo.profile": 1.0,
}

ENTERPRISE_SCOPE_CAPABILITIES = {
    "content.read": ("list_enterprise_files", "read_enterprise_file_metadata", "read_sensitive_file_contents"),
    "content.write": ("list_enterprise_files", "read_enterprise_file_metadata", "read_sensitive_file_contents", "create_enterprise_files", "update_enterprise_files"),
    "mail.read": ("list_enterprise_messages", "read_enterprise_messages"),
    "mail.send": ("send_enterprise_messages",),
    "calendar.read": ("list_enterprise_calendar_events", "read_enterprise_calendar_events"),
    "profile.read": ("read_profile",),
    "authority.full": ("list_enterprise_files", "read_enterprise_file_metadata", "read_sensitive_file_contents", "create_enterprise_files", "update_enterprise_files", "delete_enterprise_files", "list_enterprise_messages", "read_enterprise_messages", "send_enterprise_messages", "list_enterprise_calendar_events", "read_enterprise_calendar_events", "read_profile", "administer_enterprise_workspace"),
}

ENTERPRISE_SCOPE_RISK_WEIGHTS = {
    "content.read": 2.0, "content.write": 3.5, "mail.read": 3.0,
    "mail.send": 4.0, "calendar.read": 1.5, "profile.read": 1.0,
    "authority.full": 8.0,
}

CODE_HOST_SCOPE_CAPABILITIES = {
    "content.read": ("list_repositories", "read_repository_metadata", "read_repository_contents"),
    "content.write": ("list_repositories", "read_repository_metadata", "read_repository_contents", "create_repository_content", "update_repository_content"),
    "issues.write": ("create_issues", "update_issues"),
    "webhooks.manage": ("configure_external_webhooks", "delete_external_webhooks"),
    "profile.read": ("read_profile",),
    "authority.full": ("list_repositories", "read_repository_metadata", "read_repository_contents", "create_repository_content", "update_repository_content", "create_issues", "update_issues", "configure_external_webhooks", "delete_external_webhooks", "read_profile", "delete_repositories", "administer_repositories"),
}

CODE_HOST_SCOPE_RISK_WEIGHTS = {
    "content.read": 2.0, "content.write": 3.5, "issues.write": 2.5,
    "webhooks.manage": 5.0, "profile.read": 1.0, "authority.full": 8.0,
}


def _validate_broad_scope(
    provider: str,
    definitions: Mapping[str, Sequence[str]],
    broad_scope: str,
    narrower_scopes: Sequence[str],
) -> None:
    broad = set(definitions[broad_scope])
    required = {
        capability
        for scope in narrower_scopes
        for capability in definitions[scope]
    }
    if not required.issubset(broad):
        raise ValueError(
            f"Catalogue '{provider}' broad scope '{broad_scope}' does not include every narrower capability"
        )


_validate_broad_scope("google", GOOGLE_SCOPE_CAPABILITIES, "drive.full", ("drive.readonly", "drive.file"))
_validate_broad_scope("google", GOOGLE_SCOPE_CAPABILITIES, "gmail.full", ("gmail.readonly", "gmail.send", "gmail.compose"))
_validate_broad_scope("google", GOOGLE_SCOPE_CAPABILITIES, "calendar.full", ("calendar.readonly", "calendar.events"))
_validate_broad_scope("mock-enterprise", ENTERPRISE_SCOPE_CAPABILITIES, "authority.full", tuple(scope for scope in ENTERPRISE_SCOPE_CAPABILITIES if scope != "authority.full"))
_validate_broad_scope("mock-code-host", CODE_HOST_SCOPE_CAPABILITIES, "authority.full", tuple(scope for scope in CODE_HOST_SCOPE_CAPABILITIES if scope != "authority.full"))

_CATALOGUES = MappingProxyType({
    "google": _catalogue("google", GOOGLE_SCOPE_CAPABILITIES, GOOGLE_SCOPE_RISK_WEIGHTS),
    "mock-enterprise": _catalogue("mock-enterprise", ENTERPRISE_SCOPE_CAPABILITIES, ENTERPRISE_SCOPE_RISK_WEIGHTS),
    "mock-code-host": _catalogue("mock-code-host", CODE_HOST_SCOPE_CAPABILITIES, CODE_HOST_SCOPE_RISK_WEIGHTS),
})

_AUTHORITY_ALIASES = MappingProxyType({"mock-google": "google"})
SUPPORTED_PROVIDERS = frozenset(_CATALOGUES)


def resolve_authority_provider_id(provider: str) -> str:
    normalized = provider.strip().lower()
    canonical = _AUTHORITY_ALIASES.get(normalized, normalized)
    if canonical not in _CATALOGUES:
        raise ValueError(
            f"Unsupported provider '{provider}'. Supported providers: {sorted(SUPPORTED_PROVIDERS)}"
        )
    return canonical


def get_provider_catalogue(provider: str) -> ProviderCatalogue:
    return _CATALOGUES[resolve_authority_provider_id(provider)]


def get_catalog(provider: str) -> Mapping[str, tuple[str, ...]]:
    return get_provider_catalogue(provider).scopes


def get_risk_weights(provider: str) -> Mapping[str, float]:
    return get_provider_catalogue(provider).risk_weights
