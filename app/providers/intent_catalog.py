"""Provider-specific intent mappings keyed by canonical authority provider."""

from types import MappingProxyType
from typing import Iterable

from app.providers.catalog import resolve_authority_provider_id


PROVIDER_INTENT_SCOPE_MAP = MappingProxyType({
    "google": MappingProxyType({
        "read_files": ("drive.readonly",), "upload_files": ("drive.file",),
        "read_email": ("gmail.readonly",), "send_email": ("gmail.send",),
        "view_calendar": ("calendar.readonly",), "manage_calendar": ("calendar.events",),
        "read_contacts": ("contacts.readonly",), "read_profile": ("userinfo.profile",),
    }),
    "mock-enterprise": MappingProxyType({
        "read_files": ("content.read",), "write_files": ("content.write",),
        "read_email": ("mail.read",), "send_email": ("mail.send",),
        "view_calendar": ("calendar.read",), "read_profile": ("profile.read",),
    }),
    "mock-code-host": MappingProxyType({
        "read_repositories": ("content.read",), "write_repositories": ("content.write",),
        "create_issues": ("issues.write",), "configure_webhooks": ("webhooks.manage",),
        "read_profile": ("profile.read",),
    }),
})


def normalize_intent(intent: str) -> str:
    return intent.strip().lower().replace("-", "_").replace(" ", "_")


def map_provider_intents(provider: str, actions: Iterable[str]) -> tuple[list[str], list[str]]:
    canonical = resolve_authority_provider_id(provider)
    mapping = PROVIDER_INTENT_SCOPE_MAP[canonical]
    required: set[str] = set()
    unknown: list[str] = []
    for action in actions:
        scopes = mapping.get(normalize_intent(action))
        if scopes is None:
            unknown.append(action)
        else:
            required.update(scopes)
    return sorted(required), unknown
