"""Shared syntax validation for public inputs and static mock fixtures."""

from __future__ import annotations

import re
from typing import Iterable, List
from urllib.parse import urlsplit


# RFC 6749 scope-token characters. This deliberately accepts normalized aliases,
# URNs, and URL-style scopes while excluding whitespace and control characters.
_OAUTH_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
_CAPABILITY_NAME = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def validate_scope_name(value: str) -> str:
    """Validate one scope's structure without requiring catalogue membership."""
    if not isinstance(value, str):
        raise ValueError("scope names must be strings")
    normalized = value.strip()
    if not normalized:
        raise ValueError("scope names must not be empty or whitespace-only")
    if not _OAUTH_SCOPE_TOKEN.fullmatch(normalized):
        raise ValueError(
            "scope names must use valid OAuth scope-token characters and "
            "must not contain whitespace, quotes, backslashes, or controls"
        )
    if "://" in normalized:
        parsed = urlsplit(normalized)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("URL-style scope names must include a scheme and host")
    return normalized


def validate_scope_list(
    values: Iterable[str], *, reject_duplicates: bool = False
) -> List[str]:
    """Validate scopes, optionally rejecting normalized duplicates."""
    validated = [validate_scope_name(value) for value in values]
    if reject_duplicates:
        normalized = [value.lower() for value in validated]
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate scope names are not allowed in fixtures")
    return validated


def validate_capability_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("capability names must be strings")
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError("capability names must not be empty or whitespace-only")
    if not _CAPABILITY_NAME.fullmatch(normalized):
        raise ValueError("capability names must use lower-case snake_case")
    return normalized


def validate_identifier(value: str, *, label: str = "identifier") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty or whitespace-only")
    if not _IDENTIFIER.fullmatch(normalized):
        raise ValueError(f"{label} contains unsupported characters")
    return normalized


def validate_nonempty_text(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty or whitespace-only")
    if any(ord(character) < 32 for character in normalized):
        raise ValueError(f"{label} must not contain control characters")
    return normalized
