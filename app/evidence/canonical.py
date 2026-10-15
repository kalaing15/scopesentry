"""Strict canonical JSON, hashing, and sensitive-field redaction helpers."""

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID

from pydantic import BaseModel


REDACTED_VALUE = "[REDACTED]"
_SENSITIVE_TERMS = (
    "accesstoken",
    "refreshtoken",
    "authorization",
    "clientsecret",
    "password",
    "apikey",
    "cookie",
)


def _normalized_field_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def is_sensitive_field(name: str) -> bool:
    normalized = _normalized_field_name(name)
    return any(term in normalized for term in _SENSITIVE_TERMS)


def redact_sensitive_data(value: Any) -> Any:
    """Recursively replace values of credential-like fields."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")

    if isinstance(value, Mapping):
        redacted = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Canonical JSON object keys must be strings")
            redacted[key] = (
                REDACTED_VALUE
                if is_sensitive_field(key)
                else redact_sensitive_data(item)
            )
        return redacted

    if isinstance(value, (list, tuple)):
        return [redact_sensitive_data(item) for item in value]

    return value


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))

    if isinstance(value, Enum):
        return _canonical_value(value.value)

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        if value.tzinfo is not None and value.utcoffset() is not None:
            value = value.astimezone(timezone.utc)
            return value.isoformat().replace("+00:00", "Z")
        return value.isoformat()

    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("Canonical JSON does not support non-finite numbers")
        return value

    if isinstance(value, Mapping):
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Canonical JSON object keys must be strings")
            normalized[key] = _canonical_value(item)
        return {key: normalized[key] for key in sorted(normalized)}

    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]

    raise TypeError(
        f"Unsupported canonical JSON value: {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a supported value into deterministic UTF-8 JSON bytes."""
    normalized = _canonical_value(value)
    text = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return text.encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Hash the canonical JSON representation using SHA-256."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
