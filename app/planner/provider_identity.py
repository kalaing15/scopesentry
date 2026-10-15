"""Structured authority identities and collision-safe graph node IDs."""

from dataclasses import asdict, dataclass

from app.evidence.canonical import sha256_hex


@dataclass(frozen=True, order=True)
class GrantIdentity:
    provider: str
    principal_id: str
    grant_id: str


@dataclass(frozen=True, order=True)
class ScopeIdentity(GrantIdentity):
    scope: str


@dataclass(frozen=True, order=True)
class CapabilityIdentity(ScopeIdentity):
    capability: str


def identity_node_id(kind: str, identity) -> str:
    """Return an unambiguous deterministic ID; attributes remain authoritative."""
    return f"{kind}:{sha256_hex(asdict(identity))}"
