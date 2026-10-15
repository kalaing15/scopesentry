"""Pydantic schemas for the intent-locked runtime capability gateway."""

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.core.validation import (
    validate_capability_name,
    validate_identifier,
    validate_scope_list,
)
from app.providers.catalog import resolve_authority_provider_id
from app.schemas.evidence import EvidenceReference


ContractState = Literal["active", "quarantined", "expired", "revoked"]
GatewayDecision = Literal["allow", "block", "quarantine"]


class CapabilityContract(BaseModel):
    """Temporary capability policy derived from a successful analysis."""

    contract_id: str
    provider: str
    principal_id: str = "local-api-principal"
    source_grant_ids: List[str] = Field(
        default_factory=lambda: ["api-request-grant"]
    )
    intended_actions: List[str]
    allowed_scopes: List[str]
    allowed_capabilities: List[str]
    scope_fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    expires_at: datetime
    state: ContractState
    policy_version: str
    source_analysis_id: str
    source_evidence_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")

    @field_validator("provider")
    @classmethod
    def canonicalize_provider(cls, value: str) -> str:
        return resolve_authority_provider_id(value)

    @field_validator("principal_id")
    @classmethod
    def validate_principal(cls, value: str) -> str:
        return validate_identifier(value, label="principal_id")

    @field_validator("source_grant_ids")
    @classmethod
    def validate_grants(cls, value: List[str]) -> List[str]:
        validated = [validate_identifier(item, label="source grant ID") for item in value]
        if not validated or len(validated) != len(set(validated)):
            raise ValueError("source_grant_ids must be nonempty and unique")
        return sorted(validated)

    @field_validator("created_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("contract timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class ContractCreateRequest(BaseModel):
    provider: str
    principal_id: str = "local-api-principal"
    source_grant_ids: List[str] = Field(
        default_factory=lambda: ["api-request-grant"]
    )
    granted_scopes: List[str]
    intended_actions: List[str]
    ttl_seconds: int = Field(..., ge=60, le=86400)

    @field_validator("granted_scopes")
    @classmethod
    def validate_granted_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=False)

    @field_validator("principal_id")
    @classmethod
    def validate_principal(cls, value: str) -> str:
        return validate_identifier(value, label="principal_id")

    @field_validator("source_grant_ids")
    @classmethod
    def validate_source_grants(cls, value: List[str]) -> List[str]:
        validated = [validate_identifier(item, label="source grant ID") for item in value]
        if not validated or len(validated) != len(set(validated)):
            raise ValueError("source_grant_ids must be nonempty and unique")
        return sorted(validated)


class ContractListResponse(BaseModel):
    count: int = Field(..., ge=0)
    contracts: List[CapabilityContract]


class GatewayEvaluationRequest(BaseModel):
    contract_id: str
    attempted_capability: str
    observed_scopes: List[str]
    resource_reference: Optional[str] = Field(default=None, max_length=512)
    provider: Optional[str] = None
    principal_id: Optional[str] = None
    grant_id: Optional[str] = None

    @field_validator("attempted_capability")
    @classmethod
    def validate_attempted_capability(cls, value: str) -> str:
        return validate_capability_name(value)

    @field_validator("observed_scopes")
    @classmethod
    def validate_observed_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=False)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: Optional[str]) -> Optional[str]:
        return resolve_authority_provider_id(value) if value is not None else None

    @field_validator("principal_id", "grant_id")
    @classmethod
    def validate_optional_identity(cls, value: Optional[str], info) -> Optional[str]:
        return validate_identifier(value, label=info.field_name) if value is not None else None


class GatewayEvaluationResponse(BaseModel):
    decision: GatewayDecision
    reason_code: str
    explanation: str
    contract_id: str
    contract_state: ContractState
    attempted_capability: str
    scope_drift: bool
    unexpected_scopes: List[str]
    missing_scopes: List[str]
    evaluated_at: datetime
    evidence_reference: EvidenceReference
    provider: str
    principal_id: str
    grant_id: Optional[str] = None

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return value.astimezone(timezone.utc)
