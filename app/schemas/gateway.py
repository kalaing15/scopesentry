"""Pydantic schemas for the intent-locked runtime capability gateway."""

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.core.validation import validate_capability_name, validate_scope_list
from app.schemas.evidence import EvidenceReference


ContractState = Literal["active", "quarantined", "expired", "revoked"]
GatewayDecision = Literal["allow", "block", "quarantine"]


class CapabilityContract(BaseModel):
    """Temporary capability policy derived from a successful analysis."""

    contract_id: str
    provider: str
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

    @field_validator("created_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("contract timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class ContractCreateRequest(BaseModel):
    provider: str
    granted_scopes: List[str]
    intended_actions: List[str]
    ttl_seconds: int = Field(..., ge=60, le=86400)

    @field_validator("granted_scopes")
    @classmethod
    def validate_granted_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=False)


class ContractListResponse(BaseModel):
    count: int = Field(..., ge=0)
    contracts: List[CapabilityContract]


class GatewayEvaluationRequest(BaseModel):
    contract_id: str
    attempted_capability: str
    observed_scopes: List[str]
    resource_reference: Optional[str] = Field(default=None, max_length=512)

    @field_validator("attempted_capability")
    @classmethod
    def validate_attempted_capability(cls, value: str) -> str:
        return validate_capability_name(value)

    @field_validator("observed_scopes")
    @classmethod
    def validate_observed_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=False)


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

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return value.astimezone(timezone.utc)
