from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.validation import validate_scope_list
from app.schemas.evidence import EvidenceReference


class ScopeAnalysisRequest(BaseModel):
    provider: str = Field(
        ...,
        examples=["google"],
        description="OAuth service provider",
    )
    granted_scopes: List[str] = Field(
        ...,
        examples=[["drive.readonly", "gmail.readonly"]],
        description="Scopes requested or granted to the application",
    )
    intended_actions: List[str] = Field(
        ...,
        examples=[["read files"]],
        description="Actions the user actually intends to perform",
    )

    @field_validator("granted_scopes")
    @classmethod
    def validate_granted_scopes(cls, value: List[str]) -> List[str]:
        # Public duplicates and well-formed unknown scopes remain accepted;
        # downstream normalization and fail-closed analysis handle them.
        return validate_scope_list(value, reject_duplicates=False)


class LeastPrivilegePlan(BaseModel):
    """Deterministic least-privilege synthesis result."""

    status: Literal["complete", "incomplete", "manual_review"] = Field(
        ...,
        description="'complete', 'incomplete', or 'manual_review'",
    )
    selected_scopes: List[str]
    scopes_to_keep: List[str]
    scopes_to_remove: List[str]
    scopes_to_add: List[str]
    covered_capabilities: List[str]
    uncovered_capabilities: List[str]
    unnecessary_capabilities: List[str]
    risk_before: float
    risk_after: float
    risk_delta: float
    risk_reduction_percentage: float
    optimization_method: str
    explanation: str


class ScopeAnalysisResponse(BaseModel):
    provider: str
    intended_actions: List[str]
    granted_scopes: List[str]
    required_scopes: List[str]
    matched_scopes: List[str]
    excessive_scopes: List[str]
    missing_scopes: List[str]
    unknown_intents: List[str]
    synthesized_least_privilege_scopes: List[str]
    granted_capabilities: List[str]
    required_capabilities: List[str]
    missing_capabilities: List[str]
    excessive_capabilities: List[str]
    exposure_score: float
    recommendation: str
    capability_graph: Dict[str, Any]
    least_privilege_plan: LeastPrivilegePlan
    evidence_reference: EvidenceReference
