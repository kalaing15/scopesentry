"""Request and response models for multi-grant composition analysis."""

from typing import Any, Dict, List, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

from app.core.validation import validate_identifier, validate_scope_list
from app.schemas.analysis import LeastPrivilegePlan
from app.schemas.evidence import EvidenceReference


class GrantCompositionInput(BaseModel):
    """One independently issued authorization grant."""

    grant_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("grant_id", "id", "name"),
        examples=["workflow-a"],
        description="Stable identifier for the grant or consuming workflow",
    )
    granted_scopes: List[str] = Field(
        ...,
        validation_alias=AliasChoices("granted_scopes", "scopes"),
        examples=[["drive.readonly", "gmail.send"]],
    )
    intended_actions: List[str] = Field(
        default_factory=list,
        examples=[["read files"]],
        description="Optional actions associated specifically with this grant",
    )

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="grant_id")

    @field_validator("granted_scopes")
    @classmethod
    def validate_granted_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=False)


class CompositionAnalysisRequest(BaseModel):
    """A set of grants whose combined authority should be evaluated."""

    provider: str = Field(..., examples=["google"])
    grants: List[GrantCompositionInput] = Field(..., min_length=1)
    intended_actions: List[str] = Field(
        default_factory=list,
        examples=[["read files", "send email"]],
        description=(
            "Actions required across the composition. Per-grant actions are "
            "also included when deriving the complete intended capability set."
        ),
    )

    @model_validator(mode="after")
    def grant_ids_must_be_unique(self) -> "CompositionAnalysisRequest":
        normalized_ids = [grant.grant_id.strip() for grant in self.grants]
        if any(not grant_id for grant_id in normalized_ids):
            raise ValueError("grant_id must not be blank")
        if len(normalized_ids) != len(set(normalized_ids)):
            raise ValueError("grant_id values must be unique")
        return self


class ComposedGrantAnalysis(BaseModel):
    """Normalized, proof-oriented analysis for one grant."""

    grant_id: str
    intended_actions: List[str]
    granted_scopes: List[str]
    recognized_scopes: List[str]
    unknown_scopes: List[str]
    capabilities: List[str]
    covers_all_required_capabilities: bool
    risk_score: float


class CompositionAnalysisResponse(BaseModel):
    """Combined authorization exposure and least-privilege recommendation."""

    status: Literal["complete", "incomplete", "manual_review"]
    provider: str
    grant_count: int
    intended_actions: List[str]
    unknown_intents: List[str]
    required_scopes: List[str]
    required_capabilities: List[str]
    grants: List[ComposedGrantAnalysis]
    combined_scopes: List[str]
    recognized_scopes: List[str]
    unknown_scopes: List[str]
    combined_capabilities: List[str]
    matched_capabilities: List[str]
    missing_capabilities: List[str]
    excessive_capabilities: List[str]
    duplicated_scopes: List[str]
    shared_capabilities: List[str]
    capability_sources: Dict[str, List[str]]
    requires_composition: bool
    total_risk: float
    unique_scope_risk: float
    duplicated_scope_risk: float
    composition_graph: Dict[str, Any]
    least_privilege_plan: LeastPrivilegePlan
    recommendation: str
    evidence_reference: EvidenceReference
