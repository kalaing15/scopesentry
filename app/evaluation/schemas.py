"""Strict schemas for the immutable Phase 4 evaluation corpus."""

from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.validation import (
    validate_capability_name,
    validate_identifier,
    validate_nonempty_text,
    validate_scope_list,
)
from app.providers.mock.catalog import get_catalog


class CaseCategory(str, Enum):
    EXACT_LEAST_PRIVILEGE = "exact_least_privilege"
    MULTIPLE_INTENTS = "multiple_legitimate_intents"
    SAFE_COMPOSITION = "safe_multi_grant_composition"
    EXCESSIVE_READ = "excessive_read_authority"
    EXCESSIVE_WRITE = "excessive_write_authority"
    UNKNOWN_SCOPE = "unknown_public_scope"
    MISSING_PERMISSION = "missing_permission"
    MULTIPLE_MISSING = "multiple_missing_permissions"
    RUNTIME_DRIFT = "runtime_scope_drift"
    CAPABILITY_MISMATCH = "runtime_capability_mismatch"
    MISSING_RUNTIME_SCOPE = "missing_runtime_scope"
    UNAUTHORIZED_COMPOSITION = "unauthorized_composition"
    EXCESSIVE_NO_MISUSE = "excessive_authority_without_misuse"
    MANUAL_REVIEW = "manual_review"


class OperationalOutcome(str, Enum):
    PERMITTED_SAFE = "permitted_safe"
    REMEDIATED_THEN_PERMITTED = "remediated_then_permitted"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    CONTRACT_NOT_CREATED = "contract_not_created"
    SKIPPED_UNSAFE_COMPOSITION = "skipped_unsafe_composition"
    MANUAL_REVIEW = "manual_review"
    EVALUATION_ERROR = "evaluation_error"


class EvaluationGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str
    granted_scopes: List[str] = Field(..., min_length=1)

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="grant_id")

    @field_validator("granted_scopes")
    @classmethod
    def validate_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)


class EvaluationRuntimeAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str
    attempted_capability: str
    observed_scopes: List[str] = Field(..., min_length=1)

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="runtime attempt grant_id")

    @field_validator("attempted_capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        return validate_capability_name(value)

    @field_validator("observed_scopes")
    @classmethod
    def validate_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)


class EvaluationDataFlowLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    link_id: str
    source_grant_id: str
    target_grant_id: str
    data_type: str

    @field_validator("link_id", "source_grant_id", "target_grant_id")
    @classmethod
    def validate_id(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @field_validator("data_type")
    @classmethod
    def validate_data_type(cls, value: str) -> str:
        return validate_nonempty_text(value, label="data_type")

    @model_validator(mode="after")
    def reject_self_reference(self) -> "EvaluationDataFlowLink":
        if self.source_grant_id == self.target_grant_id:
            raise ValueError("evaluation data-flow links cannot be self-referencing")
        return self


class EvaluationGroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    classification: Literal["safe", "unsafe"]
    expected_outcome: OperationalOutcome
    explanation: str
    expected_unauthorized_path_count: int = Field(default=0, ge=0)

    @field_validator("explanation")
    @classmethod
    def validate_explanation(cls, value: str) -> str:
        return validate_nonempty_text(value, label="ground-truth explanation")

    @model_validator(mode="after")
    def safe_cases_must_expect_safe_permission(self) -> "EvaluationGroundTruth":
        if self.classification == "safe" and self.expected_outcome != OperationalOutcome.PERMITTED_SAFE:
            raise ValueError("safe ground truth must expect permitted_safe")
        if self.classification == "unsafe" and self.expected_outcome == OperationalOutcome.PERMITTED_SAFE:
            raise ValueError("unsafe ground truth cannot expect permitted_safe")
        return self


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    category: CaseCategory
    description: str
    provider: Literal["google"] = "google"
    principal_id: str = "local-mock-principal"
    intended_actions: List[str] = Field(..., min_length=1)
    grants: List[EvaluationGrant] = Field(..., min_length=1)
    runtime_attempts: List[EvaluationRuntimeAttempt] = Field(default_factory=list)
    composition_links: List[EvaluationDataFlowLink] = Field(default_factory=list)
    allow_unknown_scopes: bool = False
    ground_truth: EvaluationGroundTruth

    @field_validator("case_id", "principal_id")
    @classmethod
    def validate_ids(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return validate_nonempty_text(value, label="description")

    @field_validator("intended_actions")
    @classmethod
    def validate_intents(cls, value: List[str]) -> List[str]:
        return [validate_nonempty_text(item, label="intended action") for item in value]

    @model_validator(mode="after")
    def validate_references_and_catalogue(self) -> "EvaluationCase":
        grant_ids = [grant.grant_id for grant in self.grants]
        if len(grant_ids) != len(set(grant_ids)):
            raise ValueError(f"case '{self.case_id}' contains duplicate grant IDs")
        declared = set(grant_ids)
        for attempt in self.runtime_attempts:
            if attempt.grant_id not in declared:
                raise ValueError(
                    f"case '{self.case_id}' runtime attempt references unknown "
                    f"grant '{attempt.grant_id}'"
                )
        link_ids: set[str] = set()
        for link in self.composition_links:
            if link.link_id in link_ids:
                raise ValueError(f"case '{self.case_id}' contains duplicate link ID '{link.link_id}'")
            link_ids.add(link.link_id)
            if link.source_grant_id not in declared:
                raise ValueError(f"case '{self.case_id}' link '{link.link_id}' has unknown source grant '{link.source_grant_id}'")
            if link.target_grant_id not in declared:
                raise ValueError(f"case '{self.case_id}' link '{link.link_id}' has unknown destination grant '{link.target_grant_id}'")

        catalog = get_catalog(self.provider)
        all_scopes = {
            scope for grant in self.grants for scope in grant.granted_scopes
        } | {
            scope for attempt in self.runtime_attempts for scope in attempt.observed_scopes
        }
        unknown = sorted(all_scopes - set(catalog))
        if unknown and not self.allow_unknown_scopes:
            raise ValueError(f"case '{self.case_id}' contains unknown catalogue scopes {unknown}")
        known_capabilities = {capability for values in catalog.values() for capability in values}
        invalid_capabilities = sorted({attempt.attempted_capability for attempt in self.runtime_attempts} - known_capabilities)
        if invalid_capabilities:
            raise ValueError(f"case '{self.case_id}' contains unsupported capabilities {invalid_capabilities}")
        return self


class EvaluationCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    cases: List[EvaluationCase] = Field(..., min_length=1)

    @model_validator(mode="after")
    def case_ids_must_be_unique(self) -> "EvaluationCorpus":
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("evaluation case IDs must be unique")
        return self
