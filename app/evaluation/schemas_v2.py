"""Provider-qualified additive schemas for the Phase 5 evaluation corpus."""

from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.validation import validate_capability_name, validate_identifier, validate_scope_list
from app.evaluation.schemas import EvaluationCase, EvaluationGroundTruth
from app.providers.catalog import get_catalog, resolve_authority_provider_id
from app.schemas.provider import AuthorizedFlow, ProviderIntentAssignment, ScenarioDataFlowLink


class QualifiedEvaluationGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: str
    principal_id: str
    grant_id: str
    granted_scopes: List[str] = Field(..., min_length=1)

    @field_validator("provider")
    @classmethod
    def provider_id(cls, value: str) -> str:
        return resolve_authority_provider_id(value)

    @field_validator("principal_id", "grant_id")
    @classmethod
    def ids(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @field_validator("granted_scopes")
    @classmethod
    def scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)

    @model_validator(mode="after")
    def catalogue_membership(self) -> "QualifiedEvaluationGrant":
        unknown = sorted(set(self.granted_scopes) - set(get_catalog(self.provider)))
        if unknown:
            raise ValueError(f"grant '{self.grant_id}' contains wrong-provider or unknown scopes {unknown}")
        return self


class QualifiedRuntimeAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    grant_id: str
    attempted_capability: str
    observed_scopes: List[str] = Field(..., min_length=1)
    observed_provider: str
    observed_principal_id: str
    observed_grant_id: str

    @field_validator("grant_id", "observed_principal_id", "observed_grant_id")
    @classmethod
    def ids(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @field_validator("observed_provider")
    @classmethod
    def provider_id(cls, value: str) -> str:
        return resolve_authority_provider_id(value)

    @field_validator("attempted_capability")
    @classmethod
    def capability(cls, value: str) -> str:
        return validate_capability_name(value)

    @field_validator("observed_scopes")
    @classmethod
    def scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)


class ProviderQualifiedEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    case_id: str
    category: Literal[
        "provider_safe_access", "provider_excessive_authority",
        "provider_runtime_drift", "provider_scope_collision",
        "provider_capability_collision", "authorized_cross_provider_flow",
        "unauthorized_cross_provider_flow", "provider_missing_permission",
        "provider_capability_mismatch", "principal_mismatch",
    ]
    description: str
    provider_intents: List[ProviderIntentAssignment] = Field(..., min_length=1)
    grants: List[QualifiedEvaluationGrant] = Field(..., min_length=1)
    runtime_attempts: List[QualifiedRuntimeAttempt] = Field(default_factory=list)
    observed_links: List[ScenarioDataFlowLink] = Field(default_factory=list)
    authorized_flows: List[AuthorizedFlow] = Field(default_factory=list)
    ground_truth: EvaluationGroundTruth

    @field_validator("case_id")
    @classmethod
    def case_identifier(cls, value: str) -> str:
        return validate_identifier(value, label="case_id")

    @model_validator(mode="after")
    def references_and_capabilities(self) -> "ProviderQualifiedEvaluationCase":
        complete = [(item.provider, item.principal_id, item.grant_id) for item in self.grants]
        if len(complete) != len(set(complete)):
            raise ValueError("duplicate complete grant identity")
        grant_ids = {item.grant_id for item in self.grants}
        by_id: dict[str, list[QualifiedEvaluationGrant]] = {}
        for grant in self.grants:
            by_id.setdefault(grant.grant_id, []).append(grant)
        for attempt in self.runtime_attempts:
            if attempt.grant_id not in by_id:
                raise ValueError(f"runtime attempt references unknown grant '{attempt.grant_id}'")
            candidates = by_id[attempt.grant_id]
            if len(candidates) != 1:
                raise ValueError(f"runtime attempt has an ambiguous grant identity '{attempt.grant_id}'")
            grant = candidates[0]
            known_caps = {cap for values in get_catalog(grant.provider).values() for cap in values}
            if attempt.attempted_capability not in known_caps:
                raise ValueError(f"wrong-provider or unsupported capability '{attempt.attempted_capability}'")
        for link in self.observed_links:
            if link.source_grant_id not in grant_ids or link.target_grant_id not in grant_ids:
                raise ValueError(f"observed link '{link.link_id}' references unknown grant")
        return self


class Phase5EvaluationCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["2.0.0"] = "2.0.0"
    legacy_cases: List[EvaluationCase]
    provider_cases: List[ProviderQualifiedEvaluationCase]

    @model_validator(mode="after")
    def unique_cases(self) -> "Phase5EvaluationCorpus":
        ids = [item.case_id for item in [*self.legacy_cases, *self.provider_cases]]
        if len(ids) != len(set(ids)):
            raise ValueError("V2 evaluation case IDs must be unique")
        if len(ids) < 36:
            raise ValueError("V2 corpus must contain at least 36 cases")
        return self
