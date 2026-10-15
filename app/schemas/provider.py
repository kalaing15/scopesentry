"""Schemas shared by credential-free provider adapters and scenarios."""

from enum import Enum
from typing import List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.core.validation import (
    validate_capability_name,
    validate_identifier,
    validate_nonempty_text,
    validate_scope_list,
    validate_scope_name,
)


GrantStatus = Literal["active", "revoked", "drifted"]


class ProviderMetadata(BaseModel):
    provider_name: str
    display_name: str
    catalog_provider: str
    simulation_only: bool
    description: str


class MockGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    application_name: str
    provider: str
    declared_intended_actions: List[str]
    granted_scopes: List[str] = Field(..., min_length=1)
    observed_scopes: List[str] = Field(..., min_length=1)
    status: GrantStatus
    description: str

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="grant_id")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        return validate_identifier(value, label="provider")

    @field_validator("granted_scopes", "observed_scopes")
    @classmethod
    def validate_fixture_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)


class SimulatedCapabilityAttempt(BaseModel):
    grant_id: str
    attempted_capability: str
    provider_would_allow: bool
    enabled_capabilities: List[str]
    observed_scopes: List[str]
    grant_status: GrantStatus
    explanation: str


class ScenarioRuntimeAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    capability: str
    resource_reference: Optional[str] = None

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="runtime attempt grant_id")

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        return validate_capability_name(value)


class ScenarioDataFlowLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    link_id: str
    source_grant_id: str
    target_grant_id: str
    data_type: str
    description: str

    @field_validator("link_id", "source_grant_id", "target_grant_id")
    @classmethod
    def validate_ids(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @model_validator(mode="after")
    def reject_self_reference(self) -> "ScenarioDataFlowLink":
        if self.source_grant_id == self.target_grant_id:
            raise ValueError(
                f"data-flow link '{self.link_id}' must not reference the same "
                "source and destination grant"
            )
        return self


ScenarioDecision = Literal["allow", "block", "quarantine"]
ContractState = Literal["active", "quarantined", "expired", "revoked"]


class ScenarioRiskCategory(str, Enum):
    """Presentation metadata only; never consumed by security policy."""

    LOW = "low"
    EXCESSIVE_AUTHORITY = "excessive_authority"
    RUNTIME_DRIFT = "runtime_drift"
    COMPOSITION_RISK = "composition_risk"
    MISSING_PERMISSION = "missing_permission"


class ScenarioExpectations(BaseModel):
    """The complete, closed set of expectations understood by the runner."""

    model_config = ConfigDict(extra="forbid", strict=True)

    decision: Optional[ScenarioDecision] = None
    decisions: Optional[List[ScenarioDecision]] = None
    excessive_scopes: Optional[List[str]] = None
    excessive_scope: Optional[str] = None
    selected_scopes: Optional[List[str]] = None
    contract_state: Optional[ContractState] = None
    unauthorized_path_count: Optional[int] = Field(default=None, ge=0, strict=True)
    missing_scope: Optional[str] = None
    scope_to_add: Optional[str] = None

    @field_validator(
        "excessive_scopes",
        "selected_scopes",
    )
    @classmethod
    def validate_scope_lists(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        return validate_scope_list(value, reject_duplicates=True)

    @field_validator("excessive_scope", "missing_scope", "scope_to_add")
    @classmethod
    def validate_optional_scope(cls, value: Optional[str]) -> Optional[str]:
        return validate_scope_name(value) if value is not None else None

    @model_validator(mode="after")
    def validate_supported_combination(self) -> "ScenarioExpectations":
        if not self.model_fields_set:
            raise ValueError("expected_values must define at least one expectation")
        if self.decision is not None and self.decisions is not None:
            raise ValueError("decision and decisions are mutually exclusive")
        return self


class DemoScenarioDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    scenario_name: str
    description: str
    provider: str
    risk_category: ScenarioRiskCategory
    intended_actions: List[str]
    grant_ids: List[str] = Field(..., min_length=1)
    runtime_attempts: List[ScenarioRuntimeAttempt] = Field(
        default_factory=list
    )
    data_flow_links: List[ScenarioDataFlowLink] = Field(
        default_factory=list
    )
    expected_outcome: str
    expected_values: ScenarioExpectations

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, value: str) -> str:
        return validate_identifier(value, label="scenario_id")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        return validate_identifier(value, label="provider")

    @field_validator("intended_actions")
    @classmethod
    def validate_intended_actions(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("intended_actions must not be empty")
        return [
            validate_nonempty_text(action, label="intended action")
            for action in value
        ]

    @field_validator("grant_ids")
    @classmethod
    def validate_grant_ids(cls, value: List[str]) -> List[str]:
        validated = [
            validate_identifier(grant_id, label="grant_id") for grant_id in value
        ]
        if len(validated) != len(set(validated)):
            raise ValueError("grant_ids must be unique within a scenario")
        return validated

    @model_validator(mode="after")
    def validate_internal_references(self) -> "DemoScenarioDefinition":
        declared_grants = set(self.grant_ids)
        for attempt in self.runtime_attempts:
            if attempt.grant_id not in declared_grants:
                raise ValueError(
                    f"scenario '{self.scenario_id}' runtime attempt references "
                    f"undeclared grant '{attempt.grant_id}'"
                )

        link_ids: set[str] = set()
        for link in self.data_flow_links:
            if link.link_id in link_ids:
                raise ValueError(
                    f"scenario '{self.scenario_id}' contains duplicate data-flow "
                    f"link ID '{link.link_id}'"
                )
            link_ids.add(link.link_id)
            for role, grant_id in (
                ("source", link.source_grant_id),
                ("destination", link.target_grant_id),
            ):
                if grant_id not in declared_grants:
                    raise ValueError(
                        f"scenario '{self.scenario_id}' data-flow link "
                        f"'{link.link_id}' references undeclared {role} grant "
                        f"'{grant_id}'"
                    )
        return self
