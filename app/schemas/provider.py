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
from app.providers.catalog import resolve_authority_provider_id


GrantStatus = Literal["active", "revoked", "drifted"]


class ProviderMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_name: str
    display_name: str
    catalog_provider: str
    authority_provider_id: str
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    simulation_only: bool
    description: str

    @model_validator(mode="after")
    def validate_identity(self) -> "ProviderMetadata":
        canonical = resolve_authority_provider_id(self.authority_provider_id)
        if canonical != resolve_authority_provider_id(self.catalog_provider):
            raise ValueError("adapter authority provider and catalogue provider must match")
        return self


class MockGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    application_name: str
    provider: str
    authority_provider: Optional[str] = None
    principal_id: str = "local-mock-principal"
    declared_intended_actions: List[str]
    granted_scopes: List[str] = Field(..., min_length=1)
    observed_scopes: List[str] = Field(..., min_length=1)
    status: GrantStatus
    description: str

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return validate_identifier(value, label="grant_id")

    @field_validator("provider", "principal_id")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        return validate_identifier(value, label="provider")

    @field_validator("granted_scopes", "observed_scopes")
    @classmethod
    def validate_fixture_scopes(cls, value: List[str]) -> List[str]:
        return validate_scope_list(value, reject_duplicates=True)

    @model_validator(mode="after")
    def canonicalize_authority_provider(self) -> "MockGrant":
        canonical = resolve_authority_provider_id(self.provider)
        if self.authority_provider is None:
            self.authority_provider = canonical
        elif resolve_authority_provider_id(self.authority_provider) != canonical:
            raise ValueError("grant provider and authority_provider must identify the same catalogue")
        else:
            self.authority_provider = canonical
        return self


class SimulatedCapabilityAttempt(BaseModel):
    grant_id: str
    attempted_capability: str
    provider_would_allow: bool
    enabled_capabilities: List[str]
    observed_scopes: List[str]
    grant_status: GrantStatus
    explanation: str
    authority_provider: Optional[str] = None
    principal_id: Optional[str] = None


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
    source_provider: Optional[str] = None
    source_principal_id: Optional[str] = None
    target_provider: Optional[str] = None
    target_principal_id: Optional[str] = None
    data_type: str
    description: str
    source_capability: Optional[str] = None
    target_capability: Optional[str] = None

    @field_validator("link_id", "source_grant_id", "target_grant_id")
    @classmethod
    def validate_ids(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @model_validator(mode="after")
    def reject_self_reference(self) -> "ScenarioDataFlowLink":
        source_identity = (
            self.source_provider,
            self.source_principal_id,
            self.source_grant_id,
        )
        target_identity = (
            self.target_provider,
            self.target_principal_id,
            self.target_grant_id,
        )
        if source_identity == target_identity:
            raise ValueError(
                f"data-flow link '{self.link_id}' must not reference the same "
                "source and destination grant"
            )
        return self

    @field_validator("source_provider", "target_provider")
    @classmethod
    def validate_optional_provider(cls, value: Optional[str]) -> Optional[str]:
        return resolve_authority_provider_id(value) if value is not None else None

    @field_validator("source_principal_id", "target_principal_id")
    @classmethod
    def validate_optional_principal(cls, value: Optional[str]) -> Optional[str]:
        return validate_identifier(value, label="flow principal") if value is not None else None

    @model_validator(mode="after")
    def complete_optional_endpoint_identity(self) -> "ScenarioDataFlowLink":
        for endpoint, provider, principal in (
            ("source", self.source_provider, self.source_principal_id),
            ("target", self.target_provider, self.target_principal_id),
        ):
            if (provider is None) != (principal is None):
                raise ValueError(
                    f"{endpoint} provider and principal must be supplied together"
                )
        return self

    @field_validator("source_capability", "target_capability")
    @classmethod
    def validate_optional_capability(cls, value: Optional[str]) -> Optional[str]:
        return validate_capability_name(value) if value is not None else None


class ProviderIntentAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    principal_id: Optional[str] = None
    intended_actions: List[str] = Field(..., min_length=1)

    @field_validator("provider")
    @classmethod
    def canonicalize_provider(cls, value: str) -> str:
        return resolve_authority_provider_id(value)

    @field_validator("intended_actions")
    @classmethod
    def validate_actions(cls, value: List[str]) -> List[str]:
        return [validate_nonempty_text(item, label="intended action") for item in value]

    @field_validator("principal_id")
    @classmethod
    def validate_optional_principal(cls, value: Optional[str]) -> Optional[str]:
        return validate_identifier(value, label="principal_id") if value is not None else None


class AuthorizedFlow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    source_provider: str
    source_principal_id: str
    source_grant_id: str
    source_capability: str
    data_type: str
    target_provider: str
    target_principal_id: str
    target_grant_id: str
    target_capability: str

    @field_validator("authorization_id", "source_principal_id", "source_grant_id", "target_principal_id", "target_grant_id")
    @classmethod
    def validate_identity(cls, value: str, info) -> str:
        return validate_identifier(value, label=info.field_name)

    @field_validator("source_provider", "target_provider")
    @classmethod
    def canonicalize_provider(cls, value: str) -> str:
        return resolve_authority_provider_id(value)

    @field_validator("source_capability", "target_capability")
    @classmethod
    def validate_capabilities(cls, value: str) -> str:
        return validate_capability_name(value)

    @field_validator("data_type")
    @classmethod
    def validate_data_type(cls, value: str) -> str:
        return validate_nonempty_text(value, label="data_type")


ScenarioDecision = Literal["allow", "block", "quarantine"]
ContractState = Literal["active", "quarantined", "expired", "revoked"]


class ScenarioRiskCategory(str, Enum):
    """Presentation metadata only; never consumed by security policy."""

    LOW = "low"
    EXCESSIVE_AUTHORITY = "excessive_authority"
    RUNTIME_DRIFT = "runtime_drift"
    COMPOSITION_RISK = "composition_risk"
    MISSING_PERMISSION = "missing_permission"
    PROVIDER_COLLISION = "provider_collision"
    CROSS_PROVIDER = "cross_provider"


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
    providers: List[str] = Field(default_factory=list)
    provider_intents: List[ProviderIntentAssignment] = Field(default_factory=list)
    risk_category: ScenarioRiskCategory
    intended_actions: List[str]
    grant_ids: List[str] = Field(..., min_length=1)
    runtime_attempts: List[ScenarioRuntimeAttempt] = Field(
        default_factory=list
    )
    data_flow_links: List[ScenarioDataFlowLink] = Field(
        default_factory=list
    )
    authorized_flows: List[AuthorizedFlow] = Field(default_factory=list)
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

    @field_validator("providers")
    @classmethod
    def validate_providers(cls, value: List[str]) -> List[str]:
        canonical = [resolve_authority_provider_id(item) for item in value]
        if len(canonical) != len(set(canonical)):
            raise ValueError("providers must contain unique canonical provider IDs")
        return canonical

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
        authorization_ids = [item.authorization_id for item in self.authorized_flows]
        if len(authorization_ids) != len(set(authorization_ids)):
            raise ValueError(f"scenario '{self.scenario_id}' contains duplicate flow authorization IDs")
        for item in self.provider_intents:
            if self.providers and item.provider not in set(self.providers):
                raise ValueError(
                    f"scenario '{self.scenario_id}' intent references undeclared provider '{item.provider}'"
                )
        for flow in self.authorized_flows:
            if flow.source_grant_id not in declared_grants or flow.target_grant_id not in declared_grants:
                raise ValueError(
                    f"scenario '{self.scenario_id}' flow authorization '{flow.authorization_id}' references an undeclared grant"
                )
        return self
