"""API models for deterministic end-to-end demonstration scenarios."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.evidence import EvidenceReference
from app.schemas.analysis import LeastPrivilegePlan
from app.schemas.provider import (
    DemoScenarioDefinition,
    MockGrant,
    ProviderMetadata,
    ScenarioRiskCategory,
)


class TimelineStatus(str, Enum):
    """Closed workflow statuses; legacy complete/completed are both retained."""

    COMPLETED = "completed"
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    MANUAL_REVIEW = "manual_review"
    RISK_DETECTED = "risk_detected"
    SKIPPED = "skipped"
    FAILED = "failed"


class DemoTimelineEntry(BaseModel):
    step_number: int = Field(..., ge=1)
    stage: str
    status: TimelineStatus
    summary: str
    important_values: Dict[str, Any] = Field(default_factory=dict)
    evidence_reference: Optional[EvidenceReference] = None


class DemoScenarioSummary(BaseModel):
    scenario_id: str
    scenario_name: str
    provider: str
    risk_category: ScenarioRiskCategory
    description: str
    expected_outcome: str


class DemoProviderListResponse(BaseModel):
    count: int = Field(..., ge=0)
    providers: List[ProviderMetadata]


class DemoScenarioListResponse(BaseModel):
    count: int = Field(..., ge=0)
    scenarios: List[DemoScenarioSummary]


class DemoScenarioDetailResponse(BaseModel):
    scenario: DemoScenarioDefinition
    grants: List[MockGrant]


class DemoErrorResponse(BaseModel):
    detail: str


class DemoAnalysisSummary(BaseModel):
    provider: str
    catalog_provider: str
    granted_scopes: List[str]
    required_scopes: List[str]
    matched_scopes: List[str]
    excessive_scopes: List[str]
    missing_scopes: List[str]
    required_capabilities: List[str]
    granted_capabilities: List[str]
    missing_capabilities: List[str]
    excessive_capabilities: List[str]
    exposure_score: float
    least_privilege_plan: LeastPrivilegePlan
    recommendation: str


class DemoRunResponse(BaseModel):
    scenario_id: str
    scenario_name: str
    expected_outcome: str
    actual_outcome: Dict[str, Any]
    passed: bool
    timeline: List[DemoTimelineEntry]
    analysis_summary: DemoAnalysisSummary
    composition_summary: Optional[Dict[str, Any]] = None
    contract_summary: Optional[Dict[str, Any]] = None
    gateway_decisions: List[Dict[str, Any]]
    evidence_chain_valid: bool
