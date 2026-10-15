"""HTTP API for deterministic credential-free demonstration scenarios."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app.evidence.service import EvidenceService, get_evidence_service
from app.gateway.repository import ContractRepository, get_contract_repository
from app.orchestrator.demo_runner import DemoRunner, ScenarioNotFoundError
from app.providers.mock.scenarios import get_scenario, list_scenarios
from app.providers.registry import ProviderRegistry, get_provider_registry
from app.schemas.demo import (
    DemoErrorResponse,
    DemoProviderListResponse,
    DemoRunResponse,
    DemoScenarioDetailResponse,
    DemoScenarioListResponse,
    DemoScenarioSummary,
)


router = APIRouter(prefix="/api/v1/demo", tags=["Demo Scenarios"])


def _unknown_scenario(scenario_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail=f"Demo scenario '{scenario_id}' was not found.",
    )


async def reject_unexpected_run_body(request: Request) -> None:
    """Reject every nonempty body using bytes, independent of headers/type."""
    if await request.body() != b"":
        raise HTTPException(
            status_code=400,
            detail="This endpoint accepts no request body.",
        )


@router.get("/providers", response_model=DemoProviderListResponse)
def list_demo_providers(
    registry: ProviderRegistry = Depends(get_provider_registry),
) -> DemoProviderListResponse:
    providers = registry.list_metadata()
    return DemoProviderListResponse(count=len(providers), providers=providers)


@router.get("/scenarios", response_model=DemoScenarioListResponse)
def list_demo_scenarios() -> DemoScenarioListResponse:
    scenarios = [
        DemoScenarioSummary(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            provider=scenario.provider,
            risk_category=scenario.risk_category,
            description=scenario.description,
            expected_outcome=scenario.expected_outcome,
        )
        for scenario in list_scenarios()
    ]
    return DemoScenarioListResponse(count=len(scenarios), scenarios=scenarios)


@router.get(
    "/scenarios/{scenario_id}",
    response_model=DemoScenarioDetailResponse,
    response_model_exclude_none=True,
)
def get_demo_scenario(
    scenario_id: str,
    registry: ProviderRegistry = Depends(get_provider_registry),
) -> DemoScenarioDetailResponse:
    scenario = get_scenario(scenario_id)
    if scenario is None:
        raise _unknown_scenario(scenario_id)
    adapter = registry.get(scenario.provider)
    return DemoScenarioDetailResponse(
        scenario=scenario,
        grants=[adapter.get_grant(grant_id) for grant_id in scenario.grant_ids],
    )


@router.post(
    "/scenarios/{scenario_id}/run",
    response_model=DemoRunResponse,
    responses={
        400: {
            "model": DemoErrorResponse,
            "description": "A nonempty request body was supplied.",
        },
        404: {
            "model": DemoErrorResponse,
            "description": "The scenario ID is unknown.",
        },
        422: {"description": "Request validation failed."},
    },
)
def run_demo_scenario(
    scenario_id: str,
    _empty_body: None = Depends(reject_unexpected_run_body),
    registry: ProviderRegistry = Depends(get_provider_registry),
    repository: ContractRepository = Depends(get_contract_repository),
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> DemoRunResponse:
    runner = DemoRunner(
        registry=registry,
        repository=repository,
        evidence_service=evidence_service,
    )
    try:
        return runner.run(scenario_id)
    except ScenarioNotFoundError as exc:
        raise _unknown_scenario(scenario_id) from exc
