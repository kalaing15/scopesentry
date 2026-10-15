"""HTTP API for temporary intent-locked capability contracts."""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.evidence.service import EvidenceService, get_evidence_service
from app.gateway.repository import ContractRepository, get_contract_repository
from app.gateway.service import (
    ContractPlanConflictError,
    UnknownContractError,
    create_contract,
    evaluate_runtime_action as evaluate_runtime_action_service,
    revoke_contract,
)
from app.planner.analysis_service import UnsupportedAnalysisProviderError
from app.schemas.gateway import (
    CapabilityContract,
    ContractCreateRequest,
    ContractListResponse,
    GatewayEvaluationRequest,
    GatewayEvaluationResponse,
)


router = APIRouter(prefix="/api/v1/gateway", tags=["Runtime Gateway"])


def _not_found(contract_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail=f"Capability contract '{contract_id}' was not found.",
    )


@router.post(
    "/contracts",
    response_model=CapabilityContract,
    status_code=status.HTTP_201_CREATED,
)
def create_capability_contract(
    request: ContractCreateRequest,
    repository: ContractRepository = Depends(get_contract_repository),
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> CapabilityContract:
    try:
        return create_contract(
            request,
            repository=repository,
            evidence_service=evidence_service,
        )
    except UnsupportedAnalysisProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ContractPlanConflictError as exc:
        raise HTTPException(status_code=409, detail=exc.detail) from exc


@router.get("/contracts", response_model=ContractListResponse)
def list_capability_contracts(
    limit: int = Query(default=20, ge=1, le=100),
    repository: ContractRepository = Depends(get_contract_repository),
) -> ContractListResponse:
    contracts = repository.list(limit=limit)
    return ContractListResponse(count=len(contracts), contracts=contracts)


@router.get("/contracts/{contract_id}", response_model=CapabilityContract)
def get_capability_contract(
    contract_id: str,
    repository: ContractRepository = Depends(get_contract_repository),
) -> CapabilityContract:
    contract = repository.get(contract_id)
    if contract is None:
        raise _not_found(contract_id)
    return contract


@router.post(
    "/contracts/{contract_id}/revoke",
    response_model=CapabilityContract,
)
def revoke_capability_contract(
    contract_id: str,
    repository: ContractRepository = Depends(get_contract_repository),
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> CapabilityContract:
    try:
        return revoke_contract(
            contract_id,
            repository=repository,
            evidence_service=evidence_service,
        )
    except UnknownContractError as exc:
        raise _not_found(contract_id) from exc


@router.post("/evaluate", response_model=GatewayEvaluationResponse)
def evaluate_runtime_action(
    request: GatewayEvaluationRequest,
    repository: ContractRepository = Depends(get_contract_repository),
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> GatewayEvaluationResponse:
    try:
        return evaluate_runtime_action_service(
            request,
            repository=repository,
            evidence_service=evidence_service,
        )
    except UnknownContractError as exc:
        raise _not_found(request.contract_id) from exc
