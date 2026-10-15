"""HTTP API for deterministic multi-grant composition analysis."""

from fastapi import APIRouter, Depends, HTTPException

from app.evidence.service import EvidenceService, get_evidence_service
from app.planner.composition_engine import analyze_composition
from app.providers.mock.catalog import resolve_authority_provider_id
from app.schemas.composition import (
    CompositionAnalysisRequest,
    CompositionAnalysisResponse,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["Composition Analysis"],
)


@router.post(
    "/analyze-composition",
    response_model=CompositionAnalysisResponse,
)
def analyze_grant_composition(
    request: CompositionAnalysisRequest,
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> CompositionAnalysisResponse:
    """Analyze the combined authority exposed by multiple OAuth grants."""
    try:
        provider = resolve_authority_provider_id(request.provider)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    try:
        result = analyze_composition(
            provider=provider,
            grants=request.grants,
            intended_actions=request.intended_actions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    evidence_reference = evidence_service.create_record(
        analysis_type="composition",
        request={**request.model_dump(mode="json"), "provider": provider},
        result=result,
        decision_summary=result["recommendation"],
    )
    return CompositionAnalysisResponse(
        **result,
        evidence_reference=evidence_reference,
    )
