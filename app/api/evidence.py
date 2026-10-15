"""Read-only API for evidence-chain verification and record metadata."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.evidence.hash_chain import EvidenceChainError
from app.evidence.service import EvidenceService, get_evidence_service
from app.schemas.evidence import (
    ChainVerificationResult,
    EvidenceRecord,
    EvidenceRecordListResponse,
)


router = APIRouter(
    prefix="/api/v1/evidence",
    tags=["Evidence"],
)


@router.get("/verify", response_model=ChainVerificationResult)
def verify_evidence_chain(
    service: EvidenceService = Depends(get_evidence_service),
) -> ChainVerificationResult:
    return service.verify()


@router.get("/records", response_model=EvidenceRecordListResponse)
def list_evidence_records(
    limit: int = Query(default=20, ge=1, le=100),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceRecordListResponse:
    try:
        records = service.list_records(limit)
    except EvidenceChainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return EvidenceRecordListResponse(count=len(records), records=records)


@router.get("/records/{analysis_id}", response_model=EvidenceRecord)
def get_evidence_record(
    analysis_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceRecord:
    try:
        record = service.get_record(analysis_id)
    except EvidenceChainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    return record
