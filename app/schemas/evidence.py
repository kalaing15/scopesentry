"""Pydantic models for tamper-evident analysis records."""

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


HASH_PATTERN = r"^[0-9a-f]{64}$"
AnalysisType = Literal[
    "single_grant",
    "composition",
    "contract_created",
    "gateway_decision",
    "contract_revoked",
    "contract_quarantined",
    "contract_expired",
    "demo_completion",
]


class EvidenceReference(BaseModel):
    """Stable reference returned with a successful analysis."""

    analysis_id: str
    sequence_number: int = Field(..., ge=1)
    record_hash: str = Field(..., pattern=HASH_PATTERN)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class EvidenceRecord(EvidenceReference):
    """One immutable logical entry in the evidence hash chain."""

    analysis_type: AnalysisType
    engine_version: str
    request_hash: str = Field(..., pattern=HASH_PATTERN)
    result_hash: str = Field(..., pattern=HASH_PATTERN)
    decision_hash: str = Field(..., pattern=HASH_PATTERN)
    previous_record_hash: str = Field(..., pattern=HASH_PATTERN)
    decision_summary: str

    def reference(self) -> EvidenceReference:
        return EvidenceReference(
            analysis_id=self.analysis_id,
            sequence_number=self.sequence_number,
            record_hash=self.record_hash,
            created_at=self.created_at,
        )


class ChainVerificationResult(BaseModel):
    valid: bool
    records_checked: int = Field(..., ge=0)
    head_hash: str = Field(..., pattern=HASH_PATTERN)
    first_invalid_sequence: Optional[int] = Field(default=None, ge=1)
    message: str


class EvidenceRecordListResponse(BaseModel):
    count: int = Field(..., ge=0)
    records: List[EvidenceRecord]
