"""Application-facing service for evidence creation and retrieval."""

import os
from pathlib import Path
from typing import Any, List, Optional

from app.evidence.canonical import redact_sensitive_data, sha256_hex
from app.evidence.hash_chain import EvidenceHashChain
from app.schemas.evidence import (
    AnalysisType,
    ChainVerificationResult,
    EvidenceRecord,
    EvidenceReference,
)


DEFAULT_EVIDENCE_PATH = Path("runtime/evidence.jsonl")
ENGINE_VERSION = "0.1.0"


class EvidenceService:
    def __init__(self, path: Path | str, engine_version: str = ENGINE_VERSION):
        self.chain = EvidenceHashChain(path, engine_version=engine_version)

    @property
    def path(self) -> Path:
        return self.chain.path

    def create_record(
        self,
        *,
        analysis_type: AnalysisType,
        request: Any,
        result: Any,
        decision_summary: str,
    ) -> EvidenceReference:
        """Redact, hash, and append evidence for a successful analysis."""
        redacted_request = redact_sensitive_data(request)
        redacted_result = redact_sensitive_data(result)
        redacted_decision = redact_sensitive_data(
            {
                "analysis_type": analysis_type,
                "decision_summary": decision_summary,
            }
        )
        record = self.chain.append(
            analysis_type=analysis_type,
            request_hash=sha256_hex(redacted_request),
            result_hash=sha256_hex(redacted_result),
            decision_hash=sha256_hex(redacted_decision),
            decision_summary=decision_summary,
        )
        return record.reference()

    def verify(self) -> ChainVerificationResult:
        return self.chain.verify()

    def list_records(self, limit: int = 20) -> List[EvidenceRecord]:
        return self.chain.list_records(limit)

    def get_record(self, analysis_id: str) -> Optional[EvidenceRecord]:
        return self.chain.get_record(analysis_id)


def get_evidence_path() -> Path:
    configured_path = os.getenv("SCOPESENTRY_EVIDENCE_PATH")
    return Path(configured_path) if configured_path else DEFAULT_EVIDENCE_PATH


def get_evidence_service() -> EvidenceService:
    """FastAPI dependency resolved per request for easy configuration override."""
    return EvidenceService(get_evidence_path())
