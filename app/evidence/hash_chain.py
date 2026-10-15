"""Append-only JSON Lines storage and complete evidence-chain verification."""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import ValidationError

from app.evidence.canonical import canonical_json_bytes, sha256_hex
from app.schemas.evidence import (
    AnalysisType,
    ChainVerificationResult,
    EvidenceRecord,
)


GENESIS_HASH = "0" * 64


class EvidenceChainError(RuntimeError):
    """Raised when safe append or retrieval is impossible."""


class EvidenceHashChain:
    """File-backed append-only evidence chain with per-path process locks."""

    _locks_guard = threading.Lock()
    _locks: Dict[str, threading.RLock] = {}

    def __init__(self, path: Path | str, engine_version: str = "0.1.0"):
        self.path = Path(path)
        self.engine_version = engine_version
        lock_key = str(self.path.resolve())
        with self._locks_guard:
            self._lock = self._locks.setdefault(lock_key, threading.RLock())

    def append(
        self,
        *,
        analysis_type: AnalysisType,
        request_hash: str,
        result_hash: str,
        decision_hash: str,
        decision_summary: str,
    ) -> EvidenceRecord:
        """Append exactly one record after verifying the existing chain."""
        with self._lock:
            verification = self._verify_unlocked()
            if not verification.valid:
                raise EvidenceChainError(
                    "Refusing to append to an invalid evidence chain: "
                    f"{verification.message}"
                )

            records = self._load_records_unlocked()
            previous_hash = (
                records[-1].record_hash if records else GENESIS_HASH
            )
            payload: Dict[str, Any] = {
                "sequence_number": len(records) + 1,
                "analysis_id": str(uuid4()),
                "analysis_type": analysis_type,
                "created_at": datetime.now(timezone.utc),
                "engine_version": self.engine_version,
                "request_hash": request_hash,
                "result_hash": result_hash,
                "decision_hash": decision_hash,
                "previous_record_hash": previous_hash,
                "decision_summary": decision_summary,
            }
            record = EvidenceRecord(
                **payload,
                record_hash=sha256_hex(payload),
            )

            self.path.parent.mkdir(parents=True, exist_ok=True)
            encoded_record = canonical_json_bytes(record)
            with self.path.open("ab+") as stream:
                stream.seek(0, os.SEEK_END)
                if stream.tell() > 0:
                    stream.seek(-1, os.SEEK_END)
                    if stream.read(1) != b"\n":
                        stream.seek(0, os.SEEK_END)
                        stream.write(b"\n")
                stream.seek(0, os.SEEK_END)
                stream.write(encoded_record + b"\n")
                stream.flush()
                os.fsync(stream.fileno())

            return record

    def verify(self) -> ChainVerificationResult:
        with self._lock:
            return self._verify_unlocked()

    def list_records(self, limit: int = 20) -> List[EvidenceRecord]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            self._require_valid_chain_unlocked()
            records = self._load_records_unlocked()
            return records[-limit:]

    def get_record(self, analysis_id: str) -> Optional[EvidenceRecord]:
        with self._lock:
            self._require_valid_chain_unlocked()
            for record in self._load_records_unlocked():
                if record.analysis_id == analysis_id:
                    return record
            return None

    def _require_valid_chain_unlocked(self) -> None:
        verification = self._verify_unlocked()
        if not verification.valid:
            raise EvidenceChainError(verification.message)

    def _read_lines_unlocked(self) -> List[str]:
        if not self.path.exists():
            return []
        return self.path.read_text(encoding="utf-8").splitlines()

    def _load_records_unlocked(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for line in self._read_lines_unlocked():
            records.append(EvidenceRecord.model_validate(json.loads(line)))
        return records

    def _invalid_result(
        self,
        *,
        checked: int,
        head_hash: str,
        sequence: int,
        message: str,
    ) -> ChainVerificationResult:
        return ChainVerificationResult(
            valid=False,
            records_checked=checked,
            head_hash=head_hash,
            first_invalid_sequence=max(sequence, 1),
            message=message,
        )

    def _verify_unlocked(self) -> ChainVerificationResult:
        lines = self._read_lines_unlocked()
        if not lines:
            return ChainVerificationResult(
                valid=True,
                records_checked=0,
                head_hash=GENESIS_HASH,
                first_invalid_sequence=None,
                message="Evidence chain is empty and valid.",
            )

        expected_sequence = 1
        previous_hash = GENESIS_HASH
        checked = 0

        for line in lines:
            try:
                raw_record = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                return self._invalid_result(
                    checked=checked,
                    head_hash=previous_hash,
                    sequence=expected_sequence,
                    message=(
                        f"Invalid JSON at expected sequence "
                        f"{expected_sequence}: {exc.msg if hasattr(exc, 'msg') else exc}"
                    ),
                )

            try:
                record = EvidenceRecord.model_validate(raw_record)
            except ValidationError as exc:
                raw_sequence = raw_record.get("sequence_number")
                invalid_sequence = (
                    raw_sequence
                    if isinstance(raw_sequence, int) and raw_sequence > 0
                    else expected_sequence
                )
                return self._invalid_result(
                    checked=checked,
                    head_hash=previous_hash,
                    sequence=invalid_sequence,
                    message=f"Invalid evidence record: {exc.errors()[0]['msg']}",
                )

            if record.sequence_number != expected_sequence:
                return self._invalid_result(
                    checked=checked,
                    head_hash=previous_hash,
                    sequence=expected_sequence,
                    message=(
                        f"Expected sequence {expected_sequence}, found "
                        f"{record.sequence_number}."
                    ),
                )

            if record.previous_record_hash != previous_hash:
                return self._invalid_result(
                    checked=checked,
                    head_hash=previous_hash,
                    sequence=record.sequence_number,
                    message=(
                        "Previous record hash does not match at sequence "
                        f"{record.sequence_number}."
                    ),
                )

            recalculated = sha256_hex(
                record.model_dump(mode="python", exclude={"record_hash"})
            )
            if record.record_hash != recalculated:
                return self._invalid_result(
                    checked=checked,
                    head_hash=previous_hash,
                    sequence=record.sequence_number,
                    message=(
                        f"Record hash mismatch at sequence "
                        f"{record.sequence_number}."
                    ),
                )

            checked += 1
            expected_sequence += 1
            previous_hash = record.record_hash

        return ChainVerificationResult(
            valid=True,
            records_checked=checked,
            head_hash=previous_hash,
            first_invalid_sequence=None,
            message=f"Evidence chain is valid ({checked} records checked).",
        )
