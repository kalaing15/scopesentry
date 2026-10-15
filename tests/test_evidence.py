"""Tests for canonical hashing, evidence storage, APIs, and tamper checks."""

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.evidence.canonical import (
    REDACTED_VALUE,
    canonical_json_bytes,
    redact_sensitive_data,
    sha256_hex,
)
from app.evidence.hash_chain import GENESIS_HASH
from app.evidence.service import EvidenceService
from app.main import app


class ExampleKind(str, Enum):
    SAMPLE = "sample"


class ExampleModel(BaseModel):
    identifier: UUID
    created_at: datetime
    kind: ExampleKind


def _create_record(service: EvidenceService, number: int = 1):
    reference = service.create_record(
        analysis_type="single_grant",
        request={"request_number": number},
        result={"status": "complete", "number": number},
        decision_summary=f"Decision {number}",
    )
    record = service.get_record(reference.analysis_id)
    assert record is not None
    return record


def _read_raw_records(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def _write_raw_records(path: Path, records) -> None:
    payload = b"\n".join(canonical_json_bytes(record) for record in records)
    path.write_bytes(payload + b"\n")


class TestCanonicalJson:
    def test_stable_across_dictionary_ordering(self):
        first = {"z": 1, "nested": {"b": 2, "a": [3, 4]}}
        second = {"nested": {"a": [3, 4], "b": 2}, "z": 1}

        assert canonical_json_bytes(first) == canonical_json_bytes(second)
        assert sha256_hex(first) == sha256_hex(second)

    def test_different_content_has_different_hash(self):
        assert sha256_hex({"value": 1}) != sha256_hex({"value": 2})

    def test_models_datetimes_uuids_and_enums_are_supported(self):
        model = ExampleModel(
            identifier=UUID("12345678-1234-5678-1234-567812345678"),
            created_at=datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc),
            kind=ExampleKind.SAMPLE,
        )

        encoded = canonical_json_bytes(model).decode("utf-8")

        assert '"created_at":"2026-01-02T03:04:00Z"' in encoded
        assert '"identifier":"12345678-1234-5678-1234-567812345678"' in encoded
        assert '"kind":"sample"' in encoded

    def test_unsupported_values_are_rejected(self):
        with pytest.raises(TypeError, match="Unsupported canonical JSON"):
            canonical_json_bytes({"unsupported": {1, 2}})

    def test_nested_credentials_are_redacted(self):
        payload = {
            "access_token": "secret-access",
            "nested": {
                "refreshToken": "secret-refresh",
                "safe": "visible",
                "items": [
                    {"client-secret": "secret-client"},
                    {"api_key_value": "secret-key"},
                    {"cookieJar": "secret-cookie"},
                ],
            },
            "AuthorizationHeader": "Bearer secret",
            "password_hash": "secret-password",
        }

        redacted = redact_sensitive_data(payload)

        assert redacted["access_token"] == REDACTED_VALUE
        assert redacted["AuthorizationHeader"] == REDACTED_VALUE
        assert redacted["password_hash"] == REDACTED_VALUE
        assert redacted["nested"]["refreshToken"] == REDACTED_VALUE
        assert redacted["nested"]["safe"] == "visible"
        assert redacted["nested"]["items"][0]["client-secret"] == REDACTED_VALUE
        assert redacted["nested"]["items"][1]["api_key_value"] == REDACTED_VALUE
        assert redacted["nested"]["items"][2]["cookieJar"] == REDACTED_VALUE


class TestEvidenceHashChain:
    def test_genesis_record_creation(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        record = _create_record(service)

        assert record.sequence_number == 1
        assert record.previous_record_hash == GENESIS_HASH
        assert len(record.record_hash) == 64
        assert record.created_at.tzinfo is not None

    def test_multiple_records_form_valid_chain(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        first = _create_record(service, 1)
        second = _create_record(service, 2)

        verification = service.verify()
        assert second.previous_record_hash == first.record_hash
        assert verification.valid is True
        assert verification.records_checked == 2
        assert verification.head_hash == second.record_hash

    def test_modified_content_is_detected(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        _create_record(service)
        records = _read_raw_records(isolated_evidence_path)
        records[0]["decision_summary"] = "Tampered decision"
        _write_raw_records(isolated_evidence_path, records)

        verification = service.verify()
        assert verification.valid is False
        assert verification.first_invalid_sequence == 1
        assert "hash mismatch" in verification.message.lower()

    def test_deleted_middle_record_is_detected(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        for number in range(1, 4):
            _create_record(service, number)
        records = _read_raw_records(isolated_evidence_path)
        del records[1]
        _write_raw_records(isolated_evidence_path, records)

        verification = service.verify()
        assert verification.valid is False
        assert verification.first_invalid_sequence == 2
        assert "expected sequence 2" in verification.message.lower()

    def test_reordered_records_are_detected(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        _create_record(service, 1)
        _create_record(service, 2)
        records = _read_raw_records(isolated_evidence_path)
        records.reverse()
        _write_raw_records(isolated_evidence_path, records)

        verification = service.verify()
        assert verification.valid is False
        assert verification.first_invalid_sequence == 1

    def test_invalid_json_is_detected(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        _create_record(service)
        with isolated_evidence_path.open("a", encoding="utf-8") as stream:
            stream.write("{not-json}\n")

        verification = service.verify()
        assert verification.valid is False
        assert verification.records_checked == 1
        assert verification.first_invalid_sequence == 2
        assert "invalid json" in verification.message.lower()

    def test_broken_previous_hash_is_detected(self, isolated_evidence_path):
        service = EvidenceService(isolated_evidence_path)
        _create_record(service, 1)
        _create_record(service, 2)
        records = _read_raw_records(isolated_evidence_path)
        records[1]["previous_record_hash"] = "f" * 64
        records[1]["record_hash"] = sha256_hex(
            {
                key: value
                for key, value in records[1].items()
                if key != "record_hash"
            }
        )
        _write_raw_records(isolated_evidence_path, records)

        verification = service.verify()
        assert verification.valid is False
        assert verification.first_invalid_sequence == 2
        assert "previous record hash" in verification.message.lower()

    def test_empty_chain_is_valid(self, isolated_evidence_path):
        verification = EvidenceService(isolated_evidence_path).verify()

        assert verification.valid is True
        assert verification.records_checked == 0
        assert verification.head_hash == GENESIS_HASH
        assert verification.first_invalid_sequence is None


class TestEvidenceIntegration:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_single_grant_analysis_creates_record(
        self,
        client,
        isolated_evidence_path,
    ):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
            },
        )

        assert response.status_code == 200
        reference = response.json()["evidence_reference"]
        records = _read_raw_records(isolated_evidence_path)
        assert reference["sequence_number"] == 1
        assert records[0]["analysis_type"] == "single_grant"
        assert records[0]["analysis_id"] == reference["analysis_id"]

        result_without_reference = response.json()
        result_without_reference.pop("evidence_reference")
        assert records[0]["result_hash"] == sha256_hex(
            redact_sensitive_data(result_without_reference)
        )

    def test_composition_analysis_creates_record(
        self,
        client,
        isolated_evidence_path,
    ):
        response = client.post(
            "/api/v1/analyze-composition",
            json={
                "provider": "google",
                "grants": [
                    {
                        "grant_id": "files",
                        "granted_scopes": ["drive.readonly"],
                    },
                    {
                        "grant_id": "mail",
                        "granted_scopes": ["gmail.send"],
                    },
                ],
                "intended_actions": ["read files", "send email"],
            },
        )

        assert response.status_code == 200
        records = _read_raw_records(isolated_evidence_path)
        assert len(records) == 1
        assert records[0]["analysis_type"] == "composition"
        assert response.json()["evidence_reference"]["record_hash"] == (
            records[0]["record_hash"]
        )

    def test_failed_requests_do_not_create_evidence(
        self,
        client,
        isolated_evidence_path,
    ):
        unsupported = client.post(
            "/api/v1/analyze",
            json={
                "provider": "unsupported",
                "granted_scopes": [],
                "intended_actions": [],
            },
        )
        invalid = client.post("/api/v1/analyze-composition", json={})

        assert unsupported.status_code == 400
        assert invalid.status_code == 422
        assert not isolated_evidence_path.exists()

    def test_evidence_lookup_by_analysis_id(self, client):
        analysis = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
            },
        ).json()
        analysis_id = analysis["evidence_reference"]["analysis_id"]

        response = client.get(f"/api/v1/evidence/records/{analysis_id}")

        assert response.status_code == 200
        assert response.json()["analysis_id"] == analysis_id
        assert response.json()["decision_summary"]
        assert "access_token" not in response.text

    def test_evidence_list_limit_validation(self, client):
        for _ in range(2):
            response = client.post(
                "/api/v1/analyze",
                json={
                    "provider": "google",
                    "granted_scopes": ["drive.readonly"],
                    "intended_actions": ["read files"],
                },
            )
            assert response.status_code == 200

        limited = client.get("/api/v1/evidence/records?limit=1")
        too_small = client.get("/api/v1/evidence/records?limit=0")
        too_large = client.get("/api/v1/evidence/records?limit=101")

        assert limited.status_code == 200
        assert limited.json()["count"] == 1
        assert limited.json()["records"][0]["sequence_number"] == 2
        assert too_small.status_code == 422
        assert too_large.status_code == 422

    def test_verify_endpoint_handles_empty_chain(self, client):
        response = client.get("/api/v1/evidence/verify")

        assert response.status_code == 200
        assert response.json() == {
            "valid": True,
            "records_checked": 0,
            "head_hash": GENESIS_HASH,
            "first_invalid_sequence": None,
            "message": "Evidence chain is empty and valid.",
        }
