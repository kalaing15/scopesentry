"""Tests for capability contracts, runtime policy, and gateway evidence."""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.gateway.contracts import (
    build_contract_payload,
    calculate_scope_fingerprint,
    finalize_contract,
)
from app.main import app


CREATE_REQUEST = {
    "provider": "google",
    "granted_scopes": ["drive.readonly", "gmail.readonly"],
    "intended_actions": ["read files"],
    "ttl_seconds": 3600,
}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def contract(client):
    response = client.post("/api/v1/gateway/contracts", json=CREATE_REQUEST)
    assert response.status_code == 201
    return response.json()


def _evaluate(client, contract_id, capability, scopes):
    return client.post(
        "/api/v1/gateway/evaluate",
        json={
            "contract_id": contract_id,
            "attempted_capability": capability,
            "observed_scopes": scopes,
            "resource_reference": "document:example",
        },
    )


def _records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestContractCreation:
    def test_successful_contract_creation(self, client):
        response = client.post(
            "/api/v1/gateway/contracts",
            json=CREATE_REQUEST,
        )

        assert response.status_code == 201
        body = response.json()
        assert body["provider"] == "google"
        assert body["state"] == "active"
        assert body["intended_actions"] == ["read_files"]
        assert body["expires_at"] > body["created_at"]
        assert len(body["source_evidence_hash"]) == 64

        lookup = client.get(
            f"/api/v1/gateway/contracts/{body['contract_id']}"
        )
        assert lookup.status_code == 200
        assert lookup.json() == body

    def test_excessive_scopes_do_not_enter_contract(self, contract):
        assert contract["allowed_scopes"] == ["drive.readonly"]
        assert "gmail.readonly" not in contract["allowed_scopes"]
        assert "read_file_contents" in contract["allowed_capabilities"]
        assert "read_email_messages" not in contract["allowed_capabilities"]

    def test_unknown_intent_prevents_contract_creation(
        self,
        client,
        isolated_evidence_path,
    ):
        request = {
            **CREATE_REQUEST,
            "intended_actions": ["read files", "launch spacecraft"],
        }
        response = client.post("/api/v1/gateway/contracts", json=request)

        assert response.status_code == 409
        assert response.json()["detail"]["plan_status"] == "manual_review"
        assert response.json()["detail"]["unknown_intents"] == [
            "launch spacecraft"
        ]
        assert not isolated_evidence_path.exists()

    def test_unsupported_provider_returns_400(self, client):
        response = client.post(
            "/api/v1/gateway/contracts",
            json={**CREATE_REQUEST, "provider": "unsupported"},
        )

        assert response.status_code == 400
        assert "Unsupported provider" in response.json()["detail"]

    def test_complete_plan_is_required(self, client, monkeypatch):
        from app.gateway import service as gateway_service

        def incomplete_plan(**_kwargs):
            return {
                "status": "incomplete",
                "uncovered_capabilities": ["read_file_contents"],
                "explanation": "Catalogue coverage is incomplete.",
            }

        monkeypatch.setattr(
            gateway_service,
            "analyze_scope_grant",
            lambda **_kwargs: {
                "provider": "google",
                "unknown_intents": [],
                "required_capabilities": ["read_file_contents"],
                "least_privilege_plan": incomplete_plan(),
            },
        )
        response = client.post(
            "/api/v1/gateway/contracts",
            json=CREATE_REQUEST,
        )

        assert response.status_code == 409
        assert response.json()["detail"]["plan_status"] == "incomplete"

    def test_scope_fingerprint_is_deterministic(self):
        first = calculate_scope_fingerprint(
            [" Gmail.ReadOnly ", "drive.readonly", "drive.readonly"]
        )
        second = calculate_scope_fingerprint(
            ["drive.readonly", "gmail.readonly"]
        )

        assert first == second
        assert len(first) == 64

    def test_contract_list_is_bounded(self, client, contract):
        limited = client.get("/api/v1/gateway/contracts?limit=1")
        too_small = client.get("/api/v1/gateway/contracts?limit=0")
        too_large = client.get("/api/v1/gateway/contracts?limit=101")

        assert limited.status_code == 200
        assert limited.json()["count"] == 1
        assert limited.json()["contracts"][0]["contract_id"] == (
            contract["contract_id"]
        )
        assert too_small.status_code == 422
        assert too_large.status_code == 422

    def test_repository_returns_defensive_copies(
        self,
        contract,
        isolated_contract_repository,
    ):
        stored = isolated_contract_repository.get(contract["contract_id"])
        assert stored is not None
        stored.allowed_scopes.append("gmail.readonly")

        fresh = isolated_contract_repository.get(contract["contract_id"])
        assert fresh is not None
        assert fresh.allowed_scopes == ["drive.readonly"]


class TestRuntimeEvaluation:
    def test_allowed_capability_returns_allow(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly"],
        )

        assert response.status_code == 200
        assert response.json()["decision"] == "allow"
        assert response.json()["reason_code"] == "capability_allowed"
        assert response.json()["scope_drift"] is False

    def test_unauthorized_capability_returns_block(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_email_messages",
            ["drive.readonly"],
        )

        assert response.status_code == 200
        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "capability_not_allowed"

    def test_extra_observed_scope_triggers_quarantine(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly", "gmail.readonly"],
        )

        assert response.status_code == 200
        assert response.json()["decision"] == "quarantine"
        assert response.json()["contract_state"] == "quarantined"
        assert response.json()["unexpected_scopes"] == ["gmail.readonly"]
        stored = client.get(
            f"/api/v1/gateway/contracts/{contract['contract_id']}"
        )
        assert stored.json()["state"] == "quarantined"

    def test_quarantined_contract_remains_blocked(self, client, contract):
        _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly", "gmail.readonly"],
        )
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly"],
        )

        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "contract_quarantined"
        assert response.json()["contract_state"] == "quarantined"

    def test_missing_required_scope_returns_block(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            [],
        )

        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "missing_required_scopes"
        assert response.json()["missing_scopes"] == ["drive.readonly"]

    def test_expired_contract_returns_block(
        self,
        client,
        isolated_contract_repository,
    ):
        payload = build_contract_payload(
            provider="google",
            intended_actions=["read files"],
            allowed_scopes=["drive.readonly"],
            allowed_capabilities=["read_file_contents"],
            ttl_seconds=60,
            now=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        expired = finalize_contract(
            payload,
            source_analysis_id="expired-source",
            source_evidence_hash="0" * 64,
        )
        isolated_contract_repository.create(expired)

        response = _evaluate(
            client,
            expired.contract_id,
            "read_file_contents",
            ["drive.readonly"],
        )

        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "contract_expired"
        assert response.json()["contract_state"] == "expired"
        assert isolated_contract_repository.get(expired.contract_id).state == (
            "expired"
        )

    def test_revoked_contract_returns_block(self, client, contract):
        revoked = client.post(
            f"/api/v1/gateway/contracts/{contract['contract_id']}/revoke"
        )
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly"],
        )

        assert revoked.status_code == 200
        assert revoked.json()["state"] == "revoked"
        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "contract_revoked"

    def test_revocation_is_idempotent(
        self,
        client,
        contract,
        isolated_evidence_path,
    ):
        path = f"/api/v1/gateway/contracts/{contract['contract_id']}/revoke"
        first = client.post(path)
        record_count = len(_records(isolated_evidence_path))
        second = client.post(path)

        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        assert second.json()["state"] == "revoked"
        assert len(_records(isolated_evidence_path)) == record_count

    def test_unknown_contract_returns_404(self, client):
        response = _evaluate(
            client,
            "unknown-contract",
            "read_file_contents",
            ["drive.readonly"],
        )

        assert response.status_code == 404

    def test_duplicate_observed_scopes_are_normalized(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            [" drive.readonly ", "DRIVE.READONLY", "drive.readonly"],
        )

        assert response.json()["decision"] == "allow"
        assert response.json()["unexpected_scopes"] == []
        assert response.json()["missing_scopes"] == []

    def test_unknown_scopes_are_never_trusted(self, client, contract):
        response = _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly", "unknown.superuser"],
        )

        assert response.json()["decision"] == "quarantine"
        assert response.json()["unexpected_scopes"] == [
            "unknown.superuser"
        ]


class TestGatewayEvidence:
    def test_allow_block_and_quarantine_create_evidence(
        self,
        client,
        contract,
        isolated_evidence_path,
    ):
        for capability, scopes in [
            ("read_file_contents", ["drive.readonly"]),
            ("read_email_messages", ["drive.readonly"]),
            (
                "read_file_contents",
                ["drive.readonly", "gmail.readonly"],
            ),
        ]:
            response = _evaluate(
                client,
                contract["contract_id"],
                capability,
                scopes,
            )
            assert response.status_code == 200
            assert len(response.json()["evidence_reference"]["record_hash"]) == 64

        types = [
            record["analysis_type"]
            for record in _records(isolated_evidence_path)
        ]
        assert types.count("gateway_decision") == 3
        assert types.count("contract_quarantined") == 1

    def test_chain_verifies_after_gateway_decisions(self, client, contract):
        _evaluate(
            client,
            contract["contract_id"],
            "read_file_contents",
            ["drive.readonly"],
        )
        _evaluate(
            client,
            contract["contract_id"],
            "read_email_messages",
            ["drive.readonly"],
        )

        verification = client.get("/api/v1/evidence/verify")

        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert verification.json()["records_checked"] == 3
