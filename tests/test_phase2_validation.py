"""Phase 2 negative, compatibility, and fail-closed regression tests."""

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.providers.mock.scenarios import (
    MockFixtureValidationError,
    get_grant_fixtures,
    get_scenario,
    validate_grant_fixture,
    validate_scenario_fixture,
)
from app.schemas.demo import DemoTimelineEntry
from app.schemas.provider import ScenarioExpectations


@pytest.fixture
def client():
    return TestClient(app)


def _scenario_payload(scenario_id: str = "safe-file-reader"):
    scenario = get_scenario(scenario_id)
    assert scenario is not None
    return scenario.model_dump(mode="json", exclude_none=True)


class TestTypedExpectationsAndTimeline:
    def test_unknown_expectation_key_is_rejected(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ScenarioExpectations.model_validate({"decison": "allow"})

    def test_incorrect_expectation_type_is_rejected(self):
        with pytest.raises(ValidationError):
            ScenarioExpectations.model_validate(
                {"unauthorized_path_count": "1"}
            )

    def test_invalid_timeline_status_is_rejected(self):
        with pytest.raises(ValidationError):
            DemoTimelineEntry(
                step_number=1,
                stage="test",
                status="allowed",
                summary="Invalid status should not serialize.",
            )

    def test_scenario_detail_omits_unset_expectation_fields(self, client):
        response = client.get("/api/v1/demo/scenarios/safe-file-reader")

        assert response.status_code == 200
        values = response.json()["scenario"]["expected_values"]
        assert values == {"decision": "allow", "excessive_scopes": []}


class TestFixtureIntegrity:
    @pytest.mark.parametrize(
        ("mutation", "message"),
        [
            (
                lambda payload: payload["runtime_attempts"][0].update(
                    grant_id="unknown-grant"
                ),
                "undeclared grant 'unknown-grant'",
            ),
            (
                lambda payload: payload.update(
                    grant_ids=["safe-reader-grant", "safe-reader-grant"]
                ),
                "grant_ids must be unique",
            ),
            (
                lambda payload: payload.update(grant_ids=[""]),
                "grant_id must not be empty",
            ),
        ],
    )
    def test_invalid_grant_references_and_ids_are_rejected(
        self, mutation, message
    ):
        payload = _scenario_payload()
        mutation(payload)

        with pytest.raises(MockFixtureValidationError, match=message):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    @pytest.mark.parametrize(
        ("field", "unknown_id", "role"),
        [
            ("source_grant_id", "unknown-source", "source"),
            ("target_grant_id", "unknown-destination", "destination"),
        ],
    )
    def test_unknown_data_flow_references_are_rejected(
        self, field, unknown_id, role
    ):
        payload = _scenario_payload("composed-exfiltration-path")
        payload["data_flow_links"][0][field] = unknown_id

        with pytest.raises(
            MockFixtureValidationError,
            match=f"undeclared {role} grant '{unknown_id}'",
        ):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    def test_declared_but_globally_unknown_grant_is_rejected(self):
        payload = _scenario_payload()
        payload["grant_ids"] = ["not-in-catalogue"]
        payload["runtime_attempts"] = []

        with pytest.raises(
            MockFixtureValidationError, match="absent from the mock grant catalogue"
        ):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    def test_duplicate_link_ids_are_rejected(self):
        payload = _scenario_payload("composed-exfiltration-path")
        payload["data_flow_links"].append(
            deepcopy(payload["data_flow_links"][0])
        )

        with pytest.raises(MockFixtureValidationError, match="duplicate data-flow"):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    @pytest.mark.parametrize("link_id", ["", "   "])
    def test_empty_link_ids_are_rejected(self, link_id):
        payload = _scenario_payload("composed-exfiltration-path")
        payload["data_flow_links"][0]["link_id"] = link_id

        with pytest.raises(MockFixtureValidationError, match="link_id"):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    def test_self_referencing_link_is_rejected(self):
        payload = _scenario_payload("composed-exfiltration-path")
        payload["data_flow_links"][0]["target_grant_id"] = (
            payload["data_flow_links"][0]["source_grant_id"]
        )

        with pytest.raises(MockFixtureValidationError, match="same source"):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    def test_static_duplicate_and_unknown_scopes_are_rejected(self):
        grant = get_grant_fixtures()["safe-reader-grant"].model_dump(mode="json")
        duplicate = deepcopy(grant)
        duplicate["granted_scopes"].append("DRIVE.READONLY")
        unknown = deepcopy(grant)
        unknown["granted_scopes"] = ["unknown.wellformed"]

        with pytest.raises(MockFixtureValidationError, match="duplicate scope"):
            validate_grant_fixture("safe-reader-grant", duplicate)
        with pytest.raises(MockFixtureValidationError, match="unknown catalogue"):
            validate_grant_fixture("safe-reader-grant", unknown)

    def test_unsupported_runtime_capability_is_rejected(self):
        payload = _scenario_payload()
        payload["runtime_attempts"][0]["capability"] = "unknown_capability"

        with pytest.raises(
            MockFixtureValidationError, match="unsupported runtime capabilities"
        ):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

    def test_invalid_fixture_causes_no_partial_execution(
        self, isolated_evidence_path, isolated_contract_repository
    ):
        payload = _scenario_payload()
        payload["runtime_attempts"][0]["grant_id"] = "unknown-grant"

        with pytest.raises(MockFixtureValidationError):
            validate_scenario_fixture(
                payload["scenario_id"], payload, get_grant_fixtures()
            )

        assert isolated_contract_repository.list(limit=100) == []
        assert not isolated_evidence_path.exists()


class TestPublicInputValidation:
    @pytest.mark.parametrize("scope", ["", "   ", "drive.\nreadonly", "bad\\scope"])
    def test_malformed_public_scopes_return_422(self, client, scope):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": [scope],
                "intended_actions": ["read files"],
            },
        )

        assert response.status_code == 422

    def test_url_style_scope_and_unknown_scope_remain_publicly_accepted(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": [
                    "https://www.googleapis.com/auth/drive.readonly",
                    "unknown.wellformed",
                ],
                "intended_actions": ["read files"],
            },
        )

        assert response.status_code == 200
        assert response.json()["least_privilege_plan"]["scopes_to_remove"] == [
            "https://www.googleapis.com/auth/drive.readonly",
            "unknown.wellformed",
        ]

    def test_unknown_capability_fails_closed(self, client):
        contract = client.post(
            "/api/v1/gateway/contracts",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
                "ttl_seconds": 3600,
            },
        ).json()
        response = client.post(
            "/api/v1/gateway/evaluate",
            json={
                "contract_id": contract["contract_id"],
                "attempted_capability": "unknown_capability",
                "observed_scopes": ["drive.readonly"],
            },
        )

        assert response.status_code == 200
        assert response.json()["decision"] == "block"
        assert response.json()["reason_code"] == "capability_not_allowed"

    @pytest.mark.parametrize("capability", ["", " ", "Read Files", "bad-cap"])
    def test_malformed_capability_returns_422(self, client, capability):
        response = client.post(
            "/api/v1/gateway/evaluate",
            json={
                "contract_id": "unknown",
                "attempted_capability": capability,
                "observed_scopes": ["drive.readonly"],
            },
        )

        assert response.status_code == 422


class TestScenarioRunContract:
    @pytest.mark.parametrize(
        ("content", "content_type"),
        [
            (b"{}", "application/json"),
            (b"   ", "text/plain"),
            (b"text", "text/plain"),
            (b"\x00\x01", "application/octet-stream"),
        ],
    )
    def test_nonempty_body_returns_documented_400(
        self, client, content, content_type, isolated_evidence_path
    ):
        response = client.post(
            "/api/v1/demo/scenarios/safe-file-reader/run",
            content=content,
            headers={"content-type": content_type},
        )

        assert response.status_code == 400
        assert response.json() == {
            "detail": "This endpoint accepts no request body."
        }
        assert not isolated_evidence_path.exists()

    def test_truly_empty_body_remains_accepted(self, client):
        response = client.post(
            "/api/v1/demo/scenarios/safe-file-reader/run", content=b""
        )

        assert response.status_code == 200
        assert response.json()["passed"] is True

    def test_openapi_documents_run_responses(self):
        responses = app.openapi()["paths"][
            "/api/v1/demo/scenarios/{scenario_id}/run"
        ]["post"]["responses"]

        assert {"200", "400", "404", "422"}.issubset(responses)
        error_schema = responses["400"]["content"]["application/json"][
            "schema"
        ]
        assert error_schema["$ref"].endswith("/DemoErrorResponse")


class TestMissingCapabilitiesAndRegression:
    def test_missing_capability_is_exact_and_sorted(self, client):
        response = client.post(
            "/api/v1/demo/scenarios/missing-required-permission/run"
        )

        assert response.status_code == 200
        assert response.json()["analysis_summary"]["missing_capabilities"] == [
            "send_email_messages"
        ]

    def test_single_analysis_reports_empty_missing_capabilities(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
            },
        )

        assert response.status_code == 200
        assert response.json()["missing_capabilities"] == []

    @pytest.mark.parametrize(
        "scenario_id",
        [
            "safe-file-reader",
            "overprivileged-file-reader",
            "runtime-scope-drift",
            "composed-exfiltration-path",
            "missing-required-permission",
        ],
    )
    def test_all_scenarios_preserve_security_outcomes(self, client, scenario_id):
        response = client.post(f"/api/v1/demo/scenarios/{scenario_id}/run")

        assert response.status_code == 200
        result = response.json()
        assert result["passed"] is True
        assert [entry["step_number"] for entry in result["timeline"]] == list(
            range(1, 11)
        )
        assert result["evidence_chain_valid"] is True
