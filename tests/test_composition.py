"""Tests for deterministic multi-grant composition analysis."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.planner.composition_engine import analyze_composition


@pytest.fixture
def client():
    return TestClient(app)


REFERENCE_GRANTS = [
    {
        "grant_id": "files-workflow",
        "granted_scopes": ["drive.readonly"],
    },
    {
        "grant_id": "mail-workflow",
        "granted_scopes": ["gmail.readonly", "gmail.send"],
    },
]


class TestCompositionEngine:
    def test_combines_grants_and_tracks_sources(self):
        result = analyze_composition(
            provider="google",
            grants=REFERENCE_GRANTS,
            intended_actions=["read files", "send email"],
        )

        assert result["status"] == "complete"
        assert result["grant_count"] == 2
        assert result["requires_composition"] is True
        assert result["combined_scopes"] == [
            "drive.readonly",
            "gmail.readonly",
            "gmail.send",
        ]
        assert result["capability_sources"]["list_files"] == [
            "files-workflow"
        ]
        assert result["capability_sources"]["send_email_messages"] == [
            "mail-workflow"
        ]

    def test_composition_plan_removes_excess_scope(self):
        result = analyze_composition(
            provider="google",
            grants=REFERENCE_GRANTS,
            intended_actions=["read files", "send email"],
        )
        plan = result["least_privilege_plan"]

        assert plan["selected_scopes"] == [
            "drive.readonly",
            "gmail.send",
        ]
        assert plan["scopes_to_remove"] == ["gmail.readonly"]
        assert plan["risk_reduction_percentage"] == 40.0

    def test_duplicate_scopes_and_capabilities_are_deterministic(self):
        result = analyze_composition(
            provider="google",
            grants=[
                {
                    "grant_id": "z-grant",
                    "granted_scopes": [
                        "drive.readonly",
                        "drive.readonly",
                    ],
                },
                {
                    "grant_id": "a-grant",
                    "granted_scopes": ["drive.readonly"],
                },
            ],
            intended_actions=["read files"],
        )

        assert result["duplicated_scopes"] == ["drive.readonly"]
        assert result["capability_sources"]["list_files"] == [
            "a-grant",
            "z-grant",
        ]
        assert result["duplicated_scope_risk"] == 2.0

    def test_unknown_scope_is_not_trusted(self):
        result = analyze_composition(
            provider="google",
            grants=[
                {
                    "grant_id": "unknown-grant",
                    "granted_scopes": ["totally.fake.scope"],
                }
            ],
            intended_actions=["read files"],
        )

        assert result["combined_capabilities"] == []
        assert result["unknown_scopes"] == ["totally.fake.scope"]
        assert result["missing_capabilities"] == [
            "list_files",
            "read_file_contents",
            "read_file_metadata",
        ]
        assert "totally.fake.scope" in result["least_privilege_plan"][
            "scopes_to_remove"
        ]

    def test_unknown_intent_requires_manual_review(self):
        result = analyze_composition(
            provider="google",
            grants=REFERENCE_GRANTS,
            intended_actions=["read files", "teleport"],
        )

        assert result["status"] == "manual_review"
        assert result["unknown_intents"] == ["teleport"]
        assert result["least_privilege_plan"]["selected_scopes"] == []

    def test_duplicate_grant_ids_are_rejected(self):
        with pytest.raises(ValueError, match="grant_id values must be unique"):
            analyze_composition(
                provider="google",
                grants=[
                    {"grant_id": "same", "granted_scopes": []},
                    {"grant_id": "same", "granted_scopes": []},
                ],
            )


class TestCompositionEndpoint:
    def test_reference_request(self, client):
        response = client.post(
            "/api/v1/analyze-composition",
            json={
                "provider": "google",
                "grants": REFERENCE_GRANTS,
                "intended_actions": ["read files", "send email"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["grant_count"] == 2
        assert data["least_privilege_plan"]["selected_scopes"] == [
            "drive.readonly",
            "gmail.send",
        ]
        assert data["composition_graph"]["nodes"]
        assert data["composition_graph"]["edges"]

    def test_alias_input_names_are_accepted(self, client):
        response = client.post(
            "/api/v1/analyze-composition",
            json={
                "provider": "google",
                "grants": [
                    {"id": "grant-a", "scopes": ["drive.readonly"]}
                ],
                "intended_actions": ["read files"],
            },
        )

        assert response.status_code == 200
        assert response.json()["grants"][0]["grant_id"] == "grant-a"

    def test_unsupported_provider_returns_400(self, client):
        response = client.post(
            "/api/v1/analyze-composition",
            json={
                "provider": "unsupported",
                "grants": [
                    {"grant_id": "grant-a", "granted_scopes": []}
                ],
            },
        )

        assert response.status_code == 400
        assert "Unsupported provider" in response.json()["detail"]

    def test_duplicate_grant_ids_return_422(self, client):
        response = client.post(
            "/api/v1/analyze-composition",
            json={
                "provider": "google",
                "grants": [
                    {"grant_id": "same", "granted_scopes": []},
                    {"grant_id": "same", "granted_scopes": []},
                ],
            },
        )

        assert response.status_code == 422

    def test_openapi_has_composition_route_and_tag(self, client):
        schema = client.get("/openapi.json").json()
        operation = schema["paths"]["/api/v1/analyze-composition"]["post"]

        assert operation["tags"] == ["Composition Analysis"]


def test_application_registers_both_analysis_routes():
    paths = set(app.openapi()["paths"])
    assert "/api/v1/analyze" in paths
    assert "/api/v1/analyze-composition" in paths
