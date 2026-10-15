"""Tests for provider adapters, registry, and end-to-end demos."""

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.providers.mock.adapter import MockGoogleProviderAdapter
from app.providers.mock.scenarios import get_scenario
from app.providers.registry import (
    DuplicateProviderError,
    ProviderRegistry,
    UnsupportedProviderError,
)


@pytest.fixture
def client():
    return TestClient(app)


def _run(client, scenario_id):
    response = client.post(f"/api/v1/demo/scenarios/{scenario_id}/run")
    assert response.status_code == 200
    return response.json()


class TestProviderRegistryAndAdapter:
    def test_provider_registration_and_lookup(self):
        registry = ProviderRegistry()
        adapter = MockGoogleProviderAdapter()

        registry.register(adapter)

        assert registry.get(" MOCK-GOOGLE ") is adapter
        assert registry.names() == ("mock-google",)
        metadata = registry.list_metadata()
        assert metadata[0].provider_name == "mock-google"
        assert metadata[0].catalog_provider == "google"
        assert metadata[0].simulation_only is True

    def test_duplicate_provider_registration_is_rejected(self):
        registry = ProviderRegistry()
        registry.register(MockGoogleProviderAdapter())

        with pytest.raises(DuplicateProviderError, match="already registered"):
            registry.register(MockGoogleProviderAdapter())

    def test_unsupported_provider_lookup_is_controlled(self):
        registry = ProviderRegistry()

        with pytest.raises(UnsupportedProviderError, match="Unsupported"):
            registry.get("not-installed")

    def test_mock_grant_discovery(self):
        adapter = MockGoogleProviderAdapter()

        grants = adapter.list_grants("safe-file-reader")

        assert len(grants) == 1
        assert grants[0].grant_id == "safe-reader-grant"
        assert adapter.discover_scopes(grants[0].grant_id) == [
            "drive.readonly"
        ]
        assert "read_file_contents" in adapter.resolve_scopes(
            grants[0].granted_scopes
        )

    def test_fixtures_are_returned_as_defensive_copies(self):
        adapter = MockGoogleProviderAdapter()
        first = adapter.get_grant("safe-reader-grant")
        first.granted_scopes.append("gmail.send")
        scenario = get_scenario("safe-file-reader")
        assert scenario is not None
        scenario.grant_ids.append("mutated")

        second = adapter.get_grant("safe-reader-grant")
        fresh_scenario = get_scenario("safe-file-reader")

        assert second.granted_scopes == ["drive.readonly"]
        assert fresh_scenario is not None
        assert fresh_scenario.grant_ids == ["safe-reader-grant"]


class TestDemoScenarios:
    def test_safe_reader_scenario_passes(self, client):
        result = _run(client, "safe-file-reader")

        assert result["passed"] is True
        assert result["analysis_summary"]["excessive_scopes"] == []
        assert result["gateway_decisions"][0]["decision"] == "allow"

    def test_overprivileged_reader_detects_gmail_access(self, client):
        result = _run(client, "overprivileged-file-reader")

        assert result["passed"] is True
        assert result["analysis_summary"]["excessive_scopes"] == [
            "gmail.readonly"
        ]
        assert result["contract_summary"]["allowed_scopes"] == [
            "drive.readonly"
        ]
        assert result["gateway_decisions"][0]["decision"] == "quarantine"

    def test_runtime_drift_produces_quarantine(self, client):
        result = _run(client, "runtime-scope-drift")

        assert result["passed"] is True
        assert result["gateway_decisions"][0]["decision"] == "quarantine"
        assert result["gateway_decisions"][0]["unexpected_scopes"] == [
            "gmail.send"
        ]
        assert result["contract_summary"]["state"] == "quarantined"

    def test_composed_exfiltration_path_is_detected(self, client):
        result = _run(client, "composed-exfiltration-path")

        assert result["passed"] is True
        paths = result["composition_summary"]["unauthorized_paths"]
        assert len(paths) == 1
        assert paths[0]["source_capability"] == "read_file_contents"
        assert paths[0]["target_capability"] == "send_email_messages"
        assert "Break the data-flow link" in paths[0]["remediation"]

    def test_missing_permission_reports_missing_capabilities(self, client):
        result = _run(client, "missing-required-permission")

        assert result["passed"] is True
        assert result["analysis_summary"]["missing_scopes"] == [
            "gmail.send"
        ]
        assert result["analysis_summary"]["least_privilege_plan"][
            "scopes_to_add"
        ] == ["gmail.send"]
        assert "send_email_messages" in result["analysis_summary"][
            "required_capabilities"
        ]
        assert result["contract_summary"] is None

    def test_unknown_scenario_returns_404(self, client):
        detail = client.get("/api/v1/demo/scenarios/not-a-scenario")
        run = client.post("/api/v1/demo/scenarios/not-a-scenario/run")

        assert detail.status_code == 404
        assert run.status_code == 404

    def test_scenario_timeline_is_chronologically_ordered(self, client):
        result = _run(client, "safe-file-reader")
        timeline = result["timeline"]

        assert [entry["step_number"] for entry in timeline] == list(
            range(1, 11)
        )
        assert timeline[0]["stage"] == "mock_grant_discovery"
        assert timeline[-1]["stage"] == "evidence_chain_verification"

    def test_scenario_result_is_json_serializable(self, client):
        result = _run(client, "composed-exfiltration-path")

        encoded = json.dumps(result, sort_keys=True)

        assert "composed-exfiltration-path" in encoded
        assert "networkx" not in encoded.lower()

    def test_scenario_evidence_chain_verifies(
        self,
        client,
        isolated_evidence_path,
    ):
        result = _run(client, "runtime-scope-drift")
        verification = client.get("/api/v1/evidence/verify")
        records = [
            json.loads(line)
            for line in isolated_evidence_path.read_text().splitlines()
        ]

        assert result["evidence_chain_valid"] is True
        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert records[-1]["analysis_type"] == "demo_completion"
        assert result["timeline"][-1]["evidence_reference"][
            "record_hash"
        ] == records[-1]["record_hash"]

    def test_demo_responses_contain_no_secret_fields(self, client):
        provider_response = client.get("/api/v1/demo/providers").json()
        scenario_response = _run(client, "safe-file-reader")
        forbidden = {
            "access_token",
            "refresh_token",
            "authorization",
            "client_secret",
            "password",
            "api_key",
            "cookie",
        }

        def keys(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    yield key.lower()
                    yield from keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from keys(nested)

        assert forbidden.isdisjoint(set(keys(provider_response)))
        assert forbidden.isdisjoint(set(keys(scenario_response)))
