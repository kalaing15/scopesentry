"""Security, serving, and backend-integration tests for the local dashboard."""

import inspect
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.evidence.service import EvidenceService
from app.gateway.repository import get_contract_repository
from app.main import app
from app.orchestrator import demo_runner as demo_runner_module
from app.orchestrator.demo_runner import DemoRunner
from app.planner.analysis_service import analyze_scope_grant
from app.providers.mock.scenarios import get_scenario
from app.providers.registry import get_provider_registry
from app.schemas.provider import ScenarioRiskCategory


DASHBOARD_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "app" / "static" / "dashboard"
)
SCENARIO_IDS = [
    "safe-file-reader",
    "overprivileged-file-reader",
    "runtime-scope-drift",
    "composed-exfiltration-path",
    "missing-required-permission",
]


@pytest.fixture
def client():
    return TestClient(app)


def _dashboard_source(filename: str) -> str:
    return (DASHBOARD_DIRECTORY / filename).read_text(encoding="utf-8")


class TestDashboardServing:
    def test_dashboard_returns_html_without_changing_root(self, client):
        dashboard = client.get("/demo")
        root = client.get("/")

        assert dashboard.status_code == 200
        assert dashboard.headers["content-type"].startswith("text/html")
        assert "ScopeSentry-R" in dashboard.text
        assert root.status_code == 200
        assert root.json() == {"project": "ScopeSentry-R", "status": "running"}

    def test_dashboard_security_headers_are_restrictive(self, client):
        response = client.get("/demo")
        csp = response.headers["content-security-policy"]

        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "connect-src 'self'" in csp
        assert "font-src 'none'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "form-action 'none'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["permissions-policy"] == (
            "camera=(), microphone=(), geolocation=()"
        )

    @pytest.mark.parametrize(
        ("path", "content_type"),
        [
            ("/demo-assets/styles.css", "text/css"),
            ("/demo-assets/dashboard.js", "text/javascript"),
        ],
    )
    def test_local_assets_are_available(self, client, path, content_type):
        response = client.get(path)

        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.text

    def test_static_path_is_independent_of_working_directory(
        self, client, monkeypatch, tmp_path
    ):
        monkeypatch.chdir(tmp_path)

        assert client.get("/demo").status_code == 200
        assert client.get("/demo-assets/dashboard.js").status_code == 200


class TestDashboardSourceSecurity:
    def test_assets_have_no_external_network_references(self):
        combined = "\n".join(
            _dashboard_source(filename)
            for filename in ("index.html", "styles.css", "dashboard.js")
        )

        assert re.search(r"https?://", combined, flags=re.IGNORECASE) is None
        for forbidden in ("cdn", "analytics", "tracking", "googleapis.com"):
            assert forbidden not in combined.lower()

    def test_dynamic_rendering_uses_no_unsafe_dom_apis(self):
        javascript = _dashboard_source("dashboard.js")

        for forbidden in (
            "innerHTML",
            "insertAdjacentHTML",
            "eval(",
            "new Function",
            "Function(",
            "document.write",
            "localStorage",
        ):
            assert forbidden not in javascript
        assert "textContent" in javascript
        assert "document.createElement" in javascript

    def test_scenario_post_is_bodyless_and_has_no_json_content_type(self):
        javascript = _dashboard_source("dashboard.js")

        assert "body:" not in javascript
        assert "Content-Type" not in javascript
        assert (
            '{ method: "POST", headers: { Accept: "application/json" } }'
            in javascript
        )
        assert "/api/v1/demo/scenarios/${encodeURIComponent(scenarioId)}/run" in javascript

    def test_run_all_is_sequential_and_duplicate_safe(self):
        javascript = _dashboard_source("dashboard.js")

        assert "state.inFlight.has(scenarioId)" in javascript
        assert "state.runAllActive" in javascript
        assert re.search(
            r"for \(let index = 0;.*?await runScenario\(scenarioId, true\)",
            javascript,
            flags=re.DOTALL,
        )

    def test_unknown_values_and_api_errors_have_unsafe_states(self):
        javascript = _dashboard_source("dashboard.js")

        assert 'label: "Unsafe / Unknown", className: "unsafe"' in javascript
        assert "The backend response could not be safely interpreted." in javascript
        assert "No security result was produced." in javascript
        assert "No result was accepted." in javascript
        assert "TIMELINE_STATUSES.has(entry.status)" in javascript


class TestDashboardBackendIntegration:
    def test_additive_fields_are_copied_from_authoritative_analysis(self, client):
        authoritative = analyze_scope_grant(
            provider="google",
            granted_scopes=["drive.readonly"],
            intended_actions=["read files"],
        )
        response = client.post("/api/v1/demo/scenarios/safe-file-reader/run")

        assert response.status_code == 200
        summary = response.json()["analysis_summary"]
        assert summary["matched_scopes"] == authoritative["matched_scopes"]
        assert summary["granted_capabilities"] == authoritative[
            "granted_capabilities"
        ]

    def test_risk_category_is_presentation_only(
        self,
        monkeypatch,
        isolated_contract_repository,
        isolated_evidence_path,
    ):
        service = EvidenceService(isolated_evidence_path)
        runner = DemoRunner(
            registry=get_provider_registry(),
            repository=isolated_contract_repository,
            evidence_service=service,
        )
        baseline = runner.run("safe-file-reader")
        changed_scenario = get_scenario("safe-file-reader")
        assert changed_scenario is not None
        changed_scenario.risk_category = ScenarioRiskCategory.COMPOSITION_RISK
        monkeypatch.setattr(
            demo_runner_module,
            "get_scenario",
            lambda _scenario_id: changed_scenario.model_copy(deep=True),
        )

        changed = runner.run("safe-file-reader")

        assert changed.passed == baseline.passed is True
        assert [item["decision"] for item in changed.gateway_decisions] == [
            item["decision"] for item in baseline.gateway_decisions
        ]
        assert changed.analysis_summary.least_privilege_plan == (
            baseline.analysis_summary.least_privilege_plan
        )
        assert "risk_category" not in inspect.getsource(DemoRunner)

    def test_unknown_scenario_is_not_an_allowed_result(self, client):
        response = client.post("/api/v1/demo/scenarios/not-present/run")

        assert response.status_code == 404
        assert "allow" not in response.text.lower()

    def test_openapi_scenario_run_contract_is_unchanged(self):
        responses = app.openapi()["paths"][
            "/api/v1/demo/scenarios/{scenario_id}/run"
        ]["post"]["responses"]

        assert {"200", "400", "404", "422"}.issubset(responses)

    @pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
    def test_all_scenarios_still_pass(self, client, scenario_id):
        response = client.post(f"/api/v1/demo/scenarios/{scenario_id}/run")

        assert response.status_code == 200
        assert response.json()["passed"] is True

    def test_run_all_backend_sequence_leaves_valid_evidence_chain(self, client):
        results = [
            client.post(f"/api/v1/demo/scenarios/{scenario_id}/run")
            for scenario_id in SCENARIO_IDS
        ]
        verification = client.get("/api/v1/evidence/verify")

        assert all(response.status_code == 200 for response in results)
        assert all(response.json()["passed"] is True for response in results)
        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert verification.json()["records_checked"] > 0
