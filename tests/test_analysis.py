"""
Comprehensive tests for the ScopeSentry-R application.

Covers:
  - Intent normalisation and mapping
  - Exposure differential calculation
  - Capability graph construction and excessive-capability detection
  - Least-privilege synthesis engine
  - POST /api/v1/analyze (success, unsupported provider, unknown intents,
    synthesis plan, edge cases)
"""

import pytest
from fastapi.testclient import TestClient

from app.planner import least_privilege_synthesizer as synthesizer_module
from app.main import app
from app.planner.intent_mapper import normalize_intent, map_intents_to_scopes
from app.planner.exposure_engine import calculate_exposure_differential
from app.planner.capability_graph import (
    build_capability_graph,
    graph_to_serializable,
)
from app.planner.least_privilege_synthesizer import synthesize_least_privilege


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# Intent normalisation & mapping
# ============================================================================

class TestIntentMapper:
    def test_normalize_spaces(self):
        assert normalize_intent("read files") == "read_files"

    def test_normalize_hyphens(self):
        assert normalize_intent("send-email") == "send_email"

    def test_normalize_mixed_case(self):
        assert normalize_intent("Read Files") == "read_files"

    def test_normalize_strips_whitespace(self):
        assert normalize_intent("  read files  ") == "read_files"

    def test_map_known_intents(self):
        scopes, unknown = map_intents_to_scopes(["read files", "send email"])
        assert "drive.readonly" in scopes
        assert "gmail.send" in scopes
        assert unknown == []

    def test_map_unknown_intent(self):
        scopes, unknown = map_intents_to_scopes(["hack the planet"])
        assert scopes == []
        assert "hack the planet" in unknown

    def test_map_mixed_intents(self):
        scopes, unknown = map_intents_to_scopes(
            ["read files", "do magic"]
        )
        assert "drive.readonly" in scopes
        assert "do magic" in unknown

    def test_map_deduplicates_scopes(self):
        scopes, _ = map_intents_to_scopes(["read files", "read files"])
        assert scopes.count("drive.readonly") == 1


# ============================================================================
# Exposure differential
# ============================================================================

class TestExposureEngine:
    def test_all_matched(self):
        result = calculate_exposure_differential(
            granted_scopes=["drive.readonly"],
            required_scopes=["drive.readonly"],
        )
        assert result["matched_scopes"] == ["drive.readonly"]
        assert result["excessive_scopes"] == []
        assert result["missing_scopes"] == []
        assert result["exposure_score"] == 0.0

    def test_excessive_scopes(self):
        result = calculate_exposure_differential(
            granted_scopes=["drive.readonly", "gmail.readonly"],
            required_scopes=["drive.readonly"],
        )
        assert "gmail.readonly" in result["excessive_scopes"]
        assert result["exposure_score"] > 0.0

    def test_missing_scopes(self):
        result = calculate_exposure_differential(
            granted_scopes=[],
            required_scopes=["drive.readonly"],
        )
        assert "drive.readonly" in result["missing_scopes"]
        assert result["exposure_score"] == 0.0

    def test_reference_scenario_score(self):
        """Verify the score for the reference test request is 40.0."""
        result = calculate_exposure_differential(
            granted_scopes=["drive.readonly", "gmail.readonly", "gmail.send"],
            required_scopes=["drive.readonly", "gmail.send"],
        )
        assert result["exposure_score"] == 40.0
        assert result["excessive_scopes"] == ["gmail.readonly"]
        assert sorted(result["matched_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]


# ============================================================================
# Capability graph
# ============================================================================

class TestCapabilityGraph:
    def test_graph_nodes_no_duplicates(self):
        graph, _ = build_capability_graph(
            provider="google",
            granted_scopes=["drive.readonly", "drive.readonly"],
            required_scopes=["drive.readonly"],
        )
        scope_nodes = [
            n for n, d in graph.nodes(data=True)
            if d.get("node_type") == "scope"
        ]
        assert scope_nodes.count("drive.readonly") == 1

    def test_graph_edges(self):
        graph, _ = build_capability_graph(
            provider="google",
            granted_scopes=["gmail.send"],
            required_scopes=["gmail.send"],
        )
        assert graph.has_edge("gmail.send", "send_email_messages")

    def test_excessive_capabilities(self):
        _, analysis = build_capability_graph(
            provider="google",
            granted_scopes=["drive.readonly", "gmail.readonly", "gmail.send"],
            required_scopes=["drive.readonly", "gmail.send"],
        )
        # gmail.readonly caps are excessive
        assert "list_email_messages" in analysis["excessive_capabilities"]
        assert "read_email_messages" in analysis["excessive_capabilities"]
        # gmail.send caps are required
        assert "send_email_messages" in analysis["required_capabilities"]

    def test_missing_capabilities(self):
        _, analysis = build_capability_graph(
            provider="google",
            granted_scopes=[],
            required_scopes=["drive.readonly"],
        )
        assert "list_files" in analysis["missing_capabilities"]

    def test_serializable_structure(self):
        graph, _ = build_capability_graph(
            provider="google",
            granted_scopes=["gmail.send"],
            required_scopes=["gmail.send"],
        )
        data = graph_to_serializable(graph)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0

    def test_scope_status_classification(self):
        graph, _ = build_capability_graph(
            provider="google",
            granted_scopes=["drive.readonly", "gmail.readonly"],
            required_scopes=["drive.readonly", "gmail.send"],
        )
        # drive.readonly is in both → matched
        assert graph.nodes["drive.readonly"]["status"] == "matched"
        # gmail.readonly is only granted → excessive
        assert graph.nodes["gmail.readonly"]["status"] == "excessive"
        # gmail.send is only required → missing
        assert graph.nodes["gmail.send"]["status"] == "missing"

    def test_unknown_scope_not_trusted(self):
        """Unknown scopes should not produce capability nodes."""
        graph, analysis = build_capability_graph(
            provider="google",
            granted_scopes=["totally.fake.scope"],
            required_scopes=["drive.readonly"],
        )
        cap_nodes = [
            n for n, d in graph.nodes(data=True)
            if d.get("node_type") == "capability"
        ]
        # Only drive.readonly capabilities should exist
        for cap in cap_nodes:
            assert cap in [
                "list_files",
                "read_file_metadata",
                "read_file_contents",
            ]


# ============================================================================
# Least-privilege synthesizer
# ============================================================================

class TestLeastPrivilegeSynthesizer:
    def test_remove_excessive_scope(self):
        """Test case 1: removing one excessive scope."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly", "gmail.readonly", "gmail.send"],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
                "send_email_messages",
            ],
        )
        assert plan["status"] == "complete"
        assert sorted(plan["selected_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        assert sorted(plan["scopes_to_keep"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        assert plan["scopes_to_remove"] == ["gmail.readonly"]
        assert plan["scopes_to_add"] == []
        assert plan["uncovered_capabilities"] == []
        assert plan["risk_reduction_percentage"] == 40.0
        # Explanation mentions email-reading is unnecessary
        explanation_lower = plan["explanation"].lower()
        assert "gmail.readonly" in explanation_lower
        assert "not required" in explanation_lower or "unnecessary" in explanation_lower

    def test_perfectly_matched_grant(self):
        """Test case 2: nothing to remove or add."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly", "gmail.send"],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
                "send_email_messages",
            ],
        )
        assert plan["status"] == "complete"
        assert sorted(plan["selected_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        assert plan["scopes_to_remove"] == []
        assert plan["scopes_to_add"] == []
        assert plan["risk_delta"] == 0.0

    def test_missing_scopes_recommended(self):
        """Test case 3: scopes must be added."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly"],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
                "send_email_messages",
            ],
        )
        assert plan["status"] == "complete"
        assert "gmail.send" in plan["selected_scopes"]
        assert "gmail.send" in plan["scopes_to_add"]

    def test_unknown_intent_manual_review(self):
        """Test case 4: unknown intent triggers manual_review."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly"],
            required_capabilities=["list_files"],
            unknown_intents=["teleport"],
        )
        assert plan["status"] == "manual_review"
        assert "manual review" in plan["explanation"].lower()

    def test_duplicate_granted_scopes_normalized(self):
        """Test case 6: duplicate input scopes produce clean output."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=[
                "drive.readonly",
                "drive.readonly",
                "gmail.send",
            ],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
                "send_email_messages",
            ],
        )
        assert plan["status"] == "complete"
        # selected_scopes should have no duplicates
        assert len(plan["selected_scopes"]) == len(
            set(plan["selected_scopes"])
        )

    def test_unknown_granted_scope_not_trusted(self):
        """Test case 7: unknown scopes are not counted as capability sources."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["totally.fake.scope", "drive.readonly"],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
            ],
        )
        assert plan["status"] == "complete"
        # The fake scope should be removed
        assert "totally.fake.scope" in plan["scopes_to_remove"]
        # drive.readonly should be kept
        assert "drive.readonly" in plan["scopes_to_keep"]

    def test_impossible_capability_incomplete(self):
        """Test case 8: impossible capability requirement → incomplete."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly"],
            required_capabilities=["warp_drive_activation"],
        )
        assert plan["status"] == "incomplete"
        assert "warp_drive_activation" in plan["uncovered_capabilities"]

    def test_deterministic_output_equal_scores(self, monkeypatch):
        """Test case 9: alphabetical tie-break for equal candidates."""
        catalog = {
            "z.scope": ["required_capability"],
            "a.scope": ["required_capability"],
        }
        weights = {"z.scope": 1.0, "a.scope": 1.0}
        monkeypatch.setattr(
            synthesizer_module,
            "get_catalog",
            lambda provider: catalog,
        )
        monkeypatch.setattr(
            synthesizer_module,
            "get_risk_weights",
            lambda provider: weights,
        )

        results = []
        for _ in range(5):
            plan = synthesize_least_privilege(
                provider="equal-score-provider",
                granted_scopes=[],
                required_capabilities=["required_capability"],
            )
            results.append(tuple(plan["selected_scopes"]))
        assert results == [("a.scope",)] * 5

    def test_no_required_capabilities_selects_no_scopes(self):
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly"],
            required_capabilities=[],
        )
        assert plan["status"] == "complete"
        assert plan["selected_scopes"] == []
        assert plan["scopes_to_remove"] == ["drive.readonly"]
        assert plan["risk_after"] == 0.0

    def test_prefers_narrow_scope(self):
        """Optimizer should prefer drive.readonly over drive.file when only
        read capabilities are needed, because drive.readonly has lower risk."""
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.file"],
            required_capabilities=[
                "list_files",
                "read_file_metadata",
                "read_file_contents",
            ],
        )
        assert plan["status"] == "complete"
        assert "drive.readonly" in plan["selected_scopes"]
        assert "drive.file" not in plan["selected_scopes"]

    def test_optimization_method_field(self):
        plan = synthesize_least_privilege(
            provider="google",
            granted_scopes=["drive.readonly"],
            required_capabilities=[
                "list_files",
                "read_file_contents",
                "read_file_metadata",
            ],
        )
        assert plan["optimization_method"] == "exhaustive_subset_evaluation"


# ============================================================================
# API endpoint – POST /api/v1/analyze
# ============================================================================

class TestAnalyzeEndpoint:
    def test_successful_analysis(self, client):
        """Reference test case from the spec."""
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": [
                    "drive.readonly",
                    "gmail.readonly",
                    "gmail.send",
                ],
                "intended_actions": ["read files", "send email"],
            },
        )
        assert response.status_code == 200
        data = response.json()

        # Required scopes
        assert sorted(data["required_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        # Excessive scopes
        assert data["excessive_scopes"] == ["gmail.readonly"]
        # Exposure score
        assert data["exposure_score"] == 40.0
        # Excessive capabilities include gmail-reading caps
        assert "list_email_messages" in data["excessive_capabilities"]
        assert "read_email_messages" in data["excessive_capabilities"]
        # Least privilege (populated from optimizer)
        assert sorted(data["synthesized_least_privilege_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        # Graph present
        assert "nodes" in data["capability_graph"]
        assert "edges" in data["capability_graph"]
        assert len(data["capability_graph"]["nodes"]) > 0

    def test_successful_analysis_plan(self, client):
        """Verify the least_privilege_plan in the reference scenario."""
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": [
                    "drive.readonly",
                    "gmail.readonly",
                    "gmail.send",
                ],
                "intended_actions": ["read files", "send email"],
            },
        )
        assert response.status_code == 200
        plan = response.json()["least_privilege_plan"]

        assert plan["status"] == "complete"
        assert sorted(plan["selected_scopes"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        assert sorted(plan["scopes_to_keep"]) == [
            "drive.readonly",
            "gmail.send",
        ]
        assert plan["scopes_to_remove"] == ["gmail.readonly"]
        assert plan["scopes_to_add"] == []
        assert plan["uncovered_capabilities"] == []
        assert plan["risk_reduction_percentage"] == 40.0
        # Email-reading capability is unnecessary
        explanation_lower = plan["explanation"].lower()
        assert "gmail.readonly" in explanation_lower

    def test_unsupported_provider(self, client):
        """Test case 5: unsupported provider → HTTP 400."""
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "facebook",
                "granted_scopes": ["some.scope"],
                "intended_actions": ["read files"],
            },
        )
        assert response.status_code == 400
        assert "Unsupported provider" in response.json()["detail"]

    def test_unknown_intents(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files", "teleport"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "teleport" in data["unknown_intents"]
        assert "manual review" in data["recommendation"].lower()
        assert data["least_privilege_plan"]["status"] == "manual_review"
        assert data["synthesized_least_privilege_scopes"] == []
        assert data["synthesized_least_privilege_scopes"] == (
            data["least_privilege_plan"]["selected_scopes"]
        )

    def test_duplicate_scopes_no_duplicate_nodes(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": [
                    "drive.readonly",
                    "drive.readonly",
                ],
                "intended_actions": ["read files"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        # No duplicate scope nodes
        node_ids = [n["id"] for n in data["capability_graph"]["nodes"]]
        assert len(node_ids) == len(set(node_ids))

    def test_response_contains_all_fields(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        required_fields = [
            "provider",
            "intended_actions",
            "granted_scopes",
            "required_scopes",
            "matched_scopes",
            "excessive_scopes",
            "missing_scopes",
            "unknown_intents",
            "synthesized_least_privilege_scopes",
            "granted_capabilities",
            "required_capabilities",
            "excessive_capabilities",
            "exposure_score",
            "recommendation",
            "capability_graph",
            "least_privilege_plan",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_unknown_scope_not_trusted_api(self, client):
        """Unknown granted scope should be recommended for removal."""
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly", "totally.fake.scope"],
                "intended_actions": ["read files"],
            },
        )
        assert response.status_code == 200
        plan = response.json()["least_privilege_plan"]
        assert "totally.fake.scope" in plan["scopes_to_remove"]

    def test_perfectly_matched_api(self, client):
        """No changes needed when grant matches exactly."""
        response = client.post(
            "/api/v1/analyze",
            json={
                "provider": "google",
                "granted_scopes": ["drive.readonly"],
                "intended_actions": ["read files"],
            },
        )
        assert response.status_code == 200
        plan = response.json()["least_privilege_plan"]
        assert plan["status"] == "complete"
        assert plan["scopes_to_remove"] == []
        assert plan["scopes_to_add"] == []
        assert plan["risk_delta"] == 0.0
