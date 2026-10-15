"""Phase 5 provider identity, composition, scenario, and V2 regressions."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.corpus import corpus_hash, get_evaluation_corpus
from app.evaluation.corpus_v2 import corpus_v2_hash, get_evaluation_corpus_v2
from app.evaluation.engine import evaluate_provider_qualified_case
from app.evaluation.runner_v2 import run_evaluation_v2
from app.gateway.contracts import calculate_scope_fingerprint
from app.gateway.policy_engine import evaluate_capability_attempt
from app.main import app
from app.planner.cross_provider_composition import analyze_provider_qualified_composition
from app.planner.provider_identity import CapabilityIdentity, identity_node_id
from app.providers.catalog import get_catalog, resolve_authority_provider_id
from app.providers.mock.adapter import MockGoogleProviderAdapter
from app.providers.registry import DuplicateProviderError, ProviderRegistry
from app.providers.scenario_registry import get_grant, get_scenario, list_scenarios
from app.providers.synthetic.adapter import MockCodeHostProviderAdapter
from app.schemas.gateway import CapabilityContract
from app.schemas.provider import (
    AuthorizedFlow,
    MockGrant,
    ProviderIntentAssignment,
    ProviderMetadata,
)


PHASE4_HASH = "00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b"


class AliasCollisionAdapter(MockCodeHostProviderAdapter):
    def get_metadata(self):
        return ProviderMetadata(
            provider_name="second-code-adapter",
            display_name="Alias collision",
            catalog_provider="mock-code-host",
            authority_provider_id="mock-code-host",
            aliases=["google"],
            simulation_only=True,
            description="Test adapter.",
        )


class CanonicalCollisionAdapter(MockCodeHostProviderAdapter):
    def get_metadata(self):
        return ProviderMetadata(
            provider_name="second-code-adapter",
            display_name="Canonical collision",
            catalog_provider="mock-code-host",
            authority_provider_id="mock-code-host",
            aliases=[],
            simulation_only=True,
            description="Test adapter.",
        )


def _cross_scenario():
    scenario = get_scenario("safe-authorized-cross-provider-workflow")
    assert scenario is not None
    grants = [get_grant(item) for item in scenario.grant_ids]
    return scenario, grants


def _cross_analysis(scenario, grants, authorizations=None, links=None):
    return analyze_provider_qualified_composition(
        grants=grants,
        provider_intents=scenario.provider_intents,
        observed_links=links if links is not None else scenario.data_flow_links,
        authorized_flows=authorizations if authorizations is not None else scenario.authorized_flows,
    )


def _contract() -> CapabilityContract:
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CapabilityContract(
        contract_id="identity-contract",
        provider="mock-code-host",
        principal_id="principal-a",
        source_grant_ids=["grant-a"],
        intended_actions=["read repositories"],
        allowed_scopes=["content.read"],
        allowed_capabilities=["read_repository_contents"],
        scope_fingerprint=calculate_scope_fingerprint(["content.read"]),
        created_at=created,
        expires_at=created + timedelta(hours=1),
        state="active",
        policy_version="1.0.0",
        source_analysis_id="analysis-a",
        source_evidence_hash="0" * 64,
    )


def test_alias_normalization_is_explicit_and_deterministic():
    assert resolve_authority_provider_id(" MOCK-GOOGLE ") == "google"
    assert resolve_authority_provider_id("google") == "google"
    assert resolve_authority_provider_id("mock-enterprise") == "mock-enterprise"
    with pytest.raises(ValueError, match="Unsupported provider"):
        resolve_authority_provider_id("unknown")


def test_registry_rejects_ambiguous_alias_and_duplicate_canonical_id():
    registry = ProviderRegistry()
    registry.register(MockGoogleProviderAdapter())
    with pytest.raises(DuplicateProviderError, match="ambiguous"):
        registry.register(AliasCollisionAdapter())

    registry = ProviderRegistry()
    registry.register(MockCodeHostProviderAdapter())
    with pytest.raises(DuplicateProviderError, match="Canonical provider"):
        registry.register(CanonicalCollisionAdapter())


def test_same_scope_and_capability_names_remain_provider_isolated():
    assert "content.read" in get_catalog("mock-enterprise")
    assert "content.read" in get_catalog("mock-code-host")
    enterprise = CapabilityIdentity("mock-enterprise", "p", "g", "profile.read", "read_profile")
    code = CapabilityIdentity("mock-code-host", "p", "g", "profile.read", "read_profile")
    assert identity_node_id("capability", enterprise) != identity_node_id("capability", code)


def test_identical_grant_text_is_isolated_by_provider_and_principal():
    def grant(provider, principal, scopes):
        return MockGrant(
            grant_id="shared-grant",
            application_name="Identity fixture",
            provider=provider,
            authority_provider=provider,
            principal_id=principal,
            declared_intended_actions=[],
            granted_scopes=scopes,
            observed_scopes=scopes,
            status="active",
            description="Structured identity regression fixture.",
        )

    result = analyze_provider_qualified_composition(
        grants=[
            grant("mock-enterprise", "principal-a", ["content.read"]),
            grant("mock-enterprise", "principal-b", ["content.read"]),
            grant("mock-code-host", "principal-a", ["content.read"]),
        ],
        provider_intents=[
            ProviderIntentAssignment(provider="mock-enterprise", principal_id="principal-a", intended_actions=["read files"]),
            ProviderIntentAssignment(provider="mock-enterprise", principal_id="principal-b", intended_actions=["read files"]),
            ProviderIntentAssignment(provider="mock-code-host", principal_id="principal-a", intended_actions=["read repositories"]),
        ],
        observed_links=[],
        authorized_flows=[],
    )
    assert len(result["grant_identities"]) == 3
    grant_nodes = [node["id"] for node in result["composition_graph"]["nodes"] if node["node_type"] == "grant"]
    assert len(grant_nodes) == len(set(grant_nodes)) == 3


def test_static_baseline_does_not_accept_wrong_provider_scope():
    case = next(
        item for item in get_evaluation_corpus_v2().provider_cases
        if item.case_id == "v2-wrong-provider-scope-collision"
    )
    result = StaticScopeBaseline().evaluate_qualified(
        provider_intents=case.provider_intents,
        grants=case.grants,
    )
    assert result.normalized_result == "prevented"
    assert "mock-code-host" in result.missing_required_scopes[0]


def test_observed_flow_is_denied_without_a_separate_authorization():
    scenario, grants = _cross_scenario()
    result = _cross_analysis(scenario, grants, authorizations=[])
    assert len(result["observed_paths"]) == 1
    assert len(result["unauthorized_paths"]) == 1
    assert result["unauthorized_paths"][0]["authorized_by_intent"] is False


def test_exact_flow_authorization_allows_observed_flow_and_creates_no_implicit_edges():
    scenario, grants = _cross_scenario()
    result = _cross_analysis(scenario, grants)
    assert result["unauthorized_paths"] == []
    observed_edges = [edge for edge in result["composition_graph"]["edges"] if edge["relation"] == "OBSERVED_FLOW"]
    assert observed_edges
    assert {edge["link_id"] for edge in observed_edges} == {"authorized-enterprise-to-issue"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_provider", "mock-code-host"),
        ("source_principal_id", "different-principal"),
        ("source_grant_id", "different-grant"),
        ("source_capability", "list_enterprise_files"),
        ("target_capability", "update_issues"),
    ],
)
def test_changing_one_authorization_identity_component_denies_flow(field, value):
    scenario, grants = _cross_scenario()
    original = scenario.authorized_flows[0]
    changed = AuthorizedFlow.model_validate({**original.model_dump(mode="python"), field: value})
    result = _cross_analysis(scenario, grants, authorizations=[changed])
    assert len(result["unauthorized_paths"]) == 1


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"observed_provider": "mock-enterprise", "observed_principal_id": "principal-a", "observed_grant_id": "grant-a"}, "provider_mismatch"),
        ({"observed_provider": "mock-code-host", "observed_principal_id": "principal-b", "observed_grant_id": "grant-a"}, "principal_mismatch"),
        ({"observed_provider": "mock-code-host", "observed_principal_id": "principal-a", "observed_grant_id": "grant-b"}, "grant_mismatch"),
    ],
)
def test_runtime_identity_mismatches_fail_closed_before_authority_checks(kwargs, reason):
    contract = _contract()
    result = evaluate_capability_attempt(
        contract,
        attempted_capability="read_repository_contents",
        observed_scopes=["content.read"],
        now=contract.created_at,
        **kwargs,
    )
    assert result["decision"] == "block"
    assert result["reason_code"] == reason


def test_omitted_runtime_identity_does_not_widen_stored_contract_authority():
    contract = _contract()
    allowed = evaluate_capability_attempt(
        contract,
        attempted_capability="read_repository_contents",
        observed_scopes=["content.read"],
        now=contract.created_at,
    )
    denied = evaluate_capability_attempt(
        contract,
        attempted_capability="configure_external_webhooks",
        observed_scopes=["content.read"],
        now=contract.created_at,
    )
    assert allowed["decision"] == "allow"
    assert denied["decision"] == "block"


def test_phase4_corpus_hash_and_v2_corpus_are_stable():
    assert corpus_hash(get_evaluation_corpus()) == PHASE4_HASH
    corpus = get_evaluation_corpus_v2()
    assert len(corpus.legacy_cases) + len(corpus.provider_cases) == 36
    assert corpus_v2_hash(corpus) == corpus_v2_hash(get_evaluation_corpus_v2())
    assert len({item.case_id for item in [*corpus.legacy_cases, *corpus.provider_cases]}) == 36


def test_all_provider_qualified_cases_match_declared_ground_truth():
    results = [evaluate_provider_qualified_case(case) for case in get_evaluation_corpus_v2().provider_cases]
    assert all(item["scope_sentry_matches_ground_truth"] for item in results)
    unsafe = next(item for item in results if item["case_id"] == "v2-unauthorized-cross-exfiltration")
    safe = next(item for item in results if item["case_id"] == "v2-safe-authorized-cross-flow")
    assert unsafe["scope_sentry"]["global_cross_provider_contract_created"] is False
    assert unsafe["scope_sentry"]["unauthorized_path_count"] == 1
    assert safe["scope_sentry"]["unauthorized_path_count"] == 0
    assert len(safe["scope_sentry"]["contract_bindings"]) == 2


def test_original_and_new_demo_scenarios_pass_and_expose_provider_provenance():
    client = TestClient(app)
    scenarios = list_scenarios()
    assert len(scenarios) == 14
    for scenario in scenarios:
        response = client.post(f"/api/v1/demo/scenarios/{scenario.scenario_id}/run")
        assert response.status_code == 200
        payload = response.json()
        assert payload["passed"] is True
        assert payload["providers"]
    cross = client.post("/api/v1/demo/scenarios/unauthorized-cross-provider-exfiltration/run").json()
    assert len(cross["composition_summary"]["unauthorized_paths"]) == 1
    assert cross["composition_summary"]["unauthorized_paths"][0]["cross_provider"] is True


def test_dashboard_source_renders_provider_provenance_without_unsafe_dom_methods():
    source = Path("app/static/dashboard/dashboard.js").read_text(encoding="utf-8")
    assert "provider-badge" in source
    assert "cross-provider-warning" in source
    assert "qualified_capabilities" in source
    for forbidden in ("innerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write"):
        assert forbidden not in source


def test_v2_runner_keeps_phase4_files_and_normal_evidence_unchanged(tmp_path, monkeypatch):
    output = tmp_path / "reports"
    output.mkdir()
    originals = {}
    for name in ("scope_sentry_evaluation.json", "scope_sentry_evaluation.csv", "scope_sentry_evaluation.md"):
        content = f"frozen-{name}".encode()
        (output / name).write_bytes(content)
        originals[name] = hashlib.sha256(content).hexdigest()
    normal_evidence = tmp_path / "normal-evidence.jsonl"
    normal_evidence.write_text('{"frozen":true}\n', encoding="utf-8")
    normal_hash = hashlib.sha256(normal_evidence.read_bytes()).hexdigest()
    monkeypatch.setenv("SCOPESENTRY_EVIDENCE_PATH", str(normal_evidence))

    report, paths = run_evaluation_v2(iterations=1, warmups=0, output_dir=output)

    assert report["evidence"]["valid"] is True
    assert report["evidence"]["records_checked"] == 36
    assert report["evidence"]["normal_evidence_unchanged"] is True
    assert report["evidence"]["phase4_reports_unchanged"] is True
    assert hashlib.sha256(normal_evidence.read_bytes()).hexdigest() == normal_hash
    assert all(hashlib.sha256((output / name).read_bytes()).hexdigest() == digest for name, digest in originals.items())
    assert all(Path(path).name.startswith("scope_sentry_evaluation_v2") for path in paths.values())
    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert payload["metadata"]["corpus_hash"] == corpus_v2_hash()
