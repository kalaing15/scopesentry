"""Phase 6 release-verification, traceability, and preservation tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.gateway.repository import get_contract_repository
from app.release.manifest import (
    EXPECTED_SCENARIOS,
    FAILED,
    GROUND_TRUTH_STATUS,
    INCOMPLETE,
    READY,
    ReleaseProfile,
    atomic_write_text,
    load_traceability,
    render_manifest_markdown,
    render_traceability_markdown,
    sanitize_manifest,
    scan_external_clients,
    scan_secrets,
    snapshot_files,
    validate_traceability,
)
from app.release.verify import verify_release


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIME = lambda: datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def verified_manifest(tmp_path_factory):
    return verify_release(
        root=ROOT,
        output_dir=tmp_path_factory.mktemp("release-success"),
        now=FIXED_TIME,
    )


def test_release_verifier_success_and_conservative_warnings(verified_manifest):
    assert verified_manifest["release_status"] == READY
    assert verified_manifest["ground_truth_status"] == GROUND_TRUTH_STATUS
    assert any("independent review pending" in item for item in verified_manifest["warnings"])
    if verified_manifest["source_control"]["dirty"]:
        assert any("dirty" in item.lower() for item in verified_manifest["warnings"])


@pytest.mark.parametrize(
    ("profile", "check_name"),
    [
        (replace(ReleaseProfile(), expected_providers=("google",)), "provider_registry_integrity"),
        (replace(ReleaseProfile(), expected_scenarios=EXPECTED_SCENARIOS[:-1]), "scenario_registry_integrity"),
        (replace(ReleaseProfile(), expected_v1_hash="f" * 64), "fresh_corpus_hashes"),
        (replace(ReleaseProfile(), expected_v2_hash="e" * 64), "fresh_corpus_hashes"),
    ],
)
def test_required_identity_and_corpus_mismatch_fails(tmp_path, profile, check_name):
    manifest = verify_release(root=ROOT, output_dir=tmp_path, profile=profile, now=FIXED_TIME)
    assert manifest["release_status"] == FAILED
    assert any(item["name"] == check_name and not item["passed"] for item in manifest["verification_checks"])


def test_missing_required_report_is_incomplete(tmp_path):
    profile = replace(
        ReleaseProfile(),
        report_files=(*ReleaseProfile().report_files, "reports/evaluation/not-present.json"),
    )
    manifest = verify_release(root=ROOT, output_dir=tmp_path, profile=profile, now=FIXED_TIME)
    assert manifest["release_status"] == INCOMPLETE


def test_invalid_evidence_fails_without_writing_it(tmp_path):
    evidence = tmp_path / "invalid.jsonl"
    evidence.write_text("not-json\n", encoding="utf-8")
    before = evidence.read_bytes()
    manifest = verify_release(root=ROOT, output_dir=tmp_path / "out", evidence_path=evidence, now=FIXED_TIME)
    assert manifest["release_status"] == FAILED
    assert manifest["evidence_verification"]["records_checked"] == 0
    assert evidence.read_bytes() == before


def test_verifier_preserves_normal_evidence_reports_and_contracts(tmp_path):
    evidence = ROOT / "runtime/evidence.jsonl"
    evidence_before = evidence.read_bytes() if evidence.exists() else None
    reports_before = snapshot_files(ROOT, ReleaseProfile().report_files)
    contracts_before = [item.model_dump(mode="json") for item in get_contract_repository().list(100)]
    manifest = verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    assert (evidence.read_bytes() if evidence.exists() else None) == evidence_before
    assert snapshot_files(ROOT, ReleaseProfile().report_files) == reports_before
    assert [item.model_dump(mode="json") for item in get_contract_repository().list(100)] == contracts_before
    assert all(
        next(item for item in manifest["verification_checks"] if item["name"] == name)["passed"]
        for name in ("normal_evidence_preserved", "contracts_preserved", "evaluation_reports_preserved")
    )


def test_evidence_count_is_observed_not_hard_coded(verified_manifest):
    count = verified_manifest["evidence_verification"]["records_checked"]
    assert isinstance(count, int) and count >= 0
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    assert "64 records" not in source


def test_traceability_schema_paths_symbols_and_matrix_agree():
    path = ROOT / "docs/ipr/traceability.json"
    entries = load_traceability(path)
    assert len({item["element_id"] for item in entries}) == len(entries)
    assert validate_traceability(ROOT, path) == []
    assert (ROOT / "docs/ipr/Novelty-Traceability-Matrix.md").read_text(encoding="utf-8") == render_traceability_markdown(entries)


def test_traceability_rejects_duplicate_ids(tmp_path):
    data = json.loads((ROOT / "docs/ipr/traceability.json").read_text(encoding="utf-8"))
    data["elements"].append(data["elements"][0])
    path = tmp_path / "traceability.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_traceability(path)


def test_traceability_reports_missing_path_and_python_symbol(tmp_path):
    data = json.loads((ROOT / "docs/ipr/traceability.json").read_text(encoding="utf-8"))
    data["elements"][0]["implementation_paths"] = ["app/not_real.py"]
    data["elements"][0]["symbols"][0]["names"] = ["not_a_real_symbol"]
    path = tmp_path / "traceability.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    errors = validate_traceability(ROOT, path)
    assert any("missing path" in item for item in errors)
    assert any("missing symbol" in item for item in errors)


def test_verifier_source_does_not_call_scenario_or_evaluation_runners():
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    assert "DemoRunner" not in source
    assert "app.evaluation.runner" not in source
    assert "run_evaluation(" not in source


def test_provider_scenario_and_dependency_order_is_deterministic(verified_manifest):
    assert [item["adapter_id"] for item in verified_manifest["provider_inventory"]] == sorted(item["adapter_id"] for item in verified_manifest["provider_inventory"])
    assert verified_manifest["scenario_inventory"] == sorted(verified_manifest["scenario_inventory"])
    requirements = [item["declared_requirement"].lower() for item in verified_manifest["dependency_inventory"]]
    assert requirements == sorted(requirements)
    assert verified_manifest["dependency_inventory_label"] == "Local dependency inventory — not a vulnerability audit"


def test_secret_scan_fails_safely_without_exposing_value(tmp_path):
    secret_value = "super-secret-value-123456789"
    source = tmp_path / "unsafe.py"
    source.write_text(f'access_token = "{secret_value}"\n', encoding="utf-8")
    findings = scan_secrets(tmp_path, ["unsafe.py"])
    assert findings and findings[0]["severity"] == "high"
    assert secret_value not in json.dumps(findings)


def test_test_only_httpx_is_not_production_networking(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_local.py").write_text("import httpx\n", encoding="utf-8")
    findings = scan_external_clients(tmp_path)
    assert findings[0]["classification"] == "local_test_only_client_usage"
    assert not any(item["classification"] == "production_external_client_capability" for item in findings)


def test_production_external_client_is_classified_as_failure(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/client.py").write_text("import requests\n", encoding="utf-8")
    findings = scan_external_clients(tmp_path)
    assert findings == [{"path": "app/client.py", "classification": "production_external_client_capability", "detail": "Imports local testing or external-client package: requests"}]


def test_manifest_sanitizer_rejects_absolute_paths_and_secret_keys():
    with pytest.raises(ValueError, match="absolute"):
        sanitize_manifest({"path": "C:\\Users\\person\\file"})
    with pytest.raises(ValueError, match="prohibited key"):
        sanitize_manifest({"access_token": "suppressed"})


def test_atomic_output_and_json_markdown_core_equivalence(tmp_path, verified_manifest):
    target = tmp_path / "atomic.txt"
    atomic_write_text(target, "complete\n")
    assert target.read_text(encoding="utf-8") == "complete\n"
    markdown = render_manifest_markdown(verified_manifest)
    assert verified_manifest["release_status"] in markdown
    assert str(len(verified_manifest["scenario_inventory"])) in markdown
    assert verified_manifest["corpora"]["v1"]["hash"] in markdown
    assert verified_manifest["corpora"]["v2"]["hash"] in markdown


def test_manifest_does_not_hash_itself_or_contain_absolute_paths(verified_manifest):
    serialized = json.dumps(verified_manifest, sort_keys=True)
    assert "manifest_sha256" not in serialized
    sanitize_manifest(verified_manifest)
    assert "reports/release" not in serialized


def test_required_documents_exist_and_ground_truth_template_stays_pending():
    assert all((ROOT / path).is_file() for path in ReleaseProfile().document_files)
    review = (ROOT / "docs/evaluation-ground-truth-review.md").read_text(encoding="utf-8")
    assert "Reviewer name:\n" in review
    assert "Approval:\n" in review
    assert "Signature:\n" in review
    assert "independent review pending" in review.lower()


def test_generated_output_is_git_ignored_and_not_source_dirty_input():
    assert "reports/release/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    assert source.index("git_before = _git_metadata") < source.index("output_dir.mkdir")


def test_existing_dashboard_openapi_and_release_facts_are_unchanged(verified_manifest):
    from app.main import app

    schema = app.openapi()
    assert "/api/v1/demo/scenarios/{scenario_id}/run" in schema["paths"]
    assert (ROOT / "app/static/dashboard/index.html").is_file()
    assert verified_manifest["corpora"]["v1"]["size"] == 24
    assert verified_manifest["corpora"]["v2"]["size"] == 36
    assert verified_manifest["scenario_inventory"] == list(EXPECTED_SCENARIOS)


def test_dirty_git_state_produces_warning_not_false_technical_failure(tmp_path):
    """A dirty working tree must not fail technical verification checks."""
    manifest = verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    required_checks = [item for item in manifest["verification_checks"] if item["required"]]
    # All required technical checks must still pass regardless of git state.
    for item in required_checks:
        assert item["passed"], f"Required check '{item['name']}' failed unexpectedly"
    # If dirty, it must appear only as a warning.
    if manifest["source_control"].get("dirty"):
        assert any("dirty" in w.lower() for w in manifest["warnings"])
        # Dirty state must not set release_status to FAILED
        assert manifest["release_status"] != FAILED


def test_verifier_does_not_import_or_call_scenario_runner():
    """Verify the release verifier source never imports DemoRunner or the scenario runner."""
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    assert "DemoRunner" not in source
    assert "demo_runner" not in source
    assert "from app.orchestrator" not in source
    assert "app.providers.scenario_registry" not in source.split("from app.providers.registry")[0]


def test_verifier_does_not_call_evaluation_runners():
    """Verify the release verifier source never imports or calls evaluation runners."""
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    assert "app.evaluation.runner" not in source
    assert "run_evaluation(" not in source
    assert "runner.run(" not in source
    assert "runner_v2" not in source


def test_verifier_does_not_mutate_contract_state(tmp_path):
    """Contracts must be unchanged before vs after verification."""
    contracts_before = [item.model_dump(mode="json") for item in get_contract_repository().list(100)]
    verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    contracts_after = [item.model_dump(mode="json") for item in get_contract_repository().list(100)]
    assert contracts_before == contracts_after


def test_report_files_remain_byte_for_byte_unchanged(tmp_path):
    """All six evaluation reports must be byte-identical before and after verification."""
    hashes_before = snapshot_files(ROOT, ReleaseProfile().report_files)
    verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    hashes_after = snapshot_files(ROOT, ReleaseProfile().report_files)
    assert hashes_before == hashes_after
    for name, digest in hashes_before.items():
        assert digest is not None, f"Report file {name} missing before verification"
        assert digest == hashes_after[name], f"Report file {name} changed during verification"


def test_output_files_do_not_affect_captured_pre_output_git_state(tmp_path):
    """Git state is captured before output dir is created; output dir is git-ignored."""
    source = (ROOT / "app/release/verify.py").read_text(encoding="utf-8")
    git_capture_pos = source.index("git_before = _git_metadata")
    mkdir_pos = source.index("output_dir.mkdir")
    assert git_capture_pos < mkdir_pos
    assert "reports/release/" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_manifest_does_not_hash_itself(verified_manifest):
    """The manifest must not contain its own hash."""
    serialized = json.dumps(verified_manifest, sort_keys=True)
    assert "manifest_sha256" not in serialized
    assert "manifest_hash" not in serialized


def test_human_review_pending_is_represented_accurately(verified_manifest):
    """Ground truth must be labelled author-defined and pending independent review."""
    assert verified_manifest["ground_truth_status"] == GROUND_TRUTH_STATUS
    assert "author-defined" in verified_manifest["ground_truth_status"]
    assert "independent review pending" in verified_manifest["ground_truth_status"]
    # Must appear as warning, not as a check failure
    assert any("independent review pending" in w for w in verified_manifest["warnings"])
    gt_check = [c for c in verified_manifest["verification_checks"] if "ground_truth" in c.get("name", "")]
    # There must NOT be a required check that fails due to ground truth pending
    for c in gt_check:
        if c["required"]:
            assert c["passed"]


def test_json_and_markdown_manifests_contain_equivalent_release_status_and_core_facts(tmp_path):
    """Both manifest formats must present the same release status and core facts."""
    manifest = verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    md_text = render_manifest_markdown(manifest)
    # Release status
    assert f"`{manifest['release_status']}`" in md_text
    # Core corpus facts
    assert manifest["corpora"]["v1"]["hash"] in md_text
    assert manifest["corpora"]["v2"]["hash"] in md_text
    assert str(manifest["corpora"]["v1"]["size"]) in md_text
    assert str(manifest["corpora"]["v2"]["size"]) in md_text
    # Provider count
    for item in manifest["provider_inventory"]:
        assert item["canonical_id"] in md_text
    # Scenario count
    assert str(len(manifest["scenario_inventory"])) in md_text
    # Evidence validity
    assert str(manifest["evidence_verification"]["records_checked"]) in md_text
    # Ground truth
    assert manifest["ground_truth_status"] in md_text
    # Git commit
    assert manifest["source_control"]["commit"] in md_text


def test_existing_apis_dashboard_scenarios_corpora_and_reports_remain_unchanged():
    """Ensure existing core functionality is unchanged by Phase 6."""
    from app.main import app
    schema = app.openapi()
    # Core API routes exist
    assert "/api/v1/demo/scenarios" in schema["paths"]
    assert "/api/v1/demo/scenarios/{scenario_id}/run" in schema["paths"]
    assert "/api/v1/evidence/verify" in schema["paths"]
    assert "/" in schema["paths"]
    # Dashboard
    assert (ROOT / "app/static/dashboard/index.html").is_file()
    # Scenarios
    from app.providers.scenario_registry import list_scenarios
    scenarios = [s.scenario_id for s in list_scenarios()]
    assert tuple(scenarios) == EXPECTED_SCENARIOS
    # Corpora sizes
    from app.evaluation.corpus import get_evaluation_corpus
    from app.evaluation.corpus_v2 import get_evaluation_corpus_v2
    assert len(get_evaluation_corpus().cases) == 24
    v2 = get_evaluation_corpus_v2()
    assert len(v2.legacy_cases) + len(v2.provider_cases) == 36
    # Reports exist
    for report_file in ReleaseProfile().report_files:
        assert (ROOT / report_file).is_file(), f"Report {report_file} missing"
