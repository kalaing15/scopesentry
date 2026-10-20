"""Phase 7 submission-document and strengthened traceability tests."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.release.manifest import (
    DOCUMENT_FILES,
    EXPECTED_REPORT_HASHES,
    FAILED,
    ReleaseProfile,
    canonical_report_sha256,
    evidence_event_types,
    head_git_blob_sha256,
    load_traceability,
    render_traceability_markdown,
    snapshot_files,
    tracked_files,
    validate_traceability,
)
from app.release.verify import verify_release


ROOT = Path(__file__).resolve().parents[1]
TRACEABILITY = ROOT / "docs/ipr/traceability.json"
FIXED_TIME = lambda: datetime(2026, 10, 20, tzinfo=timezone.utc)
SUBMISSION_FILES = tuple(
    f"docs/ipr/submission/{name}"
    for name in (
        "00-Submission-Index.md",
        "01-Invention-Disclosure.md",
        "02-Novelty-and-Claim-Concepts.md",
        "03-Submission-Diagrams.md",
        "04-Demo-Guide.md",
        "05-Inventor-Faculty-Review-Checklist.md",
        "06-Prior-Art-Review-Worksheet.md",
    )
)


def _modified_traceability(tmp_path: Path, mutate) -> Path:
    data = json.loads(TRACEABILITY.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "traceability.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_submission_package_is_complete_and_registered():
    assert all((ROOT / path).is_file() for path in SUBMISSION_FILES)
    assert set(SUBMISSION_FILES) <= set(DOCUMENT_FILES)
    index = (ROOT / SUBMISSION_FILES[0]).read_text(encoding="utf-8")
    assert "canonical submission" in index.lower()
    assert "author-defined; independent review pending" in index


def test_invention_disclosure_contains_required_sections_and_qualifications():
    disclosure = (ROOT / SUBMISSION_FILES[1]).read_text(encoding="utf-8")
    required_headings = (
        "## Abstract", "## Technical field", "## Background", "## Problem statement",
        "## Objectives", "## Definitions", "## Trust and authority model",
        "## Architecture", "## Provider-qualified identity model",
        "## Intent-to-authority mapping", "## Capability graph",
        "## Exposure differential", "## Bounded least-privilege synthesis",
        "## Contract generation and isolation", "## Runtime decision ordering",
        "## Observed-versus-authorized flow analysis",
        "## Cross-provider composition analysis", "## Tamper-evident evidence",
        "## Explainability", "## End-to-end workflow", "## Implemented scenarios",
        "## Experimental methodology and results", "## Technical effects",
        "## Qualified novelty comparison", "## Candidate claim concepts",
        "## Alternative embodiments", "## Limitations", "## Reproducibility",
        "## Traceability", "## Review status",
    )
    assert all(heading in disclosure for heading in required_headings)
    for phrase in (
        "Runtime capability-decision enforcement within the credential-free simulator",
        "Exact within the configured finite local catalogue and risk model",
        "Tamper-evident under the documented storage assumptions",
        "Demonstrated on an author-defined deterministic local corpus",
    ):
        assert phrase.lower() in disclosure.lower()
    assert "does not establish patentability" in disclosure.lower()


def test_diagrams_cover_required_views_and_boundaries():
    diagrams = (ROOT / SUBMISSION_FILES[3]).read_text(encoding="utf-8")
    assert diagrams.count("```mermaid") == 6
    for label in (
        "Overall architecture", "Processing sequence", "Provider-qualified capability graph",
        "Contract isolation", "Runtime decision flow", "Evidence chain",
        "Synthetic-provider boundary", "Process-local", "Supplied runtime observations",
        "Simulated runtime enforcement",
    ):
        assert label.lower() in diagrams.lower()


def test_traceability_uses_closed_version_1_1_schema_and_unique_ids():
    raw = json.loads(TRACEABILITY.read_text(encoding="utf-8"))
    assert set(raw) == {"schema_version", "elements"}
    assert raw["schema_version"] == "1.1"
    entries = load_traceability(TRACEABILITY)
    assert len({item["element_id"] for item in entries}) == len(entries) == 9
    assert {item["implementation_status"] for item in entries} <= {
        "fully_implemented", "partially_implemented", "conceptual_only"
    }
    assert {item["claim_suitability"] for item in entries} <= {
        "combination_candidate", "supporting_only", "unsuitable_standalone"
    }


def test_traceability_resolves_all_exact_support_and_projection():
    from app.providers.scenario_registry import list_scenarios

    scenarios = [item.scenario_id for item in list_scenarios()]
    errors = validate_traceability(
        ROOT,
        TRACEABILITY,
        scenario_ids=scenarios,
        allowed_evidence_events=evidence_event_types(ROOT),
    )
    assert errors == []
    entries = load_traceability(TRACEABILITY)
    matrix = ROOT / "docs/ipr/Novelty-Traceability-Matrix.md"
    assert matrix.read_text(encoding="utf-8") == render_traceability_markdown(entries)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data["elements"][0]["test_functions"][0]["names"].append("test_not_real"), "missing test function"),
        (lambda data: data["elements"][0]["scenario_ids"].append("not-a-scenario"), "unknown scenario"),
        (lambda data: data["elements"][0]["evaluation_references"][0]["case_ids"].append("not-a-case"), "unknown evaluation case"),
        (lambda data: data["elements"][0]["evaluation_references"][0]["categories"].append("not-a-category"), "unknown evaluation category"),
        (lambda data: data["elements"][0]["metric_json_paths"][0].update(expected=999), "metric mismatch"),
        (lambda data: data["elements"][0]["evidence_event_types"].append("not-an-event"), "unknown evidence event"),
    ],
)
def test_traceability_rejects_unresolved_exact_support(tmp_path, mutation, message):
    path = _modified_traceability(tmp_path, mutation)
    assert any(message in item for item in validate_traceability(ROOT, path))


def test_traceability_closed_schema_rejects_unknown_field(tmp_path):
    path = _modified_traceability(
        tmp_path,
        lambda data: data["elements"][0].update(unapproved_field=True),
    )
    with pytest.raises(ValueError, match="closed schema"):
        load_traceability(path)


def test_tracked_file_enumeration_fails_closed(monkeypatch):
    completed = subprocess.CompletedProcess(["git"], returncode=1, stdout=b"", stderr=b"failure")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: completed)
    with pytest.raises(RuntimeError, match="enumeration failed"):
        tracked_files(ROOT)


def test_frozen_report_hash_mismatch_fails_release(tmp_path):
    profile = replace(
        ReleaseProfile(),
        expected_report_hashes=((ReleaseProfile().report_files[0], "0" * 64),),
    )
    manifest = verify_release(root=ROOT, output_dir=tmp_path, profile=profile, now=FIXED_TIME)
    check = next(
        item for item in manifest["verification_checks"]
        if item["name"] == "frozen_evaluation_report_hashes"
    )
    assert not check["passed"]
    assert manifest["release_status"] == FAILED


def test_canonical_report_hash_accepts_equivalent_lf_and_crlf(tmp_path):
    lf_path = tmp_path / "report-lf.json"
    crlf_path = tmp_path / "report-crlf.json"
    lf_path.write_bytes(b'{\n  "result": "safe"\n}\n')
    crlf_path.write_bytes(b'{\r\n  "result": "safe"\r\n}\r\n')
    assert canonical_report_sha256(lf_path) == canonical_report_sha256(crlf_path)


def test_changed_report_content_changes_canonical_hash(tmp_path):
    report = tmp_path / "report.md"
    report.write_bytes(b"# Frozen result\n\nvalid\n")
    approved = canonical_report_sha256(report)
    report.write_bytes(b"# Frozen result\n\nmodified\n")
    assert canonical_report_sha256(report) != approved


def test_canonical_report_hash_rejects_bare_cr(tmp_path):
    report = tmp_path / "report.csv"
    report.write_bytes(b"name,value\runsafe,1\n")
    with pytest.raises(ValueError, match="bare CR"):
        canonical_report_sha256(report)


def test_all_six_approved_canonical_and_head_blob_hashes_validate():
    expected = dict(EXPECTED_REPORT_HASHES)
    assert set(expected) == set(ReleaseProfile().report_files)
    for relative, approved in expected.items():
        assert canonical_report_sha256(ROOT / relative) == approved
        assert head_git_blob_sha256(ROOT, relative) == approved


def test_changed_head_blob_fails_even_when_working_content_matches(tmp_path, monkeypatch):
    import app.release.verify as release_verify

    target = ReleaseProfile().report_files[0]
    real_reader = release_verify.head_git_blob_sha256

    def changed_blob(root: Path, relative: str) -> str:
        return "0" * 64 if relative == target else real_reader(root, relative)

    monkeypatch.setattr(release_verify, "head_git_blob_sha256", changed_blob)
    manifest = release_verify.verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    check = next(
        item for item in manifest["verification_checks"]
        if item["name"] == "frozen_evaluation_report_hashes"
    )
    assert not check["passed"]
    assert "HEAD Git-blob hash mismatch" in check["detail"]
    assert manifest["release_status"] == FAILED


def test_raw_snapshot_preservation_detects_byte_mutation(tmp_path):
    report = tmp_path / "report.json"
    report.write_bytes(b'{"line_endings":"LF"}\n')
    before = snapshot_files(tmp_path, ("report.json",))
    report.write_bytes(b'{"line_endings":"CRLF"}\r\n')
    after = snapshot_files(tmp_path, ("report.json",))
    assert before != after


def test_manifest_distinguishes_canonical_raw_and_head_hashes(tmp_path):
    manifest = verify_release(root=ROOT, output_dir=tmp_path, now=FIXED_TIME)
    for relative, hashes in manifest["evaluation_reports"]["files"].items():
        assert set(hashes) == {
            "canonical_sha256", "working_tree_raw_sha256",
            "head_blob_sha256", "preserved",
        }
        assert hashes["canonical_sha256"] == dict(EXPECTED_REPORT_HASHES)[relative]
        assert hashes["head_blob_sha256"] == hashes["canonical_sha256"]
        assert hashes["preserved"] is True


def test_gitattributes_contains_only_targeted_report_rules():
    rules = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert rules == [
        "reports/evaluation/*.json text eol=lf",
        "reports/evaluation/*.csv text eol=lf",
        "reports/evaluation/*.md text eol=lf",
    ]


def test_frozen_reports_have_no_git_working_tree_changes():
    status = subprocess.run(
        ["git", "status", "--short", "--", "reports/evaluation"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    diff = subprocess.run(
        ["git", "diff", "--", "reports/evaluation"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    assert status.stdout == ""
    assert diff.stdout == ""


def test_phase7_review_forms_remain_blank_and_nonconclusive():
    checklist = (ROOT / SUBMISSION_FILES[5]).read_text(encoding="utf-8")
    worksheet = (ROOT / SUBMISSION_FILES[6]).read_text(encoding="utf-8")
    assert "Reviewer name: __________________________________" in checklist
    assert "Filing or publication decision: __________________" in checklist
    assert "Reviewer: ____________________________________________________" in worksheet
    assert "no novelty" in worksheet.lower()
    assert "must not be interpreted as confirmation" in worksheet.lower()
