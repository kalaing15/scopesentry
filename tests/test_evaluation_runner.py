import csv
import json
from pathlib import Path

import pytest

from app.evaluation import runner
from app.evaluation.reports import CSV_HEADERS


def test_invalid_iteration_arguments():
    with pytest.raises(ValueError, match="iterations"):
        runner.run_evaluation(iterations=0, warmups=0, output_dir="unused")
    with pytest.raises(ValueError, match="warmups"):
        runner.run_evaluation(iterations=1, warmups=-1, output_dir="unused")


def test_full_evaluation_reports_and_evidence_isolation(tmp_path: Path, monkeypatch):
    normal = tmp_path / "normal-evidence.jsonl"
    original = b"existing-normal-evidence\n"
    normal.write_bytes(original)
    monkeypatch.setenv("SCOPESENTRY_EVIDENCE_PATH", str(normal))
    output = tmp_path / "reports"
    report, paths = runner.run_evaluation(iterations=1, warmups=0, output_dir=output)

    assert report["corpus_summary"]["total_cases"] == 24
    assert report["aggregate_metrics"]["baseline"]["counts"]["false_negative"] > 0
    assert report["aggregate_metrics"]["scope_sentry"]["counts"]["false_negative"] == 0
    assert all(case["scope_sentry_matches_ground_truth"] for case in report["cases"])
    assert report["evidence"]["valid"] is True
    assert report["evidence"]["records_checked"] == 24
    assert report["evidence"]["normal_evidence_unchanged"] is True
    assert normal.read_bytes() == original
    assert set(paths) == {"json", "csv", "markdown"}
    loaded = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "1.0.0"
    with Path(paths["csv"]).open(encoding="utf-8", newline="") as stream:
        assert next(csv.reader(stream)) == CSV_HEADERS
    markdown = Path(paths["markdown"]).read_text(encoding="utf-8")
    for heading in ("## Methodology", "## Corpus composition", "## Metric definitions", "## Security findings", "## Least-privilege findings", "## Performance observations", "## Evidence integrity", "## Limitations", "## Reproduction"):
        assert heading in markdown


def test_missing_normal_evidence_file_remains_absent(tmp_path: Path, monkeypatch):
    normal = tmp_path / "absent.jsonl"
    monkeypatch.setenv("SCOPESENTRY_EVIDENCE_PATH", str(normal))
    report, _ = runner.run_evaluation(iterations=1, warmups=0, output_dir=tmp_path / "reports")
    assert not normal.exists()
    assert report["evidence"]["normal_evidence_initial_state"] == "absent"
    assert report["evidence"]["normal_evidence_final_state"] == "absent"


def test_baseline_false_negatives_do_not_fail_cli(monkeypatch, tmp_path: Path):
    report = {"corpus_summary": {"total_cases": 1}, "aggregate_metrics": {"baseline": {"counts": {"false_negative": 1}}, "scope_sentry": {"counts": {}}}, "evidence": {"valid": True, "records_checked": 1, "normal_evidence_unchanged": True}, "cases": [{"case_id": "case", "scope_sentry_matches_ground_truth": True}]}
    monkeypatch.setattr(runner, "run_evaluation", lambda **kwargs: (report, {}))
    assert runner.main(["--iterations", "1", "--output-dir", str(tmp_path)]) == 0


def test_scope_sentry_ground_truth_mismatch_fails_cli(monkeypatch, tmp_path: Path):
    report = {"corpus_summary": {"total_cases": 1}, "aggregate_metrics": {"baseline": {"counts": {}}, "scope_sentry": {"counts": {}}}, "evidence": {"valid": True, "records_checked": 1, "normal_evidence_unchanged": True}, "cases": [{"case_id": "case", "scope_sentry_matches_ground_truth": False}]}
    monkeypatch.setattr(runner, "run_evaluation", lambda **kwargs: (report, {}))
    assert runner.main(["--iterations", "1", "--output-dir", str(tmp_path)]) == 1


def test_production_modules_do_not_import_evaluation_package():
    root = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        if "evaluation" in path.parts:
            continue
        if "app.evaluation" in path.read_text(encoding="utf-8"):
            offenders.append(str(path))
    assert offenders == []
