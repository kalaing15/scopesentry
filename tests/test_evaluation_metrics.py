from pathlib import Path

from app.evaluation.metrics import confusion_matrix, rate
from app.evaluation.reports import _atomic_write, _safe_csv_cell
from app.evaluation.timing import benchmark, summarize_ns


def _result(truth, predicted, category="test"):
    return {"ground_truth": {"classification": truth}, "category": category, "system": {"normalized_result": predicted}}


def test_confusion_matrix_and_detection_without_containment():
    results = [
        _result("unsafe", "prevented"),
        _result("unsafe", "permitted"),
        _result("safe", "permitted"),
        _result("safe", "prevented"),
    ]
    metrics = confusion_matrix(results, "system")
    assert metrics["counts"] == {"true_positive": 1, "true_negative": 1, "false_positive": 1, "false_negative": 1, "evaluation_error": 0}
    assert results[1]["system_classification"] == "false_negative"


def test_zero_denominator_rates_are_explicitly_not_applicable():
    assert rate(0, 0) == {"numerator": 0, "denominator": 0, "ratio": None, "percentage": None}


def test_nearest_rank_p95_for_small_and_large_samples():
    assert summarize_ns([1, 2, 3])["p95_nearest_rank"] == 3
    assert summarize_ns(list(range(1, 101)))["p95_nearest_rank"] == 95


def test_warmups_are_excluded_from_timing_samples():
    calls = []
    summary, samples = benchmark(lambda: calls.append(len(calls)), iterations=3, warmups=2)
    assert len(calls) == 5
    assert len(samples) == 3
    assert summary["sample_count"] == 3


def test_csv_cells_prevent_spreadsheet_formula_execution():
    for prefix in "=+-@":
        assert _safe_csv_cell(prefix + "formula").startswith("'")
    assert _safe_csv_cell("ordinary") == "ordinary"


def test_atomic_replacement_uses_complete_new_content(tmp_path: Path):
    target = tmp_path / "report.txt"
    _atomic_write(target, "old")
    _atomic_write(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob("*.tmp"))
