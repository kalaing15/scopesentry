"""Security and least-privilege metric calculations."""

import statistics
from collections import Counter, defaultdict
from typing import Any, Iterable


def rate(numerator: int, denominator: int) -> dict[str, Any]:
    ratio = numerator / denominator if denominator else None
    return {
        "numerator": numerator,
        "denominator": denominator,
        "ratio": ratio,
        "percentage": round(ratio * 100, 2) if ratio is not None else None,
    }


def confusion_matrix(results: Iterable[dict[str, Any]], system_key: str) -> dict[str, Any]:
    results = list(results)
    counts = Counter({"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0, "evaluation_error": 0})
    categories: dict[str, Counter[str]] = defaultdict(Counter)
    for result in results:
        truth_unsafe = result["ground_truth"]["classification"] == "unsafe"
        predicted = result[system_key]["normalized_result"]
        if predicted not in {"permitted", "prevented"}:
            label = "evaluation_error"
        elif truth_unsafe and predicted == "prevented":
            label = "true_positive"
        elif truth_unsafe:
            label = "false_negative"
        elif predicted == "permitted":
            label = "true_negative"
        else:
            label = "false_positive"
        counts[label] += 1
        categories[result["category"]][label] += 1
        result[f"{system_key}_classification"] = label

    tp, tn = counts["true_positive"], counts["true_negative"]
    fp, fn = counts["false_positive"], counts["false_negative"]
    classified = tp + tn + fp + fn
    unsafe = tp + fn
    safe = tn + fp
    represented_unsafe = {
        result["category"]
        for result in results
        if result["ground_truth"]["classification"] == "unsafe"
    }
    covered_unsafe = {
        result["category"]
        for result in results
        if result["ground_truth"]["classification"] == "unsafe"
        and result[system_key]["normalized_result"] == "prevented"
    }
    def category_rate(names: set[str]) -> dict[str, Any]:
        applicable = [
            item for item in results
            if item["ground_truth"]["classification"] == "unsafe"
            and item["category"] in names
        ]
        prevented = sum(
            item[system_key]["normalized_result"] == "prevented"
            for item in applicable
        )
        return rate(prevented, len(applicable))

    return {
        "counts": dict(counts),
        "security_detection_rate_recall": rate(tp, unsafe),
        "precision": rate(tp, tp + fp),
        "false_allow_rate": rate(fn, unsafe),
        "false_block_rate": rate(fp, safe),
        "safe_case_allow_rate": rate(tn, safe),
        "unsafe_case_prevention_rate": rate(tp, unsafe),
        "overall_classification_accuracy": rate(tp + tn, classified),
        "attack_category_coverage": rate(len(covered_unsafe), len(represented_unsafe)),
        "runtime_drift_detection_rate": category_rate({"runtime_scope_drift"}),
        "composition_path_detection_rate": category_rate({"unauthorized_composition"}),
        "missing_permission_detection_rate": category_rate({"missing_permission", "multiple_missing_permissions"}),
        "excessive_scope_detection_rate": category_rate({"excessive_read_authority", "excessive_write_authority", "unknown_public_scope", "excessive_authority_without_misuse"}),
        "by_category": {name: dict(value) for name, value in sorted(categories.items())},
    }


def exposure_metrics(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    ratios: list[float] = []
    reduced = 0
    no_reduction = 0
    for result in results:
        scope = result["scope_sentry"]
        original_count = len(scope["original_granted_scopes"])
        removed_count = len(scope["removed_scopes"])
        reduction = removed_count / original_count if original_count else None
        scope["scope_counts"] = {
            "original_granted": original_count,
            "required": len(scope["required_scopes"]),
            "matched": len(scope["matched_scopes"]),
            "excessive": len(scope["excessive_scopes"]),
            "missing": len(scope["missing_scopes"]),
            "synthesized": len(scope["synthesized_scopes"]),
            "removed": removed_count,
        }
        scope["exposure_reduction_ratio"] = reduction
        if reduction is not None:
            ratios.append(reduction)
            if removed_count:
                reduced += 1
            else:
                no_reduction += 1
    return {
        "applicable_cases": len(ratios),
        "mean_exposure_reduction_ratio": statistics.fmean(ratios) if ratios else None,
        "median_exposure_reduction_ratio": statistics.median(ratios) if ratios else None,
        "maximum_exposure_reduction_ratio": max(ratios) if ratios else None,
        "cases_where_authority_was_reduced": reduced,
        "cases_where_no_reduction_was_necessary": no_reduction,
        "interpretation": "Scope-count reduction is one authority-exposure indicator, not a complete security measure.",
    }
