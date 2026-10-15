"""CLI runner for reproducible local ScopeSentry-R evaluation."""

import argparse
import hashlib
import json
import platform
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.evidence.service import EvidenceService, get_evidence_path
from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.corpus import corpus_hash, get_evaluation_corpus
from app.evaluation.engine import (
    _contract_for_case,
    combined_scopes,
    evaluate_case,
    evaluate_scope_sentry,
)
from app.evaluation.metrics import confusion_matrix, exposure_metrics
from app.evaluation.reports import write_reports
from app.evaluation.timing import benchmark, summarize_ns
from app.gateway.policy_engine import evaluate_capability_attempt
from app.planner.analysis_service import analyze_scope_grant
from app.planner.composition_engine import analyze_composition
from app.planner.exposure_engine import calculate_exposure_differential
from app.planner.intent_mapper import map_intents_to_scopes
from app.planner.least_privilege_synthesizer import synthesize_least_privilege


REPRODUCTION_COMMAND = "python -m app.evaluation.runner --iterations 50 --warmups 5 --output-dir reports\\evaluation"


def _file_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "sha256": None}
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"exists": True, "sha256": digest}


def _stage_callables(case) -> dict[str, Callable[[], Any]]:
    scopes = combined_scopes(case)
    required_scopes, unknown = map_intents_to_scopes(case.intended_actions)
    analysis = analyze_scope_grant(provider=case.provider, granted_scopes=scopes, intended_actions=case.intended_actions)
    calls: dict[str, Callable[[], Any]] = {
        "intent_analysis": lambda: map_intents_to_scopes(case.intended_actions),
        "exposure_calculation": lambda: calculate_exposure_differential(scopes, required_scopes, case.provider),
        "contract_synthesis": lambda: synthesize_least_privilege(case.provider, scopes, analysis["required_capabilities"], unknown or None),
        "end_to_end_scope_sentry": lambda: evaluate_scope_sentry(case),
        "static_baseline": lambda: StaticScopeBaseline().evaluate(provider=case.provider, intended_actions=case.intended_actions, granted_scopes=scopes),
    }
    if len(case.grants) > 1 or case.composition_links:
        grants = [grant.model_dump(mode="python") for grant in case.grants]
        calls["composition_analysis"] = lambda: analyze_composition(case.provider, grants, case.intended_actions)
    plan = analysis["least_privilege_plan"]
    if not analysis["unknown_intents"] and not analysis["missing_capabilities"] and plan["status"] == "complete" and case.runtime_attempts:
        contract = _contract_for_case(case, plan["selected_scopes"])
        attempt = case.runtime_attempts[0]
        calls["runtime_gateway_decision"] = lambda: evaluate_capability_attempt(contract, attempted_capability=attempt.attempted_capability, observed_scopes=attempt.observed_scopes, now=contract.created_at)
    return calls


def _performance(cases, iterations: int, warmups: int) -> dict[str, Any]:
    samples: dict[str, list[int]] = {}
    per_case: dict[str, dict[str, Any]] = {}
    for case in cases:
        for stage, callable_ in _stage_callables(case).items():
            summary, measured = benchmark(callable_, iterations=iterations, warmups=warmups)
            samples.setdefault(stage, []).extend(measured)
            per_case.setdefault(case.case_id, {})[stage] = summary
    return {
        "method": "time.perf_counter_ns",
        "unit": "nanoseconds",
        "warmups_per_applicable_case": warmups,
        "measured_iterations_per_applicable_case": iterations,
        "warmups_excluded": True,
        "excluded_operations": ["evidence I/O", "report I/O", "HTTP", "UUID creation", "temporary-file cleanup"],
        "end_to_end_includes": ["intent mapping", "capability graph and exposure analysis", "least-privilege synthesis", "composition analysis when applicable", "runtime gateway policy when applicable", "evaluation normalization"],
        "stages": {stage: summarize_ns(values) for stage, values in sorted(samples.items())},
        "per_case": per_case,
    }


def run_evaluation(*, iterations: int, warmups: int, output_dir: Path | str) -> tuple[dict[str, Any], dict[str, str]]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if warmups < 0:
        raise ValueError("warmups must not be negative")
    corpus = get_evaluation_corpus()
    normal_path = get_evidence_path()
    normal_before = _file_state(normal_path)

    with tempfile.TemporaryDirectory(prefix="scopesentry-evaluation-") as temp_dir:
        evidence = EvidenceService(Path(temp_dir) / "evaluation-evidence.jsonl")
        results: list[dict[str, Any]] = []
        for case in corpus.cases:
            result = evaluate_case(case)
            results.append(result)
            evidence.create_record(
                analysis_type="composition" if len(case.grants) > 1 or case.composition_links else "single_grant",
                request=case.model_dump(mode="json"),
                result={
                    "baseline": result["baseline"],
                    "scope_sentry": result["scope_sentry"],
                    "matches_ground_truth": result["scope_sentry_matches_ground_truth"],
                },
                decision_summary=f"Evaluation case {case.case_id}: {result['scope_sentry']['operational_outcome']}.",
            )
        verification = evidence.verify()
        evidence_summary = {
            "valid": verification.valid,
            "records_checked": verification.records_checked,
            "head_hash": verification.head_hash,
            "normal_evidence_initial_state": "present" if normal_before["exists"] else "absent",
        }

        baseline_metrics = confusion_matrix(results, "baseline")
        scope_metrics = confusion_matrix(results, "scope_sentry")
        least_privilege = exposure_metrics(results)
        performance = _performance(corpus.cases, iterations, warmups)
        for result in results:
            result["timing"] = performance["per_case"][result["case_id"]]

    normal_after = _file_state(normal_path)
    normal_unchanged = normal_before == normal_after
    evidence_summary["normal_evidence_unchanged"] = normal_unchanged
    evidence_summary["normal_evidence_final_state"] = "present" if normal_after["exists"] else "absent"
    categories = Counter(case.category.value for case in corpus.cases)
    safe_count = sum(case.ground_truth.classification == "safe" for case in corpus.cases)
    report = {
        "schema_version": "1.0.0",
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "operating_system": platform.platform(),
            "corpus_hash": corpus_hash(corpus),
            "provider": "local mock google-compatible catalogue",
            "network_access_required": False,
        },
        "reproduction_command": REPRODUCTION_COMMAND,
        "corpus_summary": {
            "total_cases": len(corpus.cases),
            "safe_cases": safe_count,
            "unsafe_cases": len(corpus.cases) - safe_count,
            "categories": dict(sorted(categories.items())),
            "bias_notice": "The hand-authored corpus is intentionally threat-heavy and is not statistically representative of every OAuth deployment.",
        },
        "metric_definitions": {
            "positive": "unsafe case",
            "true_positive": "unsafe authority effectively contained",
            "false_negative": "unsafe authority incorrectly permitted",
            "true_negative": "safe action correctly permitted",
            "false_positive": "safe action incorrectly prevented",
            "exposure_reduction_ratio": "removed scopes divided by originally granted unique scopes; not applicable when the denominator is zero",
        },
        "aggregate_metrics": {
            "baseline": baseline_metrics,
            "scope_sentry": scope_metrics,
            "least_privilege": least_privilege,
        },
        "performance": performance,
        "evidence": evidence_summary,
        "cases": results,
        "limitations": [
            "The deterministic corpus is hand-authored and limited to one local mock provider catalogue.",
            "Scope counts are an authority-exposure indicator, not a complete security measure.",
            "Local PoC timings exclude persistence and network I/O and are not production guarantees.",
            "The static baseline intentionally lacks runtime, synthesis, composition-path, and evidence functionality, so timing is not functionally equivalent.",
            "This evaluation is technical evidence, not a formal security proof or legal proof of patentability.",
        ],
    }
    paths = write_reports(report, output_dir)
    if not verification.valid:
        raise RuntimeError("temporary evaluation evidence chain verification failed")
    if not normal_unchanged:
        raise RuntimeError("normal evidence file changed during evaluation")
    return report, paths


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/evaluation"))
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    if args.warmups < 0:
        parser.error("--warmups must not be negative")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report, paths = run_evaluation(iterations=args.iterations, warmups=args.warmups, output_dir=args.output_dir)
        mismatches = [item["case_id"] for item in report["cases"] if not item["scope_sentry_matches_ground_truth"]]
        print(f"Evaluated {report['corpus_summary']['total_cases']} deterministic local cases.")
        print(f"Baseline: {json.dumps(report['aggregate_metrics']['baseline']['counts'], sort_keys=True)}")
        print(f"ScopeSentry-R: {json.dumps(report['aggregate_metrics']['scope_sentry']['counts'], sort_keys=True)}")
        print(f"Evidence: valid={report['evidence']['valid']}, records={report['evidence']['records_checked']}, normal_unchanged={report['evidence']['normal_evidence_unchanged']}")
        print(f"Reports: {json.dumps(paths, sort_keys=True)}")
        if mismatches:
            print(f"ScopeSentry-R ground-truth mismatches: {mismatches}", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
