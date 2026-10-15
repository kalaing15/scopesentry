"""Phase 5 provider-qualified evaluation CLI built on the Phase 4 engine."""

import argparse
import json
import platform
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.evidence.service import EvidenceService, get_evidence_path
from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.corpus_v2 import corpus_v2_hash, get_evaluation_corpus_v2
from app.evaluation.engine import evaluate_case, evaluate_provider_qualified_case
from app.evaluation.metrics import confusion_matrix, exposure_metrics
from app.evaluation.reports import write_reports
from app.evaluation.runner import _file_state, _performance
from app.evaluation.timing import benchmark, summarize_ns


REPRODUCTION_COMMAND = (
    "python -m app.evaluation.runner_v2 --iterations 50 --warmups 5 "
    "--output-dir reports\\evaluation"
)
PHASE4_FILENAMES = (
    "scope_sentry_evaluation.json",
    "scope_sentry_evaluation.csv",
    "scope_sentry_evaluation.md",
)


def _phase4_states(output_dir: Path) -> dict[str, dict[str, Any]]:
    return {name: _file_state(output_dir / name) for name in PHASE4_FILENAMES}


def _provider_performance(cases, iterations: int, warmups: int) -> dict[str, Any]:
    samples: dict[str, list[int]] = {}
    per_case: dict[str, dict[str, Any]] = {}
    baseline = StaticScopeBaseline()
    for case in cases:
        calls = {
            "end_to_end_scope_sentry_provider_qualified": lambda case=case: evaluate_provider_qualified_case(case),
            "static_baseline_provider_qualified": lambda case=case: baseline.evaluate_qualified(
                provider_intents=case.provider_intents,
                grants=case.grants,
            ),
        }
        for stage, callable_ in calls.items():
            summary, measured = benchmark(callable_, iterations=iterations, warmups=warmups)
            samples.setdefault(stage, []).extend(measured)
            per_case.setdefault(case.case_id, {})[stage] = summary
    return {
        "stages": {stage: summarize_ns(values) for stage, values in sorted(samples.items())},
        "per_case": per_case,
    }


def run_evaluation_v2(
    *, iterations: int, warmups: int, output_dir: Path | str
) -> tuple[dict[str, Any], dict[str, str]]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if warmups < 0:
        raise ValueError("warmups must not be negative")

    directory = Path(output_dir)
    phase4_before = _phase4_states(directory)
    normal_before = _file_state(get_evidence_path())
    corpus = get_evaluation_corpus_v2()
    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="scopesentry-evaluation-v2-") as temp_dir:
        evidence = EvidenceService(Path(temp_dir) / "evidence.jsonl")
        for case in corpus.legacy_cases:
            result = evaluate_case(case)
            results.append(result)
            evidence.create_record(
                analysis_type="composition" if len(case.grants) > 1 or case.composition_links else "single_grant",
                request=case.model_dump(mode="json"),
                result={"scope_sentry": result["scope_sentry"], "matches_ground_truth": result["scope_sentry_matches_ground_truth"]},
                decision_summary=f"Phase 5 legacy case {case.case_id}: {result['scope_sentry']['operational_outcome']}.",
            )
        for case in corpus.provider_cases:
            result = evaluate_provider_qualified_case(case)
            results.append(result)
            evidence.create_record(
                analysis_type="composition" if case.observed_links else "single_grant",
                request=case.model_dump(mode="json"),
                result={"scope_sentry": result["scope_sentry"], "matches_ground_truth": result["scope_sentry_matches_ground_truth"]},
                decision_summary=f"Phase 5 provider-qualified case {case.case_id}: {result['scope_sentry']['operational_outcome']}.",
            )
        verification = evidence.verify()

        legacy_performance = _performance(corpus.legacy_cases, iterations, warmups)
        provider_performance = _provider_performance(corpus.provider_cases, iterations, warmups)
        stages = dict(legacy_performance["stages"])
        stages.update(provider_performance["stages"])
        per_case = dict(legacy_performance["per_case"])
        per_case.update(provider_performance["per_case"])
        performance = {
            **{key: value for key, value in legacy_performance.items() if key not in {"stages", "per_case"}},
            "stages": stages,
            "per_case": per_case,
            "provider_qualified_measurement_note": "Provider-qualified cases benchmark shared production analysis, composition, synthesis, and gateway services end to end.",
        }
        for result in results:
            result["timing"] = per_case[result["case_id"]]

    normal_after = _file_state(get_evidence_path())
    phase4_after = _phase4_states(directory)
    categories = Counter(item["category"] for item in results)
    safe_count = sum(item["ground_truth"]["classification"] == "safe" for item in results)
    baseline_metrics = confusion_matrix(results, "baseline")
    scope_metrics = confusion_matrix(results, "scope_sentry")
    least_privilege = exposure_metrics(results)
    report = {
        "schema_version": "2.0.0",
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "operating_system": platform.platform(),
            "corpus_hash": corpus_v2_hash(corpus),
            "providers": ["google", "mock-code-host", "mock-enterprise"],
            "network_access_required": False,
        },
        "reproduction_command": REPRODUCTION_COMMAND,
        "corpus_summary": {
            "total_cases": len(results),
            "safe_cases": safe_count,
            "unsafe_cases": len(results) - safe_count,
            "legacy_cases": len(corpus.legacy_cases),
            "provider_qualified_cases": len(corpus.provider_cases),
            "categories": dict(sorted(categories.items())),
            "bias_notice": "The author-defined deterministic corpus is threat-heavy and awaits independent human review.",
        },
        "metric_definitions": {
            "positive": "unsafe case",
            "true_positive": "unsafe authority effectively contained",
            "false_negative": "unsafe authority incorrectly permitted",
            "true_negative": "safe action correctly permitted",
            "false_positive": "safe action incorrectly prevented",
            "exposure_reduction_ratio": "removed provider-qualified scopes divided by originally granted unique provider-qualified scopes",
        },
        "aggregate_metrics": {
            "baseline": baseline_metrics,
            "scope_sentry": scope_metrics,
            "least_privilege": least_privilege,
        },
        "performance": performance,
        "evidence": {
            "valid": verification.valid,
            "records_checked": verification.records_checked,
            "head_hash": verification.head_hash,
            "normal_evidence_unchanged": normal_before == normal_after,
            "phase4_reports_unchanged": phase4_before == phase4_after,
            "phase4_report_states_before": phase4_before,
            "phase4_report_states_after": phase4_after,
        },
        "cases": results,
        "limitations": [
            "The corpus and ground truth are author-defined until independently reviewed.",
            "All providers are deterministic local simulators; no real provider interoperability is claimed.",
            "Scope counts are one exposure indicator and not a complete security measure.",
            "Local PoC timings exclude evidence and report I/O and are not production guarantees.",
            "This evaluation is technical evidence, not a formal security proof or legal proof of patentability.",
        ],
    }
    paths = write_reports(report, directory, filename_suffix="_v2")
    if not verification.valid:
        raise RuntimeError("temporary V2 evidence chain verification failed")
    if normal_before != normal_after:
        raise RuntimeError("normal evidence file changed during V2 evaluation")
    if phase4_before != phase4_after:
        raise RuntimeError("Phase 4 reports changed during V2 evaluation")
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
        report, paths = run_evaluation_v2(iterations=args.iterations, warmups=args.warmups, output_dir=args.output_dir)
        mismatches = [item["case_id"] for item in report["cases"] if not item["scope_sentry_matches_ground_truth"]]
        print(f"Evaluated {report['corpus_summary']['total_cases']} deterministic V2 cases.")
        print(f"Corpus SHA-256: {report['metadata']['corpus_hash']}")
        print(f"Baseline: {json.dumps(report['aggregate_metrics']['baseline']['counts'], sort_keys=True)}")
        print(f"ScopeSentry-R: {json.dumps(report['aggregate_metrics']['scope_sentry']['counts'], sort_keys=True)}")
        print(f"Evidence: valid={report['evidence']['valid']}, records={report['evidence']['records_checked']}, normal_unchanged={report['evidence']['normal_evidence_unchanged']}")
        print(f"Phase 4 reports unchanged: {report['evidence']['phase4_reports_unchanged']}")
        print(f"Reports: {json.dumps(paths, sort_keys=True)}")
        if mismatches:
            print(f"ScopeSentry-R ground-truth mismatches: {mismatches}", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"V2 evaluation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
