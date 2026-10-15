"""UTF-8, deterministic, atomic JSON/CSV/Markdown report writers."""

import csv
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any


CSV_HEADERS = [
    "case_id",
    "category",
    "ground_truth",
    "expected_operational_outcome",
    "baseline_operational_outcome",
    "baseline_normalized_result",
    "baseline_classification",
    "scope_sentry_operational_outcome",
    "scope_sentry_normalized_result",
    "scope_sentry_classification",
    "unsafe_authority_contained",
    "original_unsafe_authority_executed",
    "original_granted_scopes",
    "required_scopes",
    "matched_scopes",
    "excessive_scopes",
    "missing_scopes",
    "synthesized_scopes",
    "removed_scopes",
    "required_capabilities",
    "available_capabilities",
    "missing_capabilities",
    "gateway_decisions",
    "unauthorized_path_count",
    "unauthorized_paths",
    "remediation",
    "exposure_reduction_ratio",
    "timing",
    "scope_sentry_matches_ground_truth",
]


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)


def _safe_csv_cell(value: Any) -> str:
    if isinstance(value, (list, dict, tuple)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    elif value is None:
        text = "N/A"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _csv_content(report: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_HEADERS, lineterminator="\n")
    writer.writeheader()
    for result in report["cases"]:
        scope = result["scope_sentry"]
        row = {
            "case_id": result["case_id"],
            "category": result["category"],
            "ground_truth": result["ground_truth"]["classification"],
            "expected_operational_outcome": result["ground_truth"]["expected_outcome"],
            "baseline_operational_outcome": result["baseline"]["operational_outcome"],
            "baseline_normalized_result": result["baseline"]["normalized_result"],
            "baseline_classification": result["baseline_classification"],
            "scope_sentry_operational_outcome": scope["operational_outcome"],
            "scope_sentry_normalized_result": scope["normalized_result"],
            "scope_sentry_classification": result["scope_sentry_classification"],
            "unsafe_authority_contained": scope["unsafe_authority_contained"],
            "original_unsafe_authority_executed": scope["original_unsafe_authority_executed"],
            "original_granted_scopes": scope["original_granted_scopes"],
            "required_scopes": scope["required_scopes"],
            "matched_scopes": scope["matched_scopes"],
            "excessive_scopes": scope["excessive_scopes"],
            "missing_scopes": scope["missing_scopes"],
            "synthesized_scopes": scope["synthesized_scopes"],
            "removed_scopes": scope["removed_scopes"],
            "required_capabilities": scope["required_capabilities"],
            "available_capabilities": scope["available_capabilities"],
            "missing_capabilities": scope["missing_capabilities"],
            "gateway_decisions": scope["gateway_decisions"],
            "unauthorized_path_count": scope["unauthorized_path_count"],
            "unauthorized_paths": scope["unauthorized_paths"],
            "remediation": scope["remediation"],
            "exposure_reduction_ratio": scope["exposure_reduction_ratio"],
            "timing": result["timing"],
            "scope_sentry_matches_ground_truth": result["scope_sentry_matches_ground_truth"],
        }
        writer.writerow({key: _safe_csv_cell(row[key]) for key in CSV_HEADERS})
    return stream.getvalue()


def _rate_text(value: dict[str, Any]) -> str:
    percentage = value["percentage"]
    return "Not applicable" if percentage is None else f"{percentage:.2f}% ({value['numerator']}/{value['denominator']})"


def _markdown_content(report: dict[str, Any]) -> str:
    baseline = report["aggregate_metrics"]["baseline"]
    scope_sentry = report["aggregate_metrics"]["scope_sentry"]
    exposure = report["aggregate_metrics"]["least_privilege"]
    lines = [
        "# ScopeSentry-R Reproducible Security Evaluation",
        "",
        "## Executive summary",
        "",
        f"This local, deterministic corpus contains {report['corpus_summary']['total_cases']} cases: "
        f"{report['corpus_summary']['safe_cases']} safe and {report['corpus_summary']['unsafe_cases']} unsafe. "
        "It is intentionally threat-heavy and is not statistically representative of every OAuth deployment.",
        "",
        f"ScopeSentry-R unsafe-case prevention: **{_rate_text(scope_sentry['unsafe_case_prevention_rate'])}**. Static baseline unsafe-case prevention: **{_rate_text(baseline['unsafe_case_prevention_rate'])}**.",
        "",
        "## Methodology",
        "",
        "Immutable declared ground truth is evaluated independently against a provider-aware static scope baseline and the production ScopeSentry-R services. Baseline disagreements are measured results; ScopeSentry-R disagreements fail the evaluation.",
        "",
        "## Corpus composition",
        "",
        f"Corpus SHA-256: `{report['metadata']['corpus_hash']}`",
        "",
        "| Category | Cases |",
        "|---|---:|",
    ]
    lines.extend(f"| {name} | {count} |" for name, count in report["corpus_summary"]["categories"].items())
    lines.extend([
        "",
        "## Metric definitions",
        "",
        "Positive means unsafe. TP: unsafe authority contained; FN: unsafe authority permitted; TN: safe action permitted; FP: safe action prevented. Detection alone is insufficient: successful unsafe handling requires effective containment.",
        "",
        "## Comparison",
        "",
        "| Capability | Static scope baseline | ScopeSentry-R |",
        "|---|---:|---:|",
        "| Required-scope checking | Yes | Yes |",
        "| Excessive-scope detection | No | Yes |",
        "| Least-privilege synthesis | No | Yes |",
        "| Runtime drift detection | No | Yes |",
        "| Capability-level enforcement | No | Yes |",
        "| Cross-grant composition detection | No | Yes |",
        "| Unauthorized-path remediation | No | Yes |",
        "| Tamper-evident evidence | No | Yes |",
        "",
        "| System | TP | TN | FP | FN | False-allow rate | Safe allow rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| Static baseline | {baseline['counts']['true_positive']} | {baseline['counts']['true_negative']} | {baseline['counts']['false_positive']} | {baseline['counts']['false_negative']} | {_rate_text(baseline['false_allow_rate'])} | {_rate_text(baseline['safe_case_allow_rate'])} |",
        f"| ScopeSentry-R | {scope_sentry['counts']['true_positive']} | {scope_sentry['counts']['true_negative']} | {scope_sentry['counts']['false_positive']} | {scope_sentry['counts']['false_negative']} | {_rate_text(scope_sentry['false_allow_rate'])} | {_rate_text(scope_sentry['safe_case_allow_rate'])} |",
        "",
        "## Security findings",
        "",
        "Operational outcomes remain distinct from binary normalization. Remediated cases execute only through synthesized scopes; blocked, quarantined, incomplete, composition-skipped, and manual-review cases do not execute unsafe authority.",
        "",
        "## Least-privilege findings",
        "",
        f"Authority was reduced in {exposure['cases_where_authority_was_reduced']} cases. Mean scope-count exposure reduction was {exposure['mean_exposure_reduction_ratio']:.4f}. Scope count is one measurable exposure indicator, not a complete security guarantee.",
        "",
        "## Performance observations",
        "",
        "Timings use `time.perf_counter_ns()` after warm-up. Evidence I/O, report I/O, HTTP, UUID creation, and temporary cleanup are excluded. These are local PoC observations, not production performance guarantees. The baseline performs materially less security work, so timing is not a functional-equivalence comparison.",
        "",
        "| Stage | Samples | Median (ns) | p95 (ns) | Min | Max |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for stage, timing in report["performance"]["stages"].items():
        lines.append(f"| {stage} | {timing['sample_count']} | {timing['median']} | {timing['p95_nearest_rank']} | {timing['minimum']} | {timing['maximum']} |")
    lines.extend([
        "",
        "## Evidence integrity",
        "",
        f"Temporary evaluation chain valid: **{report['evidence']['valid']}**; isolated records: **{report['evidence']['records_checked']}**. Normal evidence state remained unchanged: **{report['evidence']['normal_evidence_unchanged']}**.",
        "",
        "## Limitations",
        "",
    ])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend([
        "",
        "## Reproduction",
        "",
        "```powershell",
        report["reproduction_command"],
        "```",
        "",
    ])
    return "\n".join(lines)


def write_reports(
    report: dict[str, Any],
    output_dir: Path | str,
    *,
    filename_suffix: str = "",
) -> dict[str, str]:
    """Atomically write reports; the empty suffix preserves Phase 4 filenames."""
    directory = Path(output_dir)
    paths = {
        "json": directory / f"scope_sentry_evaluation{filename_suffix}.json",
        "csv": directory / f"scope_sentry_evaluation{filename_suffix}.csv",
        "markdown": directory / f"scope_sentry_evaluation{filename_suffix}.md",
    }
    _atomic_write(paths["json"], json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _atomic_write(paths["csv"], _csv_content(report))
    _atomic_write(paths["markdown"], _markdown_content(report))
    return {name: str(path) for name, path in paths.items()}
