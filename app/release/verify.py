"""Read-only ScopeSentry-R release verifier and manifest CLI."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.release.manifest import (
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
    sha256_file,
    snapshot_files,
    validate_traceability,
)


def _check(name: str, passed: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "required": required, "passed": bool(passed), "detail": detail}


def _git_metadata(root: Path) -> dict[str, Any]:
    def run(*args: str) -> str | None:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    status = run("status", "--porcelain", "--untracked-files=all")
    return {
        "available": status is not None,
        "commit": run("rev-parse", "HEAD") or "unavailable",
        "branch": run("branch", "--show-current") or "unavailable",
        "dirty": bool(status) if status is not None else None,
    }


def _requirements_inventory(root: Path) -> list[dict[str, str | None]]:
    path = root / "requirements.txt"
    if not path.is_file():
        return []
    inventory: list[dict[str, str | None]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        declared = raw.strip()
        if not declared or declared.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)", declared)
        package = match.group(1) if match else declared
        try:
            version = importlib.metadata.version(package)
            status = "resolved_locally"
        except importlib.metadata.PackageNotFoundError:
            version = None
            status = "not_installed"
        inventory.append({"declared_requirement": declared, "installed_version": version, "resolution_status": status})
    return sorted(inventory, key=lambda item: str(item["declared_requirement"]).lower())


def _report_summary(root: Path, profile: ReleaseProfile, hashes: dict[str, str | None]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    reports: dict[str, Any] = {}
    for version, filename in (
        ("v1", "reports/evaluation/scope_sentry_evaluation.json"),
        ("v2", "reports/evaluation/scope_sentry_evaluation_v2.json"),
    ):
        path = root / filename
        if not path.is_file():
            errors.append(f"Missing {version.upper()} JSON report")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            summary = data["corpus_summary"]
            reports[version] = {
                "path": filename,
                "sha256": hashes[filename],
                "schema_version": data["schema_version"],
                "corpus_size": summary.get("total_cases", summary.get("case_count")),
                "corpus_hash": data["metadata"]["corpus_hash"],
                "confusion_matrices": {
                    "static_baseline": data["aggregate_metrics"]["baseline"]["counts"],
                    "scope_sentry": data["aggregate_metrics"]["scope_sentry"]["counts"],
                },
                "containment_metrics": {
                    "baseline": data["aggregate_metrics"]["baseline"]["unsafe_case_prevention_rate"],
                    "scope_sentry": data["aggregate_metrics"]["scope_sentry"]["unsafe_case_prevention_rate"],
                },
                "timing_metadata": {
                    "evaluation_timestamp": data["metadata"].get("evaluation_timestamp"),
                    "python_version": data["metadata"].get("python_version"),
                    "operating_system": data["metadata"].get("operating_system"),
                    "unit": data.get("performance", {}).get("unit"),
                    "warmups_per_applicable_case": data.get("performance", {}).get("warmups_per_applicable_case"),
                    "measured_iterations_per_applicable_case": data.get("performance", {}).get("measured_iterations_per_applicable_case"),
                    "evidence_io": data.get("performance", {}).get("excluded_operations", []),
                },
            }
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"Malformed {version.upper()} report: {type(exc).__name__}")
    return reports, errors


def _safe_app_inspection(root: Path) -> tuple[list[str], dict[str, Any]]:
    """Check main statically before importing it solely to construct OpenAPI."""
    import ast

    main_path = root / "app/main.py"
    tree = ast.parse(main_path.read_text(encoding="utf-8"), filename="app/main.py")
    prohibited = {"create_record", "create_contract", "run_evaluation", "run", "append"}
    module_calls = []
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            called = node.value.func
            name = called.attr if isinstance(called, ast.Attribute) else called.id if isinstance(called, ast.Name) else ""
            if name in prohibited:
                module_calls.append(name)
    if module_calls:
        return module_calls, {}
    from app.main import app
    schema = app.openapi()
    return [], {
        "title": schema.get("info", {}).get("title"),
        "route_count": len(schema.get("paths", {})),
        "root_route_present": "/" in schema.get("paths", {}),
        "dashboard_asset_present": (root / "app/static/dashboard/index.html").is_file(),
    }


def _contract_snapshot() -> list[dict[str, Any]]:
    from app.gateway.repository import get_contract_repository
    return [item.model_dump(mode="json") for item in get_contract_repository().list(limit=100)]


def verify_release(
    *,
    root: Path,
    output_dir: Path,
    profile: ReleaseProfile | None = None,
    evidence_path: Path | None = None,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Verify existing artifacts and write only two verifier-owned manifests."""
    profile = profile or ReleaseProfile()
    root = root.resolve()
    git_before = _git_metadata(root)  # Captured before generated output exists.
    report_hashes_before = snapshot_files(root, profile.report_files)
    normal_evidence = evidence_path or Path(os.getenv("SCOPESENTRY_EVIDENCE_PATH", "runtime/evidence.jsonl"))
    if not normal_evidence.is_absolute():
        normal_evidence = root / normal_evidence
    evidence_hash_before = sha256_file(normal_evidence) if normal_evidence.is_file() else None
    contracts_before = _contract_snapshot()

    checks: list[dict[str, Any]] = []
    warnings = ["Ground truth status: author-defined; independent review pending.", "Captured local timing is platform-specific and is not a production benchmark."]
    if git_before["dirty"]:
        warnings.append("Git working tree was dirty before release outputs were generated; rerun after committing Phase 6 for the final IPR manifest.")
    elif git_before["available"] is False:
        warnings.append("Git metadata was unavailable.")

    missing_reports = [name for name, digest in report_hashes_before.items() if digest is None]
    checks.append(_check("evaluation_report_presence", not missing_reports, "All six frozen evaluation reports are present." if not missing_reports else "Missing: " + ", ".join(missing_reports)))
    report_data, report_errors = _report_summary(root, profile, report_hashes_before)
    checks.append(_check("evaluation_report_schema", not report_errors, "Existing report metadata and metrics were parsed without rerunning evaluation." if not report_errors else "; ".join(report_errors)))

    # Preserve the production/evaluation static-import boundary. These two
    # explicitly named immutable definition modules are loaded read-only; the
    # evaluation runners are never imported or called.
    evaluation_namespace = ".".join(("app", "evaluation"))
    corpus_module = importlib.import_module(f"{evaluation_namespace}.corpus")
    corpus_v2_module = importlib.import_module(f"{evaluation_namespace}.corpus_v2")
    v1 = corpus_module.get_evaluation_corpus()
    v2 = corpus_v2_module.get_evaluation_corpus_v2()
    v1_hash = corpus_module.corpus_hash(v1)
    v2_hash = corpus_v2_module.corpus_v2_hash(v2)
    v1_size = len(v1.cases)
    v2_size = len(v2.legacy_cases) + len(v2.provider_cases)
    corpus_ok = v1_hash == profile.expected_v1_hash and v2_hash == profile.expected_v2_hash
    checks.append(_check("fresh_corpus_hashes", corpus_ok, f"V1={v1_hash}; V2={v2_hash}"))
    report_corpus_ok = bool(report_data) and all(report_data.get(key, {}).get("corpus_hash") == value for key, value in (("v1", v1_hash), ("v2", v2_hash)))
    checks.append(_check("report_corpus_hashes", report_corpus_ok, "Fresh corpus hashes match report metadata." if report_corpus_ok else "Fresh corpus hashes do not match report metadata."))

    from app.providers.registry import get_provider_registry
    metadata = get_provider_registry().list_metadata()
    provider_inventory = sorted(({"adapter_id": item.provider_name, "canonical_id": item.authority_provider_id, "aliases": sorted(item.aliases), "simulation_only": item.simulation_only} for item in metadata), key=lambda item: item["adapter_id"])
    canonical = tuple(sorted(item["canonical_id"] for item in provider_inventory))
    adapters = tuple((item["adapter_id"], item["canonical_id"]) for item in provider_inventory)
    providers_ok = canonical == profile.expected_providers and adapters == profile.expected_adapters and all(item["simulation_only"] for item in provider_inventory)
    checks.append(_check("provider_registry_integrity", providers_ok, "Exactly three synthetic canonical authorities and the explicit mock-google to google mapping are registered." if providers_ok else "Provider inventory or adapter mapping differs from the release profile."))

    from app.providers.scenario_registry import list_scenarios
    scenario_inventory = [item.scenario_id for item in list_scenarios()]
    scenarios_ok = tuple(scenario_inventory) == profile.expected_scenarios
    checks.append(_check("scenario_registry_integrity", scenarios_ok, f"Observed {len(scenario_inventory)} deterministic scenario definitions; none were executed."))

    from app.evidence.hash_chain import EvidenceHashChain
    evidence_result = EvidenceHashChain(normal_evidence).verify()
    evidence_ok = evidence_result.valid and evidence_result.records_checked >= 0 and evidence_result.first_invalid_sequence is None
    checks.append(_check("evidence_chain", evidence_ok, f"Read-only verification observed {evidence_result.records_checked} records."))

    missing_docs = [name for name in profile.document_files if not (root / name).is_file()]
    checks.append(_check("required_documentation", not missing_docs, "All required disclosure and reproducibility documents are present." if not missing_docs else "Missing: " + ", ".join(missing_docs)))
    trace_errors: list[str] = []
    trace_path = root / "docs/ipr/traceability.json"
    if trace_path.is_file():
        try:
            trace_entries = load_traceability(trace_path)
            trace_errors.extend(validate_traceability(root, trace_path))
            matrix = root / "docs/ipr/Novelty-Traceability-Matrix.md"
            if not matrix.is_file() or matrix.read_text(encoding="utf-8") != render_traceability_markdown(trace_entries):
                trace_errors.append("Markdown matrix does not match structured traceability")
        except (ValueError, json.JSONDecodeError, SyntaxError) as exc:
            trace_errors.append(str(exc))
    else:
        trace_errors.append("Structured traceability is missing")
    checks.append(_check("traceability_integrity", not trace_errors, "Structured traceability paths, Python symbols, tests, scenarios, and Markdown projection resolve." if not trace_errors else "; ".join(trace_errors)))

    secret_findings = scan_secrets(root)
    high_secrets = [item for item in secret_findings if item["severity"] == "high"]
    checks.append(_check("committed_secret_scan", not high_secrets, "No high-confidence committed credential was detected by the narrow local scan." if not high_secrets else f"{len(high_secrets)} high-confidence finding(s); values suppressed."))
    network_findings = scan_external_clients(root)
    production_network = [item for item in network_findings if item["classification"] == "production_external_client_capability"]
    checks.append(_check("production_external_client_scan", not production_network, "No executable production external HTTP/OAuth client was detected; local TestClient and same-origin dashboard access are excluded." if not production_network else f"{len(production_network)} production network-capability finding(s)."))

    unsafe_main_calls, application_summary = _safe_app_inspection(root)
    app_ok = not unsafe_main_calls and application_summary.get("root_route_present") and application_summary.get("dashboard_asset_present")
    checks.append(_check("application_construction", bool(app_ok), "OpenAPI and dashboard assets were inspected without starting a server." if app_ok else "Application construction safety or required routes/assets failed."))

    dependencies = _requirements_inventory(root)
    unresolved = [item for item in dependencies if item["resolution_status"] != "resolved_locally"]
    if unresolved:
        warnings.append("Some declared dependency versions were unavailable locally; this inventory is not a vulnerability audit.")
    checks.append(_check("dependency_inventory", bool(dependencies), "Declared requirements were inventoried from local metadata only.", required=False))

    reports = {
        name: {"sha256": digest, "preserved": None}
        for name, digest in report_hashes_before.items()
    }
    timestamp = (now or (lambda: datetime.now(timezone.utc)))().astimezone(timezone.utc).isoformat()
    required_failed = any(item["required"] and not item["passed"] for item in checks)
    missing_core = bool(missing_docs or missing_reports)
    status = INCOMPLETE if missing_core else FAILED if required_failed else READY
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "project_name": "ScopeSentry-R",
        "release_status": status,
        "generated_at_utc": timestamp,
        "ground_truth_status": GROUND_TRUTH_STATUS,
        "source_control": git_before,
        "runtime": {"python_version": platform.python_version(), "platform": platform.platform()},
        "provider_inventory": provider_inventory,
        "scenario_inventory": scenario_inventory,
        "corpora": {"v1": {"size": v1_size, "hash": v1_hash}, "v2": {"size": v2_size, "hash": v2_hash}},
        "evaluation_reports": {"files": reports, "extracted": report_data},
        "evidence_verification": evidence_result.model_dump(mode="json"),
        "documentation_inventory": [{"path": name, "present": (root / name).is_file()} for name in sorted(profile.document_files)],
        "dashboard_and_api": application_summary,
        "dependency_inventory_label": "Local dependency inventory — not a vulnerability audit",
        "dependency_inventory": dependencies,
        "source_scans": {"secret_findings": secret_findings, "external_client_findings": network_findings},
        "verification_checks": checks,
        "warnings": sorted(warnings),
        "known_limitations": [
            "Local synthetic providers are not implementations of commercial OAuth providers.",
            "Contracts are process-local and are lost on restart.",
            "Evidence locking is in-process, not a distributed multi-process lock.",
            "The scan is narrow and is not a comprehensive security or vulnerability audit.",
            "No authentication, database persistence, production deployment, formal verification, or independent validation is claimed.",
        ],
        "generated_output_note": "Release manifests are reproducible generated outputs, are excluded from source-tree dirty-state capture, and do not hash themselves.",
    }

    # Read-only preservation checks occur before output generation.
    contracts_after = _contract_snapshot()
    evidence_hash_after = sha256_file(normal_evidence) if normal_evidence.is_file() else None
    report_hashes_after = snapshot_files(root, profile.report_files)
    evidence_preserved = evidence_hash_before == evidence_hash_after
    contracts_preserved = contracts_before == contracts_after
    reports_preserved = report_hashes_before == report_hashes_after
    preservation_checks = [
        _check("normal_evidence_preserved", evidence_preserved, "Normal evidence bytes were unchanged and no evidence-writing service was called."),
        _check("contracts_preserved", contracts_preserved, "Process-local contract repository state was unchanged."),
        _check("evaluation_reports_preserved", reports_preserved, "All six evaluation reports remained byte-for-byte unchanged and no evaluation runner was called."),
    ]
    manifest["verification_checks"].extend(preservation_checks)
    for name, digest in report_hashes_after.items():
        manifest["evaluation_reports"]["files"][name]["preserved"] = digest == report_hashes_before[name]
    if any(not item["passed"] for item in preservation_checks):
        manifest["release_status"] = FAILED

    sanitize_manifest(manifest)
    json_text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    markdown_text = render_manifest_markdown(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "scope_sentry_release_manifest.json"
    markdown_path = output_dir / "scope_sentry_release_manifest.md"
    try:
        atomic_write_text(json_path, json_text)
        atomic_write_text(markdown_path, markdown_text)
    except OSError:
        # A partially replaced final file may exist, but no user directory is removed.
        raise
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify ScopeSentry-R for a local IPR demonstration without executing scenarios or evaluations.")
    parser.add_argument("--output-dir", default="reports/release", help="Directory for generated release manifests only.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    try:
        manifest = verify_release(root=root, output_dir=root / args.output_dir)
    except Exception as exc:
        print(f"Release verification failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"Release status: {manifest['release_status']}")
    print(f"Providers: {len(manifest['provider_inventory'])}; scenarios: {len(manifest['scenario_inventory'])}")
    print(f"Evidence records checked: {manifest['evidence_verification']['records_checked']}")
    print("Ground truth status: author-defined; independent review pending")
    return 0 if manifest["release_status"] == READY else 1


if __name__ == "__main__":
    raise SystemExit(main())
