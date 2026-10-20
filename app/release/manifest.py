"""Release-verification constants, scanners, and deterministic renderers."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


READY = "ready_for_local_ipr_demo"
FAILED = "verification_failed"
INCOMPLETE = "incomplete"
GROUND_TRUTH_STATUS = "author-defined; independent review pending"

EXPECTED_V1_HASH = "00c58b55801496a489bb896504fbc34c0304c605dec2ec75b93843ada3674f5b"
EXPECTED_V2_HASH = "070b0b607dcc1170a9f49250943c09df42f005ee279ed6b7e721ef4a0a15b06d"
EXPECTED_PROVIDERS = ("google", "mock-code-host", "mock-enterprise")
EXPECTED_ADAPTERS = (
    ("mock-code-host", "mock-code-host"),
    ("mock-enterprise", "mock-enterprise"),
    ("mock-google", "google"),
)
EXPECTED_SCENARIOS = (
    "composed-exfiltration-path",
    "enterprise-runtime-drift",
    "excessive-code-webhook-authority",
    "missing-required-permission",
    "overprivileged-enterprise-file-reader",
    "overprivileged-file-reader",
    "runtime-scope-drift",
    "safe-authorized-cross-provider-workflow",
    "safe-code-repository-reader",
    "safe-enterprise-file-reader",
    "safe-file-reader",
    "same-name-capability-collision",
    "unauthorized-cross-provider-exfiltration",
    "wrong-provider-scope-collision",
)
REPORT_FILES = (
    "reports/evaluation/scope_sentry_evaluation.json",
    "reports/evaluation/scope_sentry_evaluation.csv",
    "reports/evaluation/scope_sentry_evaluation.md",
    "reports/evaluation/scope_sentry_evaluation_v2.json",
    "reports/evaluation/scope_sentry_evaluation_v2.csv",
    "reports/evaluation/scope_sentry_evaluation_v2.md",
)
DOCUMENT_FILES = (
    "docs/ipr/ScopeSentry-R-Technical-Disclosure.md",
    "docs/ipr/Architecture-and-Data-Flow.md",
    "docs/ipr/Threat-Model.md",
    "docs/ipr/Novelty-Traceability-Matrix.md",
    "docs/ipr/Experimental-Methodology.md",
    "docs/ipr/Demo-Runbook.md",
    "docs/ipr/Reproducibility-Guide.md",
    "docs/ipr/traceability.json",
    "docs/evaluation-ground-truth-review.md",
)


@dataclass(frozen=True)
class ReleaseProfile:
    expected_v1_hash: str = EXPECTED_V1_HASH
    expected_v2_hash: str = EXPECTED_V2_HASH
    expected_providers: tuple[str, ...] = EXPECTED_PROVIDERS
    expected_adapters: tuple[tuple[str, str], ...] = EXPECTED_ADAPTERS
    expected_scenarios: tuple[str, ...] = EXPECTED_SCENARIOS
    report_files: tuple[str, ...] = REPORT_FILES
    document_files: tuple[str, ...] = DOCUMENT_FILES


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot_files(root: Path, relative_paths: Iterable[str]) -> dict[str, str | None]:
    return {
        name: sha256_file(root / name) if (root / name).is_file() else None
        for name in sorted(relative_paths)
    }


def python_symbols(path: Path) -> set[str]:
    """Return top-level Python symbols without importing the module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }


def load_traceability(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != "1.0.0":
        raise ValueError("Traceability schema_version must be 1.0.0")
    entries = data.get("elements")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Traceability must contain a nonempty elements list")
    required = {
        "element_id", "candidate_technical_element", "implementation_paths",
        "symbols", "schema_paths", "test_paths", "test_names", "scenario_ids",
        "evaluation_references", "technical_effect", "evidence_event_types",
        "known_limitation",
    }
    ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("Every traceability entry must use the closed schema")
        element_id = entry["element_id"]
        if not isinstance(element_id, str) or not element_id.strip():
            raise ValueError("Traceability element IDs must be nonempty strings")
        if element_id in ids:
            raise ValueError(f"Duplicate traceability element ID: {element_id}")
        ids.add(element_id)
        for key in required - {"element_id", "candidate_technical_element", "technical_effect", "known_limitation"}:
            if not isinstance(entry[key], list):
                raise ValueError(f"Traceability field '{key}' must be a list")
        for key in ("candidate_technical_element", "technical_effect", "known_limitation"):
            if not isinstance(entry[key], str) or not entry[key].strip():
                raise ValueError(f"Traceability field '{key}' must be nonempty")
    return entries


def validate_traceability(root: Path, traceability_path: Path) -> list[str]:
    errors: list[str] = []
    for entry in load_traceability(traceability_path):
        for field in ("implementation_paths", "schema_paths", "test_paths"):
            for relative in entry[field]:
                if Path(relative).is_absolute() or not (root / relative).is_file():
                    errors.append(f"{entry['element_id']}: missing path {relative}")
        symbols_by_path = entry["symbols"]
        for reference in symbols_by_path:
            if not isinstance(reference, dict) or set(reference) != {"path", "names"}:
                errors.append(f"{entry['element_id']}: invalid symbol reference")
                continue
            path = root / reference["path"]
            if not path.is_file() or path.suffix != ".py":
                errors.append(f"{entry['element_id']}: missing Python path {reference['path']}")
                continue
            available = python_symbols(path)
            for name in reference["names"]:
                if name not in available:
                    errors.append(f"{entry['element_id']}: missing symbol {name} in {reference['path']}")
        for scenario_id in entry["scenario_ids"]:
            if scenario_id not in EXPECTED_SCENARIOS:
                errors.append(f"{entry['element_id']}: unknown scenario {scenario_id}")
        for test_path, test_name in zip(entry["test_paths"], entry["test_names"]):
            if (root / test_path).is_file() and test_name not in (root / test_path).read_text(encoding="utf-8"):
                errors.append(f"{entry['element_id']}: missing test {test_name}")
    return sorted(errors)


def render_traceability_markdown(entries: list[dict[str, Any]]) -> str:
    lines = [
        "# Novelty Traceability Matrix",
        "",
        "Generated from and validated against `docs/ipr/traceability.json`. Candidate elements are technical material for IPR/patent-attorney review, not final legal claims or conclusions of novelty or patentability.",
        "",
        "| ID | Candidate technical element | Implementation and symbols | Tests and scenarios | Measured technical effect | Evidence | Known limitation |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in entries:
        impl = "; ".join(item["implementation_paths"])
        symbols = ", ".join(
            f"{ref['path']}: {', '.join(ref['names'])}" for ref in item["symbols"]
        )
        tests = "; ".join(item["test_names"] + item["scenario_ids"] + item["evaluation_references"])
        evidence = ", ".join(item["evidence_event_types"]) or "None"
        cells = [item["element_id"], item["candidate_technical_element"], f"{impl}; {symbols}", tests, item["technical_effect"], evidence, item["known_limitation"]]
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    return "\n".join(lines) + "\n"


_SECRET_RULES = (
    ("private-key", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential-assignment", "high", re.compile(r"(?i)\b(?:access_token|refresh_token|client_secret|api_key|password)\b\s*[:=]\s*['\"](?!\[?REDACTED\]?|placeholder|example|test|mock|dummy|changeme)([^'\"\r\n]{16,})['\"]")),
)


def tracked_files(root: Path) -> list[str]:
    import subprocess
    completed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False
    )
    if completed.returncode != 0:
        return []
    return sorted(item for item in completed.stdout.decode("utf-8").split("\0") if item)


def scan_secrets(root: Path, files: Iterable[str] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    candidates = list(files) if files is not None else tracked_files(root)
    allowed_suffixes = {".py", ".js", ".json", ".toml", ".yaml", ".yml", ".ini", ".env", ".txt"}
    for relative in sorted(candidates):
        path = root / relative
        if not path.is_file() or path.suffix.lower() not in allowed_suffixes:
            continue
        if any(part in {".git", ".venv", "__pycache__", ".pytest_cache", "reports"} for part in Path(relative).parts):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for rule_id, severity, pattern in _SECRET_RULES:
            if rule_id == "credential-assignment" and "tests" in Path(relative).parts:
                # Credential-shaped literals in isolated tests are fixtures,
                # not production credentials; test directories remain scanned
                # for private-key material.
                continue
            if pattern.search(content):
                findings.append({
                    "path": Path(relative).as_posix(), "rule_id": rule_id,
                    "severity": severity,
                    "explanation": "A high-confidence credential-shaped literal may be committed; value suppressed.",
                })
    return findings


_NETWORK_IMPORTS = {"requests", "httpx", "aiohttp", "urllib3", "oauthlib", "google.auth"}
_LOCAL_TEST_CLIENT_IMPORTS = {"fastapi.testclient", "starlette.testclient"}


def scan_external_clients(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for base, classification in ((root / "app", "production_external_client_capability"), (root / "tests", "local_test_only_client_usage")):
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
            matched = sorted(name for name in imports if any(name == item or name.startswith(item + ".") for item in _NETWORK_IMPORTS))
            local_clients = sorted(name for name in imports if name in _LOCAL_TEST_CLIENT_IMPORTS)
            if matched:
                findings.append({
                    "path": path.relative_to(root).as_posix(),
                    "classification": classification,
                    "detail": "Imports local testing or external-client package: " + ", ".join(matched),
                })
            if classification == "local_test_only_client_usage" and local_clients:
                findings.append({
                    "path": path.relative_to(root).as_posix(),
                    "classification": classification,
                    "detail": "Imports in-process local API test client: " + ", ".join(local_clients),
                })
    dashboard = root / "app/static/dashboard/app.js"
    if dashboard.is_file() and re.search(r"fetch\(\s*['\"](?:https?:)?//", dashboard.read_text(encoding="utf-8")):
        findings.append({"path": "app/static/dashboard/app.js", "classification": "production_external_client_capability", "detail": "Dashboard contains an absolute fetch target."})
    return findings


def sanitize_manifest(value: Any, key: str = "") -> None:
    """Reject paths or secret-bearing values before serialization."""
    sensitive_keys = {"access_token", "refresh_token", "authorization", "client_secret", "password", "api_key", "cookie"}
    if isinstance(value, dict):
        for child_key, child in value.items():
            if str(child_key).lower() in sensitive_keys:
                raise ValueError(f"Manifest contains prohibited key: {child_key}")
            sanitize_manifest(child, str(child_key))
    elif isinstance(value, list):
        for child in value:
            sanitize_manifest(child, key)
    elif isinstance(value, str):
        if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("/"):
            raise ValueError(f"Manifest contains an absolute or temporary path in {key}")
        if "-----BEGIN" in value:
            raise ValueError(f"Manifest contains suspected secret material in {key}")
        for environment_name in ("USERPROFILE", "HOME", "TEMP", "TMP"):
            environment_value = os.getenv(environment_name)
            if environment_value and len(environment_value) >= 4 and environment_value.lower() in value.lower():
                raise ValueError(f"Manifest contains an environment path value in {key}")
        username = os.getenv("USERNAME") or os.getenv("USER")
        if username and len(username) >= 4 and re.search(rf"(?i)(?:^|[\\/]){re.escape(username)}(?:$|[\\/])", value):
            raise ValueError(f"Manifest contains a username-bearing path in {key}")


def render_manifest_markdown(manifest: dict[str, Any]) -> str:
    checks = manifest["verification_checks"]
    lines = [
        "# ScopeSentry-R Release Verification Manifest", "",
        f"- Release status: `{manifest['release_status']}`",
        f"- Generated at (UTC): `{manifest['generated_at_utc']}`",
        f"- Ground truth status: {manifest['ground_truth_status']}",
        f"- Git commit: `{manifest['source_control']['commit']}`",
        f"- Git branch: `{manifest['source_control']['branch']}`",
        f"- Git dirty before output: `{str(manifest['source_control']['dirty']).lower()}`", "",
        "## Verification checks", "",
        "| Check | Required | Passed | Detail |", "|---|---:|---:|---|",
    ]
    for check in checks:
        lines.append(f"| {check['name']} | {check['required']} | {check['passed']} | {check['detail']} |")
    lines += ["", "## Core facts", "", f"- Providers: {', '.join(item['canonical_id'] for item in manifest['provider_inventory'])}", f"- Scenarios: {len(manifest['scenario_inventory'])}", f"- V1 corpus: {manifest['corpora']['v1']['size']} cases, `{manifest['corpora']['v1']['hash']}`", f"- V2 corpus: {manifest['corpora']['v2']['size']} cases, `{manifest['corpora']['v2']['hash']}`", f"- Evidence: valid={manifest['evidence_verification']['valid']}, records={manifest['evidence_verification']['records_checked']}, head=`{manifest['evidence_verification']['head_hash']}`", "", "## Frozen evaluation reports", ""]
    for path, details in sorted(manifest["evaluation_reports"]["files"].items()):
        lines.append(f"- `{path}`: `{details['sha256']}`; preserved={details['preserved']}")
    lines += ["", "## Documentation inventory", ""]
    lines.extend(f"- `{item['path']}`: present={item['present']}" for item in manifest["documentation_inventory"])
    lines += ["", "## Source scan summary", "", f"- Secret findings: {len(manifest['source_scans']['secret_findings'])}", f"- Production external-client findings: {sum(item['classification'] == 'production_external_client_capability' for item in manifest['source_scans']['external_client_findings'])}", f"- Local/test-only client findings: {sum(item['classification'] == 'local_test_only_client_usage' for item in manifest['source_scans']['external_client_findings'])}", "", "## Warnings", ""]
    lines.extend(f"- {warning}" for warning in manifest["warnings"])
    lines += ["", "## Local dependency inventory — not a vulnerability audit", ""]
    lines.extend(f"- `{item['declared_requirement']}`: {item['installed_version'] or 'unavailable'} ({item['resolution_status']})" for item in manifest["dependency_inventory"])
    lines += ["", "## Known limitations", ""]
    lines.extend(f"- {item}" for item in manifest["known_limitations"])
    lines += ["", manifest["generated_output_note"], ""]
    return "\n".join(lines)


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
