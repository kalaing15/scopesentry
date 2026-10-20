"""Read-only local preflight checks for the ScopeSentry-R live demonstration.

This module deliberately does not import or call the demo runner. It does not
append evidence, create contracts, start a server, or contact a network peer.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
EXPECTED_INTERPRETER = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
REQUIRED_MODULES = ("fastapi", "uvicorn", "pydantic", "networkx")
REQUIRED_ROUTES = (
    "/",
    "/health",
    "/docs",
    "/demo",
    "/api/v1/demo/providers",
    "/api/v1/demo/scenarios",
    "/api/v1/demo/scenarios/{scenario_id}",
    "/api/v1/demo/scenarios/{scenario_id}/run",
    "/api/v1/evidence/verify",
)
REQUIRED_DASHBOARD_ASSETS = (
    "app/static/dashboard/index.html",
    "app/static/dashboard/styles.css",
    "app/static/dashboard/dashboard.js",
)
CURATED_SCENARIO_IDS = (
    "safe-file-reader",
    "overprivileged-file-reader",
    "runtime-scope-drift",
    "missing-required-permission",
    "composed-exfiltration-path",
    "unauthorized-cross-provider-exfiltration",
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _capture(name: str, operation: Callable[[], str]) -> CheckResult:
    try:
        return CheckResult(name=name, passed=True, detail=operation())
    except Exception as exc:  # A preflight failure must be visible and fail closed.
        return CheckResult(
            name=name,
            passed=False,
            detail=f"{type(exc).__name__}: {exc}",
        )


def check_interpreter(expected: Path = EXPECTED_INTERPRETER) -> str:
    observed = Path(sys.executable).resolve()
    target = expected.resolve()
    if observed != target:
        raise RuntimeError(f"expected {target}, observed {observed}")
    return f"Using the project virtual environment: {observed}"


def check_required_modules() -> str:
    missing = [name for name in REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    if missing:
        raise RuntimeError("missing local modules: " + ", ".join(missing))
    return "Required local modules are importable: " + ", ".join(REQUIRED_MODULES)


def check_application() -> str:
    from app.main import app

    paths = {route.path for route in app.routes}
    missing = [path for path in REQUIRED_ROUTES if path not in paths]
    if missing:
        raise RuntimeError("missing application routes: " + ", ".join(missing))
    schema = app.openapi()
    if schema.get("info", {}).get("title") != "ScopeSentry-R API":
        raise RuntimeError("unexpected OpenAPI application title")
    return f"Application imports and exposes {len(paths)} routes, including demo and evidence APIs."


def check_dashboard_assets(root: Path = PROJECT_ROOT) -> str:
    missing = [name for name in REQUIRED_DASHBOARD_ASSETS if not (root / name).is_file()]
    if missing:
        raise RuntimeError("missing dashboard assets: " + ", ".join(missing))
    return "Dashboard HTML, CSS, and JavaScript assets are present."


def check_registries() -> str:
    from app.providers.registry import get_provider_registry
    from app.providers.scenario_registry import list_scenarios
    from app.release.manifest import EXPECTED_ADAPTERS, EXPECTED_PROVIDERS, EXPECTED_SCENARIOS

    metadata = get_provider_registry().list_metadata()
    canonical = tuple(sorted(item.authority_provider_id for item in metadata))
    adapters = tuple(
        sorted((item.provider_name, item.authority_provider_id) for item in metadata)
    )
    if canonical != EXPECTED_PROVIDERS:
        raise RuntimeError(f"provider identities differ: {canonical}")
    if adapters != EXPECTED_ADAPTERS:
        raise RuntimeError(f"adapter mapping differs: {adapters}")
    if not all(item.simulation_only for item in metadata):
        raise RuntimeError("a registered provider is not marked simulation-only")

    observed = tuple(item.scenario_id for item in list_scenarios())
    if observed != EXPECTED_SCENARIOS:
        raise RuntimeError("scenario registry differs from the release profile")
    missing_curated = [item for item in CURATED_SCENARIO_IDS if item not in observed]
    if missing_curated:
        raise RuntimeError("curated scenarios missing: " + ", ".join(missing_curated))
    return (
        f"Registered {len(metadata)} deterministic local providers and "
        f"{len(observed)} scenarios; all {len(CURATED_SCENARIO_IDS)} curated IDs resolve."
    )


def check_evidence(root: Path = PROJECT_ROOT) -> str:
    from app.evidence.hash_chain import EvidenceHashChain

    path = root / "runtime" / "evidence.jsonl"
    before = _sha256(path)
    result = EvidenceHashChain(path).verify()
    after = _sha256(path)
    if before != after:
        raise RuntimeError("normal evidence bytes changed during read-only verification")
    if not result.valid or result.first_invalid_sequence is not None:
        raise RuntimeError(result.message)
    return f"Evidence chain is valid; {result.records_checked} records checked without writing."


def check_release_profile(root: Path = PROJECT_ROOT) -> str:
    from app.release.manifest import (
        EXPECTED_REPORT_HASHES,
        EXPECTED_V1_HASH,
        EXPECTED_V2_HASH,
        READY,
        canonical_report_sha256,
        head_git_blob_sha256,
    )
    from app.evaluation.corpus import corpus_hash, get_evaluation_corpus
    from app.evaluation.corpus_v2 import corpus_v2_hash, get_evaluation_corpus_v2

    failures: list[str] = []
    for relative, expected in EXPECTED_REPORT_HASHES:
        path = root / relative
        if not path.is_file():
            failures.append(f"missing {relative}")
            continue
        if canonical_report_sha256(path) != expected:
            failures.append(f"working-tree hash mismatch: {relative}")
        if head_git_blob_sha256(root, relative) != expected:
            failures.append(f"HEAD blob hash mismatch: {relative}")

    if corpus_hash(get_evaluation_corpus()) != EXPECTED_V1_HASH:
        failures.append("V1 corpus hash mismatch")
    if corpus_v2_hash(get_evaluation_corpus_v2()) != EXPECTED_V2_HASH:
        failures.append("V2 corpus hash mismatch")
    if failures:
        raise RuntimeError("; ".join(failures))
    return f"Release status is {READY}; frozen reports and V1/V2 corpus hashes match."


def check_port_available(host: str, port: int) -> str:
    if port < 0 or port > 65535:
        raise ValueError("port must be between 0 and 65535")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise RuntimeError(f"{host}:{port} is unavailable: {exc}") from exc
    display_port = str(port) if port else "an ephemeral test port"
    return f"{host}:{display_port} is available for local binding."


def _contract_snapshot() -> list[dict[str, object]]:
    from app.gateway.repository import get_contract_repository

    return [
        item.model_dump(mode="json")
        for item in get_contract_repository().list(limit=100)
    ]


def run_preflight(host: str = "127.0.0.1", port: int = 8000) -> dict[str, object]:
    evidence_path = PROJECT_ROOT / "runtime" / "evidence.jsonl"
    evidence_before = _sha256(evidence_path)
    contracts_before = _contract_snapshot()

    checks = [
        _capture("python_interpreter", check_interpreter),
        _capture("required_modules", check_required_modules),
        _capture("application_import", check_application),
        _capture("dashboard_assets", check_dashboard_assets),
        _capture("provider_and_scenario_registry", check_registries),
        _capture("evidence_chain", check_evidence),
        _capture("release_profile", check_release_profile),
        _capture("port_availability", lambda: check_port_available(host, port)),
    ]

    contracts_after = _contract_snapshot()
    evidence_after = _sha256(evidence_path)
    preservation = CheckResult(
        name="state_preservation",
        passed=(contracts_before == contracts_after and evidence_before == evidence_after),
        detail=(
            "Contract repository and normal evidence are unchanged."
            if contracts_before == contracts_after and evidence_before == evidence_after
            else "Contract repository or normal evidence changed during preflight."
        ),
    )
    checks.append(preservation)
    passed = all(item.passed for item in checks)
    return {
        "passed": passed,
        "release_status": "ready_for_local_ipr_demo" if passed else "verification_failed",
        "host": host,
        "port": port,
        "curated_scenarios": list(CURATED_SCENARIO_IDS),
        "checks": [item.as_dict() for item in checks],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only ScopeSentry-R demo preflight")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_preflight(host=args.host, port=args.port)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("ScopeSentry-R live-demo preflight")
        for check in result["checks"]:
            marker = "PASS" if check["passed"] else "FAIL"
            print(f"[{marker}] {check['name']}: {check['detail']}")
        print(f"Release status: {result['release_status']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
