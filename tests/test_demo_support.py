"""Focused tests for the read-only live-demo support package."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from app.gateway.repository import get_contract_repository
from app.providers.scenario_registry import list_scenarios
from app.release.manifest import REPORT_FILES


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_PATH = ROOT / "tools" / "demo" / "preflight.py"
LAUNCHER_PATH = ROOT / "tools" / "demo" / "start_demo.ps1"


def _load_preflight():
    spec = importlib.util.spec_from_file_location("scope_sentry_demo_preflight", PREFLIGHT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_curated_scenario_ids_resolve_in_live_registry() -> None:
    preflight = _load_preflight()
    observed = {item.scenario_id for item in list_scenarios()}
    assert preflight.CURATED_SCENARIO_IDS == (
        "safe-file-reader",
        "overprivileged-file-reader",
        "runtime-scope-drift",
        "missing-required-permission",
        "composed-exfiltration-path",
        "unauthorized-cross-provider-exfiltration",
    )
    assert set(preflight.CURATED_SCENARIO_IDS) <= observed


def test_preflight_rejects_wrong_interpreter_path(tmp_path: Path) -> None:
    preflight = _load_preflight()
    with pytest.raises(RuntimeError, match="expected"):
        preflight.check_interpreter(tmp_path / "not-the-project-python.exe")


def test_preflight_detects_unavailable_port() -> None:
    preflight = _load_preflight()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen(1)
        with pytest.raises(RuntimeError, match="unavailable"):
            preflight.check_port_available("127.0.0.1", port)


def test_preflight_cli_passes_without_mutating_protected_state() -> None:
    evidence = ROOT / "runtime" / "evidence.jsonl"
    protected = [evidence, *(ROOT / item for item in REPORT_FILES)]
    before = {str(path): _sha256(path) for path in protected}
    contracts_before = [
        item.model_dump(mode="json")
        for item in get_contract_repository().list(limit=100)
    ]

    result = subprocess.run(
        [
            str(ROOT / ".venv" / "Scripts" / "python.exe"),
            str(PREFLIGHT_PATH),
            "--port",
            "0",
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["release_status"] == "ready_for_local_ipr_demo"
    assert all(item["passed"] for item in payload["checks"])
    assert before == {str(path): _sha256(path) for path in protected}
    assert contracts_before == [
        item.model_dump(mode="json")
        for item in get_contract_repository().list(limit=100)
    ]


def test_preflight_source_cannot_execute_scenarios_or_write_evidence() -> None:
    source = PREFLIGHT_PATH.read_text(encoding="utf-8")
    forbidden = (
        "app.orchestrator.demo_runner",
        "DemoRunner",
        ".create_record(",
        "EvidenceHashChain.append",
        "requests.",
        "httpx.",
    )
    for token in forbidden:
        assert token not in source


def test_launcher_uses_project_python_and_runs_preflight_before_uvicorn() -> None:
    source = LAUNCHER_PATH.read_text(encoding="utf-8")
    assert "$ProjectRoot = 'C:\\scopesentry'" in source
    assert ".venv\\Scripts\\python.exe" in source
    assert "http://${HostAddress}:${Port}/demo" in source
    assert "http://${HostAddress}:${Port}/docs" in source
    assert source.index("tools\\demo\\preflight.py") < source.index("-m uvicorn")
    lowered = source.lower()
    for forbidden in ("pip install", "npm install", "winget", "choco", "stop-process", "taskkill"):
        assert forbidden not in lowered


def test_launcher_has_valid_powershell_syntax() -> None:
    command = (
        "$errors=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{LAUNCHER_PATH}', "
        "[ref]$null, [ref]$errors) | Out-Null; "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
    )
    result = subprocess.run(
        [
            str(
                Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            ),
            "-NoProfile",
            "-Command",
            command,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_demo_documents_use_only_live_curated_ids() -> None:
    preflight = _load_preflight()
    live = (ROOT / "docs" / "demo" / "Live-Demo-Script.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "demo" / "Demo-Checklist.md").read_text(encoding="utf-8")
    for scenario_id in preflight.CURATED_SCENARIO_IDS:
        assert scenario_id in live
        assert scenario_id in checklist
    assert "real OAuth" not in live or "no OAuth credentials" in live


def test_demo_support_files_are_present() -> None:
    expected = (
        "tools/demo/start_demo.ps1",
        "tools/demo/preflight.py",
        "docs/demo/Live-Demo-Script.md",
        "docs/demo/Demo-Checklist.md",
        "docs/demo/Troubleshooting.md",
    )
    assert all((ROOT / item).is_file() for item in expected)
