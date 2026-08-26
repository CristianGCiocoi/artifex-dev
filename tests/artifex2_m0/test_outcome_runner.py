from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from tools.artifex2.outcome_runner import ScenarioError, run_scenario


def _write(path: Path, value: object) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8", newline="\n")


def test_public_process_runner_verifies_json_without_shell(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    _write(
        scenario,
        {
            "id": "synthetic-public-process",
            "composition": "PUBLIC_PROCESS",
            "command": [sys.executable, "-c", 'print("{\\"ok\\":true}")'],
            "cwd": ".",
            "timeout_seconds": 5,
            "expect": {"exit_code": 0, "stdout_json": {"ok": True}},
        },
    )

    result = run_scenario(scenario, tmp_path)

    assert result["status"] == "PASS"
    assert result["returncode"] == 0
    assert result["timed_out"] is False
    assert result["scrubbed"] is True
    assert result["command_sha256"]


def test_runner_times_out_bounded_process(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    _write(
        scenario,
        {
            "id": "synthetic-timeout",
            "composition": "PACKAGED_PROCESS",
            "command": [sys.executable, "-c", "import time; time.sleep(5)"],
            "timeout_seconds": 1,
            "expect": {"exit_code": 0},
        },
    )

    result = run_scenario(scenario, tmp_path)

    assert result["status"] == "FAIL"
    assert result["timed_out"] is True
    assert result["failures"] == ["process timed out"]


def test_runner_rejects_explicit_secret_environment(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    _write(
        scenario,
        {
            "id": "unsafe-environment",
            "composition": "PUBLIC_PROCESS",
            "command": [sys.executable, "-c", "print('ok')"],
            "environment": {"API_TOKEN": "should-never-be-written"},
        },
    )

    with pytest.raises(ScenarioError, match="sensitive environment key"):
        run_scenario(scenario, tmp_path)


def test_runner_rejects_cwd_escape(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    _write(
        scenario,
        {
            "id": "unsafe-cwd",
            "composition": "PUBLIC_PROCESS",
            "command": [sys.executable, "-c", "print('ok')"],
            "cwd": "..",
        },
    )

    with pytest.raises(ScenarioError, match="escapes repository root"):
        run_scenario(scenario, tmp_path)
