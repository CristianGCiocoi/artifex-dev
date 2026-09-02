"""Control-plane and fail-closed J21 contracts for ARTIFEX 2.0.2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tools.artifex2.validate_j21 import J21EvidenceError, validate_j21

ROOT = Path(__file__).resolve().parents[2]


def _valid_j21(tmp_path: Path) -> Path:
    contract = yaml.safe_load(
        (ROOT / "implementation/JOURNEYS/J21.yaml").read_text(encoding="utf-8")
    )
    evidence = {
        "schema_version": "artifex.j21-qualification/v1",
        "journey": "J21",
        "status": "PASS",
        "candidate": {
            "source_commit": "a" * 40,
            "installer_sha256": "b" * 64,
            "provenance_sha256": "c" * 64,
        },
        "environment": {
            "os": "Windows 11 24H2 x64",
            "clean_vm": True,
            "defender_enabled": True,
        },
        "terminal_remediation_used": False,
        "completed_stages": contract["required_stages"],
        "providers": {
            provider: {
                "approval_shown": True,
                "approval_recorded": True,
                "live_read_only": "PASS",
                "receipt_persisted": True,
            }
            for provider in ("codex", "claude")
        },
        "service_healthy_at_installer_finish": True,
        "platform_dashboard_user_launched": True,
        "project_dashboard_user_launched": True,
        "reboot_persistence_passed": True,
        "uninstall_passed": True,
        "retained_data_reported": True,
    }
    path = tmp_path / "j21.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return path


def test_af_201_matrix_is_complete_and_scope_locked() -> None:
    matrix = yaml.safe_load(
        (ROOT / "implementation/CONFORMANCE/AF-201-DISPOSITION.yaml").read_text(
            encoding="utf-8"
        )
    )
    findings = matrix["findings"]
    assert [finding["id"] for finding in findings] == [
        f"AF-201-{number:03d}" for number in range(1, 19)
    ]
    control = yaml.safe_load(
        (ROOT / "implementation/CONFORMANCE/ARTIFEX-2.0.2-CONTROL.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert control["target_release"] == "2.0.2"
    assert control["scope"]["prohibited"] == ["M6B", "M8B", "M8C", "M10", "M11", "ATLAS"]
    assert control["release_history"]["v2_0_0"]["state"] == "RELEASED_IMMUTABLE"
    assert control["release_history"]["v2_0_1"]["state"] == "RELEASED_IMMUTABLE"


def test_j21_validator_accepts_only_complete_non_cli_evidence(tmp_path: Path) -> None:
    evidence = _valid_j21(tmp_path)
    result = validate_j21(ROOT / "implementation/JOURNEYS/J21.yaml", evidence)
    assert result == {
        "journey": "J21",
        "status": "PASS",
        "source_commit": "a" * 40,
        "stages": 20,
        "providers": ["codex", "claude"],
    }


def test_j21_validator_rejects_terminal_repair(tmp_path: Path) -> None:
    evidence = _valid_j21(tmp_path)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["terminal_remediation_used"] = True
    evidence.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(J21EvidenceError, match="terminal remediation"):
        validate_j21(ROOT / "implementation/JOURNEYS/J21.yaml", evidence)


def test_j21_validator_rejects_missing_provider_approval(tmp_path: Path) -> None:
    evidence = _valid_j21(tmp_path)
    value = json.loads(evidence.read_text(encoding="utf-8"))
    value["providers"]["claude"]["approval_shown"] = False
    evidence.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(J21EvidenceError, match="claude integration"):
        validate_j21(ROOT / "implementation/JOURNEYS/J21.yaml", evidence)
