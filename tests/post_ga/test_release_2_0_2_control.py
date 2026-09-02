"""Control-plane and fail-closed J21 capture contracts for ARTIFEX 2.0.2."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from tools.artifex2.validate_j21 import (
    J21EvidenceError,
    build_j21_evidence,
    stage_contract,
    validate_j21,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "implementation/JOURNEYS/J21.yaml"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    installer = tmp_path / "ARTIFEX-Setup.exe"
    installer.write_bytes(b"shipping installer")
    provenance = tmp_path / "ARTIFEX-Setup.provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema_version": "artifex.windows-installer-provenance/v1",
                "product": "ARTIFEX",
                "product_version": "2.0.2",
                "source_commit": "a" * 40,
                "installer": {
                    "name": installer.name,
                    "sha256": _digest(installer),
                    "bytes": installer.stat().st_size,
                },
            }
        ),
        encoding="utf-8",
    )
    evidence_root = tmp_path / "observations"
    evidence_root.mkdir()
    observations = []
    for sequence, requirement in enumerate(stage_contract(CONTRACT), 1):
        artifact = evidence_root / f"{sequence:02d}.bin"
        artifact.write_bytes(f"proof {requirement['stage']}".encode())
        observations.append(
            {
                "sequence": sequence,
                "stage": requirement["stage"],
                "channel": requirement["channel"],
                "status": "PASS",
                "observed_at": f"2026-09-02T12:00:{sequence:02d}Z",
                "remediation_performed": False,
                "terminal_opened": False,
                "evidence": [
                    {
                        "path": artifact.name,
                        "kind": (
                            "SCREENSHOT"
                            if requirement["channel"] == "USER_UI_ACTION"
                            else "ARTIFEX_RECEIPT_EXPORT"
                        ),
                        "sha256": _digest(artifact),
                        "contains_secret_material": False,
                    }
                ],
            }
        )
    capture = tmp_path / "capture.json"
    receipt_sha = {
        "codex": observations[9]["evidence"][0]["sha256"],
        "claude": observations[13]["evidence"][0]["sha256"],
    }
    capture.write_text(
        json.dumps(
            {
                "schema_version": "artifex.j21-capture/v1",
                "journey": "J21",
                "status": "PASS",
                "candidate": {
                    "source_commit": "a" * 40,
                    "installer_sha256": _digest(installer),
                    "provenance_sha256": _digest(provenance),
                },
                "environment": {
                    "os": "Windows 11 24H2 x64",
                    "clean_vm": True,
                    "defender_enabled": True,
                    "vm_identity": "VM-J21-001",
                    "snapshot_identity": "clean-24h2-defender-on",
                },
                "operator_attestation": {
                    "shipping_artifact_only": True,
                    "secrets_excluded": True,
                    "source_checkout_used": False,
                    "terminal_remediation_used": False,
                    "manual_path_edit_used": False,
                    "manual_vendor_configuration_edit_used": False,
                },
                "observations": observations,
                "providers": {
                    provider: {
                        "client_version": "1.2.3",
                        "approval_shown": True,
                        "approval_recorded": True,
                        "live_read_only": "PASS",
                        "receipt_persisted": True,
                        "receipt_sha256": receipt_sha[provider],
                    }
                    for provider in ("codex", "claude")
                },
                "outcomes": {
                    "service_healthy_at_installer_finish": True,
                    "platform_dashboard_user_launched": True,
                    "project_dashboard_user_launched": True,
                    "reboot_persistence_passed": True,
                    "uninstall_passed": True,
                    "installer_owned_resources_removed": True,
                    "retained_data_reported": True,
                },
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "qualified.json"
    return capture, installer, provenance, evidence_root, evidence


def _seal(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    capture, installer, provenance, root, evidence = _fixture(tmp_path)
    evidence.write_text(
        json.dumps(build_j21_evidence(CONTRACT, capture, installer, provenance, root)),
        encoding="utf-8",
    )
    return capture, installer, provenance, root, evidence


def test_af_201_matrix_is_complete_and_scope_locked() -> None:
    matrix = yaml.safe_load(
        (ROOT / "implementation/CONFORMANCE/AF-201-DISPOSITION.yaml").read_text(encoding="utf-8")
    )
    assert [item["id"] for item in matrix["findings"]] == [
        f"AF-201-{number:03d}" for number in range(1, 19)
    ]
    control = yaml.safe_load(
        (ROOT / "implementation/CONFORMANCE/ARTIFEX-2.0.2-CONTROL.yaml").read_text(encoding="utf-8")
    )
    assert control["target_release"] == "2.0.2"
    assert control["scope"]["prohibited"] == ["M6B", "M8B", "M8C", "M10", "M11", "ATLAS"]
    assert control["release_history"]["v2_0_0"]["state"] == "RELEASED_IMMUTABLE"
    assert control["release_history"]["v2_0_1"]["state"] == "RELEASED_IMMUTABLE"


def test_j21_seals_and_validates_exact_non_cli_evidence(tmp_path: Path) -> None:
    _, installer, provenance, root, evidence = _seal(tmp_path)
    result = validate_j21(CONTRACT, evidence, installer, provenance, root)
    assert result["status"] == "PASS"
    assert result["source_commit"] == "a" * 40
    assert result["installer_sha256"] == _digest(installer)
    assert result["stages"] == 20
    assert result["providers"] == ["codex", "claude"]


def test_j21_rejects_terminal_repair(tmp_path: Path) -> None:
    capture, installer, provenance, root, _ = _fixture(tmp_path)
    value = json.loads(capture.read_text(encoding="utf-8"))
    value["observations"][5]["terminal_opened"] = True
    capture.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(J21EvidenceError, match="terminal remediation"):
        build_j21_evidence(CONTRACT, capture, installer, provenance, root)


def test_j21_rejects_missing_visual_ui_proof(tmp_path: Path) -> None:
    capture, installer, provenance, root, _ = _fixture(tmp_path)
    value = json.loads(capture.read_text(encoding="utf-8"))
    value["observations"][0]["evidence"][0]["kind"] = "INSTALLER_LOG"
    capture.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(J21EvidenceError, match="lacks required captured evidence"):
        build_j21_evidence(CONTRACT, capture, installer, provenance, root)


def test_j21_rejects_tampered_observation(tmp_path: Path) -> None:
    _, installer, provenance, root, evidence = _seal(tmp_path)
    (root / "01.bin").write_bytes(b"tampered")
    with pytest.raises(J21EvidenceError, match="digest does not match"):
        validate_j21(CONTRACT, evidence, installer, provenance, root)


def test_j21_rejects_relabelled_installer_or_provenance(tmp_path: Path) -> None:
    _, installer, provenance, root, evidence = _seal(tmp_path)
    installer.write_bytes(b"different candidate")
    with pytest.raises(J21EvidenceError, match="candidate digests"):
        validate_j21(CONTRACT, evidence, installer, provenance, root)


def test_j21_rejects_receipt_not_bound_to_captured_file(tmp_path: Path) -> None:
    capture, installer, provenance, root, _ = _fixture(tmp_path)
    value = json.loads(capture.read_text(encoding="utf-8"))
    value["providers"]["claude"]["receipt_sha256"] = "d" * 64
    capture.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(J21EvidenceError, match="persistent receipt is not bound"):
        build_j21_evidence(CONTRACT, capture, installer, provenance, root)


def test_user_guidance_is_non_cli_and_contextual() -> None:
    quick = (ROOT / "docs/guides/QUICK_START_WINDOWS.md").read_text(encoding="utf-8")
    providers = (ROOT / "docs/guides/PROVIDER_ONBOARDING.md").read_text(encoding="utf-8")
    assert "Windows Start" in quick and "Approve and apply" in quick
    assert "does not require manual PATH editing" in quick
    assert "Codex Desktop and the Codex CLI are separate" in providers
    assert "installed standalone ARTIFEX MCP bridge" in providers
    assert "python -m artifex.mcp" in providers
