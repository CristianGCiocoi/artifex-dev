from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.artifex2 import run_m7_shipping_journey as journey_runner
from tools.artifex2.qualify_m7_windows import _installed_origin, _run_json
from tools.artifex2.run_m7_shipping_journey import (
    JourneyFailure,
    ShippingCLI,
    _install_shipping_candidate,
    _require_clean_guest,
    _require_windows_25h2,
    _validate_clean_base_attestation,
    _wait_for_process_exit,
)


def test_journey_failures_are_operator_safe_messages() -> None:
    assert str(JourneyFailure("clean-machine preflight failed")) == (
        "clean-machine preflight failed"
    )


def test_runtime_phase_diagnostics_are_bounded_and_secret_safe() -> None:
    journey_runner._mark_phase("task-scheduler-restart")

    assert journey_runner._ACTIVE_PHASE == "task-scheduler-restart"


def test_shipping_cli_os_failure_reports_only_operation_and_code(tmp_path: Path) -> None:
    def fail(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        raise OSError(5, "sensitive local path marker")

    cli = ShippingCLI(tmp_path / "artifex.exe", cwd=tmp_path, runner=fail)

    with pytest.raises(JourneyFailure, match=r"service\.status.*os_code=5") as caught:
        cli.direct("service.status", ["service", "status"])
    assert "sensitive local path marker" not in str(caught.value)


def test_shipping_candidate_runs_exact_installer_at_standard_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "ARTIFEX-Setup.exe"
    artifact.write_bytes(b"installer")
    program_files = tmp_path / "Program Files"
    local_app_data = tmp_path / "LocalAppData"
    install_root = program_files / "ARTIFEX"
    state_root = local_app_data / "ARTIFEX" / "runtime"
    monkeypatch.setenv("PROGRAMW6432", str(program_files))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    observed: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        install_root.mkdir(parents=True)
        for name in (
            "artifex.exe",
            "artifex-install-manifest.json",
            "service-registration.json",
            "Uninstall.exe",
        ):
            (install_root / name).write_bytes(b"candidate")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    executable = _install_shipping_candidate(
        artifact,
        install_root=install_root.resolve(),
        state_root=state_root.resolve(),
        runner=runner,
    )

    assert executable == install_root.resolve() / "artifex.exe"
    assert observed == [[str(artifact), "/S"]]


def test_shipping_candidate_rejects_nonstandard_install_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "ARTIFEX-Setup.exe"
    artifact.write_bytes(b"installer")
    monkeypatch.setenv("PROGRAMW6432", str(tmp_path / "Program Files"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))

    with pytest.raises(JourneyFailure, match="standard ARTIFEX installation"):
        _install_shipping_candidate(
            artifact,
            install_root=(tmp_path / "custom").resolve(),
            state_root=(tmp_path / "LocalAppData" / "ARTIFEX" / "runtime").resolve(),
            runner=subprocess.run,
        )


def test_clean_guest_fails_closed_for_any_provider_or_prior_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USERNAME", "qualification-user")
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#1")
    paths = [tmp_path / name for name in ("stage", "install", "state", "project")]
    with pytest.raises(JourneyFailure, match="supported provider"):
        _require_clean_guest(
            staging_root=paths[0],
            install_root=paths[1],
            state_root=paths[2],
            project_root=paths[3],
            which=lambda name: "C:/codex.exe" if name == "codex" else None,
        )
    paths[2].mkdir()
    with pytest.raises(JourneyFailure, match="existing state root"):
        _require_clean_guest(
            staging_root=paths[0],
            install_root=paths[1],
            state_root=paths[2],
            project_root=paths[3],
            which=lambda _name: None,
        )


def test_clean_base_attestation_is_exact_and_vm104_bound() -> None:
    value = {
        "schema_version": "1.0",
        "vm_id": 104,
        "snapshot_name": "m7-qualified-25h2-x64-cell-base-v8",
        "snapshot_config_sha256": "a" * 64,
        "account_sid_sha256": "b" * 64,
        "candidate_sha256": "c" * 64,
        "providers_absent": True,
        "source_checkout_absent": True,
    }
    _validate_clean_base_attestation(value)
    with pytest.raises(JourneyFailure, match="authorized VM104"):
        _validate_clean_base_attestation({**value, "vm_id": 101})


def test_windows_11_25h2_accepts_compatibility_product_name() -> None:
    _require_windows_25h2(
        {
            "system": "Windows",
            "release": "11",
            "product_name": "Windows 10 Pro",
            "display_version": "25H2",
            "architecture": "x86_64",
            "os_build": "26200",
            "ubr": 9168,
        }
    )


def test_restart_boundary_waits_for_old_process_to_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = iter((True, True, False))
    monkeypatch.setattr(
        "tools.artifex2.run_m7_shipping_journey._process_exists",
        lambda _process_id: next(observations),
    )
    monkeypatch.setattr("tools.artifex2.run_m7_shipping_journey.time.sleep", lambda _value: None)

    _wait_for_process_exit(123)


def test_shipping_cli_records_hashes_not_raw_output(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")

    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 0, stdout='{"ok":true,"value":{}}\n', stderr="")

    cli = ShippingCLI(executable, cwd=tmp_path, runner=runner)
    cli.direct("service.status", ["service", "status"])

    assert cli.calls[0] == {
        "operation": "service.status",
        "returncode": 0,
        "ok": True,
        "stdout_sha256": "177b1de4bfd52d4bd3f3fe816e132d29b745088fbd125b56e51dc45fe799d31e",
        "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    assert "value" not in cli.calls[0]


def test_shipping_cli_surfaces_only_normalized_failure(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")

    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            [],
            1,
            stdout=json.dumps(
                {
                    "ok": False,
                    "value": {},
                    "error": {
                        "code": "OPERATION_FAILED",
                        "message": "managed service registration failed",
                        "details": {"type": "ServiceRegistrationError"},
                    },
                }
            ),
            stderr="",
        )

    cli = ShippingCLI(executable, cwd=tmp_path, runner=runner)
    with pytest.raises(
        JourneyFailure,
        match="OPERATION_FAILED/ServiceRegistrationError",
    ):
        cli.direct("distribution.install", ["install"])
    assert cli.calls == []


def test_qualifier_executes_installed_native_cli_without_python_module(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")
    observed: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"ok":true,"value":{}}', stderr="")

    _run_json(
        executable,
        ["service", "status"],
        environment={},
        cwd=tmp_path,
        runner=runner,
    )

    assert observed == [[str(executable), "service", "status"]]
    assert "-m" not in observed[0]


def test_installed_origin_binds_native_executable_and_install_manifest(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")
    digest = "bef32d2c315a289576f2a6828d27edb16bb316a4d85c271f2d794045f3ea668d"
    manifest = {
        "install_root": str(tmp_path.resolve()),
        "artifact_manifest": {"artifact": "artifex.exe", "sha256": digest},
        "files": [{"path": "artifex.exe", "sha256": digest}],
    }
    (tmp_path / "artifex-install-manifest.json").write_text(json.dumps(manifest))

    assert len(_installed_origin(executable, install_root=tmp_path, repo_root=None)) == 64

    manifest["artifact_manifest"]["sha256"] = "0" * 64
    (tmp_path / "artifex-install-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="does not bind"):
        _installed_origin(executable, install_root=tmp_path, repo_root=None)
