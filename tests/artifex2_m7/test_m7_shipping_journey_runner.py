from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from tools.artifex2 import run_m7_shipping_journey as journey_runner
from tools.artifex2.qualify_m7_windows import _installed_origin, _run_json
from tools.artifex2.run_m7_shipping_journey import (
    FrontendDetached,
    JourneyFailure,
    ShippingCLI,
    _bounded_interaction_prompt,
    _durable_provider_execution,
    _initial_service_status,
    _install_shipping_candidate,
    _provider_envelope,
    _provider_workspace_root,
    _require_clean_guest,
    _require_provider_guest,
    _require_provider_resume,
    _require_windows_25h2,
    _resume_installed_candidate,
    _role_states,
    _validate_clean_base_attestation,
    _validate_provider_ready_rebinding_attestation,
    _wait_for_process_exit,
)


def test_provider_interaction_prompt_requires_only_the_exact_bounded_marker() -> None:
    marker = "ARTIFEX_INTERACTION project_id=project semantic_revision=1"
    prompt = _bounded_interaction_prompt(marker)

    assert prompt.endswith("\n" + marker)
    assert prompt.count(marker) == 1
    assert "entire final response" in prompt
    assert "Do not call tools" in prompt
    assert "do not modify files" in prompt


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


def test_provider_guest_requires_exact_standalone_provider_and_clean_artifex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USERNAME", "qualification-user")
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#1")
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"native")
    paths = [tmp_path / name for name in ("stage", "install", "state", "project")]
    _require_provider_guest(
        expected_provider="codex",
        provider_command=codex,
        other_provider="claude",
        staging_root=paths[0],
        install_root=paths[1],
        state_root=paths[2],
        project_root=paths[3],
        which=lambda _name: None,
    )
    with pytest.raises(JourneyFailure, match="forbidden provider claude"):
        _require_provider_guest(
            expected_provider="codex",
            provider_command=codex,
            other_provider="claude",
            staging_root=paths[0],
            install_root=paths[1],
            state_root=paths[2],
            project_root=paths[3],
            which=lambda name: "C:/claude.exe" if name == "claude" else None,
        )


def test_provider_resume_requires_exact_preserved_harness_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USERNAME", "qualification-user")
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#1")
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"native")
    install_root = tmp_path / "install"
    state_root = tmp_path / "state"
    install_root.mkdir()
    state_root.mkdir()
    failure_capture = tmp_path / "failure.json"
    failure = {
        "diagnostic": (
            "governance.envelope.propose failed: OPERATION_FAILED/ValueError: "
            "service_id cannot override the managed service authority"
        ),
        "error": "JourneyFailure",
        "schema_version": "1.0",
        "status": "FAIL",
    }
    failure_capture.write_text(json.dumps(failure), encoding="utf-8")

    _require_provider_resume(
        expected_provider="codex",
        provider_command=codex,
        other_provider="claude",
        staging_root=tmp_path / "stage",
        install_root=install_root,
        state_root=state_root,
        project_root=tmp_path / "project-resume",
        failure_capture=failure_capture,
        which=lambda _name: None,
    )

    failure["diagnostic"] = "some other failure"
    failure_capture.write_text(json.dumps(failure), encoding="utf-8")
    with pytest.raises(JourneyFailure, match="authorized preserved qualification failure"):
        _require_provider_resume(
            expected_provider="codex",
            provider_command=codex,
            other_provider="claude",
            staging_root=tmp_path / "stage",
            install_root=install_root,
            state_root=state_root,
            project_root=tmp_path / "project-resume",
            failure_capture=failure_capture,
            which=lambda _name: None,
        )


def test_provider_resume_accepts_preserved_provider_terminal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USERNAME", "qualification-user")
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#1")
    codex = tmp_path / "codex.exe"
    codex.write_bytes(b"native")
    install_root = tmp_path / "install"
    state_root = tmp_path / "state"
    install_root.mkdir()
    state_root.mkdir()
    failure_capture = tmp_path / "failure.json"
    failure_capture.write_text(
        json.dumps(
            {
                "diagnostic": (
                    "provider EXECUTION_IMPLEMENTER did not finish successfully"
                ),
                "error": "JourneyFailure",
                "schema_version": "1.0",
                "status": "FAIL",
            }
        ),
        encoding="utf-8",
    )

    _require_provider_resume(
        expected_provider="codex",
        provider_command=codex,
        other_provider="claude",
        staging_root=tmp_path / "stage",
        install_root=install_root,
        state_root=state_root,
        project_root=tmp_path / "project-resume",
        failure_capture=failure_capture,
        which=lambda _name: None,
    )


def test_provider_resume_binds_existing_native_install_manifest(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")
    digest = hashlib.sha256(b"native").hexdigest()
    manifest = {
        "install_root": str(tmp_path.resolve()),
        "artifact_manifest": {"artifact": "artifex.exe", "sha256": digest},
        "files": [{"path": "artifex.exe", "sha256": digest}],
    }
    (tmp_path / "artifex-install-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (tmp_path / "service-registration.json").write_text("{}", encoding="utf-8")
    (tmp_path / "Uninstall.exe").write_bytes(b"uninstaller")

    assert _resume_installed_candidate(tmp_path.resolve()) == executable.resolve()

    manifest["artifact_manifest"]["sha256"] = "0" * 64
    (tmp_path / "artifex-install-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    with pytest.raises(JourneyFailure, match="does not bind"):
        _resume_installed_candidate(tmp_path.resolve())


def test_provider_envelope_is_proposed_unapproved_and_provider_bounded() -> None:
    envelope = _provider_envelope(
        provider_id="codex",
        project_id="m7-codex-project",
        workstream_id="m7-codex-workstream",
        baseline_fingerprint="a" * 64,
        baseline_commit="b" * 40,
    )

    assert envelope["approved"] is False
    assert envelope["allowed_providers"] == ["codex"]
    assert envelope["allowed_provider_roles"] == ["EXECUTION_IMPLEMENTER"]
    assert envelope["credential_references"][0]["revoked"] is False


def test_role_state_projection_requires_typed_certification_roles() -> None:
    assert _role_states(
        {
            "roles": [
                {"role": "INTERACTION", "state": "LIVE_ROLE_CERTIFIED"},
                {"role": "EXECUTION_IMPLEMENTER", "state": "LIVE_ROLE_CERTIFIED"},
            ]
        }
    ) == {
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
        "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
    }


def test_windows_provider_workspace_uses_public_managed_service_authority(
    tmp_path: Path,
) -> None:
    state_root = (tmp_path / "runtime").resolve()
    expected = state_root.with_name("runtime-workspaces")

    assert _provider_workspace_root(
        {"paths": {"workspace_root": str(expected)}},
        state_root=state_root,
        platform_name="nt",
    ) == expected

    with pytest.raises(JourneyFailure, match="private state tree"):
        _provider_workspace_root(
            {"paths": {"workspace_root": str(state_root / "workspaces")}},
            state_root=state_root,
            platform_name="nt",
        )


def test_clean_base_attestation_is_exact_and_operator_bound() -> None:
    value = {
        "schema_version": "1.0",
        "vm_id": 104,
        "snapshot_name": "m7-qualified-25h2-x64-cell-base-v10",
        "snapshot_config_sha256": "a" * 64,
        "account_sid_sha256": "b" * 64,
        "candidate_sha256": "c" * 64,
        "providers_absent": True,
        "source_checkout_absent": True,
    }
    _validate_clean_base_attestation(value)
    with pytest.raises(JourneyFailure, match="authorized VM reset"):
        _validate_clean_base_attestation({**value, "vm_id": 101})
    with pytest.raises(JourneyFailure, match="authorized VM reset"):
        _validate_clean_base_attestation(
            {**value, "snapshot_name": "m7-qualified-25h2-x64-cell-base-v9"}
        )

    vm105 = {
        **value,
        "vm_id": 105,
        "snapshot_name": "m7-qualified-25h2-x64-codex-cell-v10",
    }
    _validate_clean_base_attestation(
        vm105,
        expected_vm_id=105,
        expected_snapshot_name="m7-qualified-25h2-x64-codex-cell-v10",
    )
    with pytest.raises(JourneyFailure, match="authorized VM reset"):
        _validate_clean_base_attestation(
            vm105,
            expected_vm_id=105,
            expected_snapshot_name="m7-qualified-25h2-x64-claude-cell-v10",
        )


def test_provider_ready_rebinding_is_exact_and_preserves_clean_lineage(
    tmp_path: Path,
) -> None:
    clean_path = tmp_path / "clean.json"
    clean = {
        "schema_version": "1.0",
        "vm_id": 106,
        "snapshot_name": "m7-qualified-25h2-x64-claude-cell-v13",
        "snapshot_config_sha256": "a" * 64,
        "account_sid_sha256": "b" * 64,
        "candidate_sha256": "c" * 64,
        "providers_absent": True,
        "source_checkout_absent": True,
    }
    clean_path.write_text(json.dumps(clean), encoding="utf-8")
    rebound = {
        "schema_version": "1.0",
        "vm_id": 106,
        "snapshot_name": "m7-claude-provider-ready-v14",
        "snapshot_config_sha256": "d" * 64,
        "parent_provider_ready_snapshot_name": "m7-claude-provider-ready-v13",
        "parent_provider_ready_snapshot_config_sha256": "e" * 64,
        "clean_base_attestation_sha256": hashlib.sha256(
            clean_path.read_bytes()
        ).hexdigest(),
        "previous_candidate_sha256": "c" * 64,
        "candidate_sha256": "f" * 64,
        "source_commit": "1" * 40,
        "provider_id": "claude",
        "provider_version": "2.1.247 (Claude Code)",
        "provider_executable_sha256": "2" * 64,
        "auth_probe_sha256": "3" * 64,
        "artifex_absent": True,
        "journey_project_absent": True,
        "source_checkout_absent": True,
        "interactive_session_active": True,
        "vm_memory_included": True,
        "defender_realtime_enabled": True,
        "defender_candidate_detection_count": 0,
        "defender_candidate_excluded": False,
        "credential_material_extracted": False,
    }
    arguments = {
        "clean_base_attestation": clean_path,
        "clean_base": clean,
        "expected_vm_id": 106,
        "expected_snapshot_name": "m7-claude-provider-ready-v14",
        "expected_candidate_sha256": "f" * 64,
        "expected_source_commit": "1" * 40,
        "expected_provider_id": "claude",
        "expected_provider_version": "2.1.247 (Claude Code)",
        "expected_provider_executable_sha256": "2" * 64,
        "expected_auth_probe_sha256": "3" * 64,
    }
    _validate_provider_ready_rebinding_attestation(rebound, **arguments)
    _validate_provider_ready_rebinding_attestation(
        {**rebound, "vm_memory_included": False}, **arguments
    )

    with pytest.raises(JourneyFailure, match="security state"):
        _validate_provider_ready_rebinding_attestation(
            {**rebound, "credential_material_extracted": True}, **arguments
        )
    with pytest.raises(JourneyFailure, match="identity"):
        _validate_provider_ready_rebinding_attestation(
            {**rebound, "candidate_sha256": "4" * 64}, **arguments
        )
    with pytest.raises(JourneyFailure, match="memory state"):
        _validate_provider_ready_rebinding_attestation(
            {**rebound, "vm_memory_included": "no"}, **arguments
        )


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


def test_resume_recovers_a_stopped_registered_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailedCLI:
        def direct(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            raise JourneyFailure("service.status did not return one JSON object")

    restarted: list[bool] = []
    expected = {"ok": True, "value": {"lifecycle_state": "RUNNING"}}
    monkeypatch.setattr(
        journey_runner,
        "_restart_registered_windows_task",
        lambda **_kwargs: restarted.append(True),
    )
    monkeypatch.setattr(
        journey_runner,
        "_wait_for_service",
        lambda *_args, **_kwargs: expected,
    )

    assert (
        _initial_service_status(
            FailedCLI(),  # type: ignore[arg-type]
            state_root=tmp_path,
            resume_installed=True,
            runner=subprocess.run,
        )
        == expected
    )
    assert restarted == [True]


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


def test_shipping_cli_propagates_bounded_service_response_timeout(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")
    observed: list[tuple[list[str], int]] = []

    def runner(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        observed.append((command, int(kwargs["timeout"])))
        return subprocess.CompletedProcess(
            command, 0, stdout='{"ok":true,"value":{}}\n', stderr=""
        )

    cli = ShippingCLI(executable, cwd=tmp_path, runner=runner, timeout_seconds=900)
    cli.service_call(
        "providers.interact",
        {},
        project_root=tmp_path / "project",
        state_root=tmp_path / "state",
    )

    command, subprocess_timeout = observed[0]
    assert command[command.index("--timeout-seconds") + 1] == "900"
    assert subprocess_timeout == 900


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


def test_provider_execution_frontend_detach_is_hash_only(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native")

    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, "frontend transport timeout", "")

    cli = ShippingCLI(executable, cwd=tmp_path, runner=runner)
    with pytest.raises(FrontendDetached, match="durable result"):
        cli.direct("runtime.provider.execute", ["service", "call"])
    assert cli.calls[0]["frontend_detached"] is True
    assert "frontend transport timeout" not in json.dumps(cli.calls)


def test_durable_provider_execution_requires_success_and_passed_evidence() -> None:
    running = {
        "attempts": [{"attempt_id": "attempt", "state": "RUNNING"}],
    }
    assert (
        _durable_provider_execution(
            running,
            provider_id="codex",
            project_job_id="job",
            attempt_id="attempt",
        )
        is None
    )
    finished = {
        "attempts": [
            {
                "attempt_id": "attempt",
                "state": "FINISHED",
                "result_claim": "provider=codex; status=SUCCESS; owned_artifacts_sha256="
                + "a" * 64,
            }
        ],
        "project_jobs": [{"project_job_id": "job", "state": "FINISHED"}],
        "dispatch_authorizations": [
            {
                "attempt_id": "attempt",
                "provider_id": "codex",
                "provider_role": "EXECUTION_IMPLEMENTER",
            }
        ],
        "evidence_records": [
            {
                "attempt_id": "attempt",
                "project_job_id": "job",
                "evidence_id": "evidence-1",
                "passed": 1,
            }
        ],
    }
    assert _durable_provider_execution(
        finished,
        provider_id="codex",
        project_job_id="job",
        attempt_id="attempt",
    )["status"] == "SUCCESS"

    finished["attempts"][0]["result_claim"] = "provider=codex; status=BLOCKED;"
    with pytest.raises(JourneyFailure, match="did not finish successfully"):
        _durable_provider_execution(
            finished,
            provider_id="codex",
            project_job_id="job",
            attempt_id="attempt",
        )


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
