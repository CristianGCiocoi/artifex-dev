from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from artifex.application import Application, OperationContext, OperationRequest
from artifex.capabilities import ProviderCompositionLoader, ProviderRole
from artifex.cli import app
from artifex.runtime import SQLiteRunStore


def _completed(
    arguments: tuple[str, ...], *, returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr="")


def _ready_codex_loader() -> ProviderCompositionLoader:
    def runner(arguments: object) -> subprocess.CompletedProcess[str]:
        command = tuple(str(item) for item in arguments)  # type: ignore[arg-type]
        if command[-1] == "--version":
            return _completed(command, stdout="codex-cli 0.150.1\n")
        assert command[-2:] == ("login", "status")
        return _completed(command, stdout="Logged in using ChatGPT\n")

    return ProviderCompositionLoader(
        which=lambda value: "C:/fixture/codex.exe" if value == "codex" else None,
        runner=runner,  # type: ignore[arg-type]
        certified_roles={
            "codex": frozenset({ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER})
        },
    )


def _persist_codex_setup(root: Path) -> None:
    state = root / ".artifex" / "integrations.json"
    state.parent.mkdir(parents=True)
    state.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "enabled": ["codex"],
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.integration
def test_public_bootstrap_consumes_setup_and_projects_certified_candidate(
    tmp_path: Path,
) -> None:
    _persist_codex_setup(tmp_path)

    result = Application(provider_loader=_ready_codex_loader()).dispatch(
        OperationRequest(
            "distribution.bootstrap",
            {},
            OperationContext(project_root=str(tmp_path), actor="clean-machine"),
        )
    )

    assert result.ok
    assert result.value["fresh_process_consumed_setup"] is True
    assert result.value["automated_candidates"] == ["codex"]
    assert result.value["manual_fallback"]["selected"] is False
    assert result.value["authority"]["contextual_dispatch_requires_resolver"] is True
    provider = result.value["capability_graph"]["providers"][0]
    assert provider["readiness"]["state"] == "AVAILABLE"
    assert provider["certified_roles"] == ["EXECUTION_IMPLEMENTER", "INTERACTION"]


@pytest.mark.conformance
def test_no_provider_bootstrap_is_fail_closed_and_manual_fallback_is_actionable(
    tmp_path: Path,
) -> None:
    result = Application().dispatch(
        OperationRequest(
            "distribution.bootstrap",
            {},
            OperationContext(project_root=str(tmp_path), actor="clean-machine"),
        )
    )

    assert result.ok
    assert result.value["status"] == "MANUAL_FALLBACK"
    assert result.value["fresh_process_consumed_setup"] is False
    assert result.value["automated_candidates"] == []
    fallback = result.value["manual_fallback"]
    assert fallback["selected"] is True
    assert [item["operation"] for item in fallback["actions"]] == [
        "manual.packet.create",
        "manual.result.submit",
    ]
    assert fallback["self_acceptance"] is False


@pytest.mark.integration
def test_shipping_cli_exposes_parameterized_bootstrap_without_private_factory(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(app, ["bootstrap", "--project-root", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["value"]["status"] == "MANUAL_FALLBACK"
    source = Path(payload["value"]["capability_graph"]["source"])
    assert source.parts[-2:] == (".artifex", "integrations.json")


@pytest.mark.adversarial
def test_available_but_uncertified_provider_cannot_suppress_manual_fallback(
    tmp_path: Path,
) -> None:
    _persist_codex_setup(tmp_path)
    loader = _ready_codex_loader()
    loader.certified_roles = {}

    result = Application(provider_loader=loader).dispatch(
        OperationRequest(
            "distribution.bootstrap",
            {},
            OperationContext(project_root=str(tmp_path), actor="clean-machine"),
        )
    )

    assert result.ok
    provider = result.value["capability_graph"]["providers"][0]
    assert provider["globally_available"] is True
    assert provider["certified_roles"] == []
    assert result.value["automated_candidates"] == []
    assert result.value["manual_fallback"]["selected"] is True


@pytest.mark.integration
def test_public_doctor_reports_service_fence_runstore_and_provider_without_secrets(
    tmp_path: Path,
) -> None:
    _persist_codex_setup(tmp_path)
    now = int(time.time())
    runstore_path = tmp_path / "runtime" / "runstore.sqlite3"
    store = SQLiteRunStore(runstore_path)
    token = store.acquire_coordinator("service-private-identity", now=now, ttl_seconds=120)
    service_state = tmp_path / "runtime" / "service-state.json"
    service_state.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "service_id": "artifex",
                "instance_id": "private-instance",
                "lifecycle_state": "RUNNING",
                "process_id": 123,
                "coordinator_generation": token.generation,
                "frontend_independent": True,
                "transport": {
                    "kind": "LOCAL_TCP",
                    "protocol": "ARTIFEX_JSON_V1",
                    "host": "127.0.0.1",
                    "port": 43210,
                },
                "paths": {"runstore": str(runstore_path)},
                "must_not_escape": "doctor-secret-marker",
            }
        ),
        encoding="utf-8",
    )
    (service_state.parent / ".local-transport-token").write_text(
        "transport-secret-marker", encoding="utf-8"
    )

    result = Application(provider_loader=_ready_codex_loader()).dispatch(
        OperationRequest(
            "distribution.doctor",
            {
                "runstore_path": str(runstore_path),
                "service_state_path": str(service_state),
            },
            OperationContext(project_root=str(tmp_path), actor="clean-machine"),
        )
    )

    assert result.ok
    findings = {item["id"]: item for item in result.value["findings"]}
    assert findings["managed-service"]["status"] == "PASS"
    assert findings["managed-service"]["details"] == {
        "state": "RUNNING",
        "state_file_present": True,
        "schema_version": "1.0",
        "frontend_independent": True,
        "process_id_present": True,
        "coordinator_generation": token.generation,
        "transport": {
            "configured": True,
            "kind": "LOCAL_TCP",
            "protocol": "ARTIFEX_JSON_V1",
        },
    }
    assert findings["runstore"]["status"] == "PASS"
    assert findings["coordinator-fence"]["status"] == "PASS"
    assert findings["provider:codex"]["details"]["automated_candidate"] is True
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    assert "service-private-identity" not in serialized
    assert "private-instance" not in serialized
    assert "doctor-secret-marker" not in serialized
    assert "transport-secret-marker" not in serialized
    assert "credential_reference" not in serialized


@pytest.mark.adversarial
def test_doctor_classifies_corrupt_provider_setup_without_echoing_content(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".artifex" / "integrations.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"secret":"must-not-echo"}', encoding="utf-8")

    result = Application().dispatch(
        OperationRequest(
            "distribution.doctor",
            {},
            OperationContext(project_root=str(tmp_path), actor="clean-machine"),
        )
    )

    assert result.ok
    findings = {item["id"]: item for item in result.value["findings"]}
    assert findings["provider-composition"]["status"] == "FAIL"
    assert findings["provider-composition"]["details"]["error_type"] == ("ProviderSetupError")
    assert "must-not-echo" not in json.dumps(result.to_dict())


@pytest.mark.adversarial
def test_doctor_reports_an_uncreated_nested_project_without_failing(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "not-created" / "nested" / "project"

    result = Application().dispatch(
        OperationRequest(
            "distribution.doctor",
            {},
            OperationContext(project_root=str(project_root), actor="clean-machine"),
        )
    )

    assert result.ok
    findings = {item["id"]: item for item in result.value["findings"]}
    assert findings["project-state"]["status"] == "DEGRADED"
    assert findings["manual-fallback"]["remediation_id"] == "use-manual-integration"
    assert not project_root.exists()
