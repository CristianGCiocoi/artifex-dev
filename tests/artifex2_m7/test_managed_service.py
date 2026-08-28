from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from artifex.cli import app
from artifex.managed_service import (
    LOCAL_TRANSPORT_PROTOCOL,
    LocalServiceClient,
    ManagedServiceHost,
    ServiceAlreadyRunningError,
    ServicePaths,
    ServiceUnavailableError,
    read_service_state,
)
from artifex.runtime import ExecutionEnvelope


def _envelope() -> ExecutionEnvelope:
    return ExecutionEnvelope(
        envelope_id="m7-envelope",
        version=1,
        project_id="m7-project",
        objective="Prove frontend-independent managed runtime continuity",
        baseline_revision=1,
        actor_id="architect",
        allowed_paths=("src", "tests"),
        allowed_capabilities=("filesystem:workspace",),
        required_gates=("validation", "acceptance"),
        max_attempts=1,
        recovery_policy="RECONCILE_BEFORE_RETRY",
    )


def _bootstrap_arguments() -> dict[str, object]:
    return {
        "envelope": _envelope().to_dict(),
        "workstream_id": "m7-workstream",
        "run_id": "m7-run",
        "project_job_id": "m7-job",
        "attempt_id": "m7-attempt",
        "purpose": "service continuity",
    }


@pytest.mark.architecture
def test_service_state_is_secret_free_and_paths_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "state"
    paths = ServicePaths.resolve(root)
    assert paths.state_file == root / "service-state.json"
    assert paths.runstore == root / "runstore.sqlite3"
    assert paths.workspace_root == root / "workspaces"
    assert paths.instance_lock == root / ".service-instance.lock"
    assert paths.transport_token == root / ".local-transport-token"

    host = ManagedServiceHost(root)
    try:
        state = host.start().to_dict()
        token = paths.transport_token.read_text(encoding="utf-8")
        persisted = paths.state_file.read_text(encoding="utf-8")

        assert state["schema_version"] == "artifex.managed-service-state/v1"
        assert state["frontend_independent"] is True
        assert state["transport"] == {
            "kind": "TCP_LOOPBACK",
            "protocol": LOCAL_TRANSPORT_PROTOCOL,
            "host": "127.0.0.1",
            "port": state["transport"]["port"],
        }
        assert state["paths"] == {
            "state_root": str(root),
            "runstore": str(root / "runstore.sqlite3"),
            "workspace_root": str(root / "workspaces"),
        }
        assert token not in persisted
        assert "authorization" not in persisted
        if os.name != "nt":
            assert stat.S_IMODE(paths.transport_token.stat().st_mode) == 0o600
            assert stat.S_IMODE(paths.state_root.stat().st_mode) == 0o700
    finally:
        host.stop()


@pytest.mark.integration
def test_j01_j02_runtime_survives_frontend_exit_and_service_restart(tmp_path: Path) -> None:
    root = tmp_path / "state"
    first_host = ManagedServiceHost(root, lease_seconds=3)
    first_state = first_host.start()
    first_client = LocalServiceClient(root)

    bootstrapped = first_client.call("runtime.bootstrap", _bootstrap_arguments())
    assert bootstrapped["ok"] is True
    del first_client  # frontend lifetime is not runtime authority

    reconnected = LocalServiceClient(root)
    running = reconnected.call("runtime.status", {"run_id": "m7-run"})
    assert running["value"]["attempts"][0]["state"] == "RUNNING"
    first_host.stop(reason="CONTROLLED_RESTART")

    second_host = ManagedServiceHost(root, lease_seconds=3)
    try:
        second_state = second_host.start()
        assert second_state.instance_id != first_state.instance_id
        assert second_state.coordinator_generation > first_state.coordinator_generation

        after_restart = LocalServiceClient(root).call(
            "runtime.status", {"run_id": "m7-run"}
        )
        assert after_restart["value"]["attempts"][0]["state"] == "RUNNING"
        finished = LocalServiceClient(root).call(
            "runtime.attempt.finish",
            {"attempt_id": "m7-attempt", "result_claim": "restart preserved authority"},
        )
        assert finished["ok"] is True
        final = LocalServiceClient(root).call(
            "runtime.status", {"run_id": "m7-run"}
        )
        assert final["value"]["attempts"][0]["state"] == "FINISHED"
    finally:
        second_host.stop()


@pytest.mark.adversarial
def test_single_instance_fencing_and_stale_lock_recovery_are_fail_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    owner = ManagedServiceHost(root)
    owner.start()
    contender = ManagedServiceHost(root)
    try:
        with pytest.raises(ServiceAlreadyRunningError, match="already owned"):
            contender.start()
    finally:
        owner.stop()

    paths = ServicePaths.resolve(root)
    paths.instance_lock.write_text("not-json", encoding="utf-8")
    with pytest.raises(ServiceAlreadyRunningError, match="refusing unsafe"):
        ManagedServiceHost(root).start()
    assert paths.instance_lock.read_text(encoding="utf-8") == "not-json"

    paths.instance_lock.write_text(
        json.dumps({"instance_id": "dead-instance", "process_id": 2_147_483_647}),
        encoding="utf-8",
    )
    recovered = ManagedServiceHost(root)
    try:
        state = recovered.start()
        assert state.lifecycle_state == "RUNNING"
        assert state.instance_id != "dead-instance"
    finally:
        recovered.stop()


@pytest.mark.adversarial
def test_hosted_runtime_rejects_authority_path_overrides(tmp_path: Path) -> None:
    root = tmp_path / "state"
    host = ManagedServiceHost(root)
    try:
        host.start()
        result = LocalServiceClient(root).call(
            "runtime.bootstrap",
            {
                **_bootstrap_arguments(),
                "store_path": str(tmp_path / "attacker.sqlite3"),
            },
        )
        assert result["ok"] is False
        assert result["error"]["code"] == "OPERATION_FAILED"
        assert "cannot override" in result["error"]["message"]
        assert not (tmp_path / "attacker.sqlite3").exists()
    finally:
        host.stop()


@pytest.mark.integration
def test_public_status_and_controlled_shutdown_operations(tmp_path: Path) -> None:
    root = tmp_path / "state"
    host = ManagedServiceHost(root)
    host.start()
    client = LocalServiceClient(root)

    status = client.status()
    assert status["ok"] is True
    assert status["value"]["lifecycle_state"] == "RUNNING"
    assert client.shutdown()["value"] == {"shutdown_requested": True}

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = read_service_state(root / "service-state.json")
        if state["lifecycle_state"] == "STOPPED":
            break
        time.sleep(0.01)
    assert state["lifecycle_state"] == "STOPPED"
    assert state["shutdown_reason"] == "CLIENT_REQUEST"
    assert not (root / ".local-transport-token").exists()
    with pytest.raises(ServiceUnavailableError, match="not running"):
        LocalServiceClient(root).status()


@pytest.mark.integration
def test_public_cli_routes_application_calls_through_managed_service(tmp_path: Path) -> None:
    root = tmp_path / "state"
    host = ManagedServiceHost(root)
    host.start()
    runner = CliRunner()
    try:
        status = runner.invoke(app, ["service", "status", "--state-root", str(root)])
        assert status.exit_code == 0, status.stdout
        status_value = json.loads(status.stdout)
        assert status_value["value"]["lifecycle_state"] == "RUNNING"

        health = runner.invoke(
            app,
            [
                "service",
                "call",
                "system.health",
                "--state-root",
                str(root),
                "--arguments",
                "{}",
            ],
        )
        assert health.exit_code == 0, health.stdout
        assert json.loads(health.stdout)["ok"] is True

        stopped = runner.invoke(app, ["service", "stop", "--state-root", str(root)])
        assert stopped.exit_code == 0, stopped.stdout
        assert json.loads(stopped.stdout)["value"] == {"shutdown_requested": True}
    finally:
        host.stop()
