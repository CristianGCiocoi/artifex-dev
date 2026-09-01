from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer

import artifex.cli as cli


def test_cli_translates_every_current_command_family_to_semantic_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, Any], str | None]] = []

    def capture(
        operation: str,
        arguments: dict[str, Any] | None = None,
        *,
        project_root: str | None = None,
    ) -> None:
        calls.append((operation, arguments or {}, project_root))

    monkeypatch.setattr(cli, "_emit", capture)
    project = str(tmp_path / "project")
    catalog = str(tmp_path / "catalog.json")
    runstore = str(tmp_path / "runstore.sqlite3")
    state = str(tmp_path / "state")
    executable = str(tmp_path / "artifex.exe")
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"value": "bounded"}), encoding="utf-8")

    cli.system_health()
    cli.system_version()
    cli.system_operations()
    cli.doctor(project, runstore, state, True, False)
    cli.bootstrap(project)
    cli.migration_inspect(project, catalog, runstore, state)
    cli.migration_plan(project, catalog, runstore, state)
    cli.migration_apply(project, catalog, runstore, state, "token")
    cli.migration_validate("record.json", project, catalog, runstore, state)
    cli.migration_rollback_plan("record.json", project, catalog, runstore, state)
    cli.migration_rollback("record.json", project, catalog, runstore, state, "token")
    cli.discover(project)
    cli.mode("guided")
    cli.setup_integrations(project, ["manual"], False, None)
    cli.setup_integrations(project, ["manual"], True, "token")
    cli.beginner_start("Build safely", project, "Example")
    cli.install_command(state, executable, False, None, True, state, "service", 30)
    cli.install_command(state, executable, True, "token", True, state, "service", 30)
    cli.upgrade_command(state, executable, False, None, True, state, "service", 30)
    cli.upgrade_command(state, executable, True, "token", True, state, "service", 30)
    cli.uninstall_command(state, False, None, True, "service", 30)
    cli.uninstall_command(state, True, "token", True, "service", 30)
    cli.call_operation("system.health", "{}", project)
    cli.integration_list()
    cli.integration_health("manual")
    cli.integration_select("INTERACTION", ["read"], None, ["manual"], [], True)
    cli.integration_select("INTERACTION", [], "manual", [], [], False)
    cli.integration_conformance("manual")
    cli.project_status(project, "manual")
    cli.project_create("Example", project, catalog, "project-id", "description")
    cli.project_adopt(project, "Example", catalog, "project-id")
    cli.project_continue("Example", catalog)
    cli.project_propose("Example", payload, 1, catalog, "CLIENT")
    cli.project_accept("Example", "proposal", 1, catalog)
    cli.project_observe("Example", catalog)
    cli.reality_state("Example", catalog)
    cli.documentation_status("Example", catalog)
    cli.documentation_regenerate("Example", ["README"], catalog)
    cli.dashboard_project("Example", catalog)
    cli.dashboard_platform(catalog)
    cli.manual_packet_create(payload)
    cli.manual_result_submit(payload)
    cli.research_request_validate(payload)
    cli.research_bundle_validate(payload)
    cli.pandora_readiness(state)
    cli.pandora_request(payload, state)
    cli.pandora_import(payload, state)
    cli.pandora_propose_adoption(payload, project, state, 1)

    operations = [operation for operation, _, _ in calls]
    assert len(calls) == 48
    assert operations.count("distribution.setup.plan") == 1
    assert operations.count("distribution.setup.apply") == 1
    assert operations.count("distribution.install.plan") == 1
    assert operations.count("distribution.install") == 1
    assert operations.count("distribution.upgrade.plan") == 1
    assert operations.count("distribution.upgrade") == 1
    assert operations.count("distribution.uninstall.plan") == 1
    assert operations.count("distribution.uninstall") == 1
    assert calls[-1] == (
        "research.pandora.adoption.propose",
        {
            "exchange_root": state,
            "request": {"value": "bounded"},
            "expected_revision": 1,
        },
        project,
    )


@pytest.mark.parametrize("content", ["not-json", "[]"])
def test_cli_json_inputs_fail_before_dispatch(tmp_path: Path, content: str) -> None:
    source = tmp_path / "input.json"
    source.write_text(content, encoding="utf-8")
    with pytest.raises(typer.BadParameter):
        cli._load_object(source)


@pytest.mark.parametrize("arguments", ["not-json", "[]"])
def test_generic_and_service_calls_reject_non_object_json(arguments: str) -> None:
    with pytest.raises(typer.BadParameter):
        cli.call_operation("system.health", arguments, None)
    with pytest.raises(typer.BadParameter):
        cli.service_call("system.health", arguments, None, None, 30.0)


def test_installer_transport_requires_consent_and_exact_action() -> None:
    with pytest.raises(typer.BadParameter, match="consent"):
        cli.installer_lifecycle_command("install", "root", "source", "state", False)
    with pytest.raises(typer.BadParameter, match="install requires"):
        cli.installer_lifecycle_command("install", "root", None, None, True)
    with pytest.raises(typer.BadParameter, match="action"):
        cli.installer_lifecycle_command("unknown", "root", None, None, True)


def test_cli_emit_and_service_emit_return_stable_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cli._emit("system.health")
    assert json.loads(capsys.readouterr().out)["ok"] is True
    cli._emit_service_result({"ok": True, "value": {"status": "PASS"}})
    assert json.loads(capsys.readouterr().out)["value"]["status"] == "PASS"
    with pytest.raises(typer.Exit):
        cli._emit("missing.operation")
    assert json.loads(capsys.readouterr().out)["ok"] is False
    with pytest.raises(typer.Exit):
        cli._emit_service_result({"ok": False, "error": {"code": "BLOCKED"}})
    assert json.loads(capsys.readouterr().out)["ok"] is False
