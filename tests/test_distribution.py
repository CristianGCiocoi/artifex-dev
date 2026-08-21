from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.distribution import (
    ExperienceMode,
    ResourceEnvelope,
    apply_integration_setup,
    discover_environment,
    explain_decision,
    install,
    install_plan,
    plan_integration_setup,
    presentation_policy,
    require_approval,
    run_distribution_doctor,
    uninstall,
    uninstall_plan,
    upgrade,
    upgrade_plan,
)
from artifex.integrations.claude import ClaudeDetection, ClaudeIntegration
from artifex.integrations.codex import CodexDetection, CodexIntegration
from artifex.integrations.hermes import HermesIntegration
from artifex.integrations.manual import ManualIntegration


@pytest.mark.unit
def test_resource_envelope_is_typed_and_rejects_invalid_values() -> None:
    value = ResourceEnvelope(4, 1024, 2048, "Test", "x64")
    assert value.to_dict()["logical_cpu_count"] == 4
    with pytest.raises(ValueError):
        ResourceEnvelope(0, None, 1, "Test", "x64")


@pytest.mark.unit
def test_discovery_is_bounded_read_only_and_covers_every_supported_tool(tmp_path: Path) -> None:
    report = discover_environment(
        command_overrides={name: sys.executable for name in ("git", "hermes", "codex", "claude")},
        resource_path=tmp_path,
        timeout_seconds=2,
    )
    assert report.bounded_read_only is True
    assert {tool.tool for tool in report.tools} == {"git", "hermes", "codex", "claude"}
    assert all(tool.probe == "PATH + --version (read-only)" for tool in report.tools)
    assert report.resources.logical_cpu_count >= 1
    with pytest.raises(ValueError):
        discover_environment(timeout_seconds=30)


@pytest.mark.unit
def test_discovery_reports_missing_tools_without_failure(tmp_path: Path) -> None:
    report = discover_environment(
        command_overrides={name: None for name in ("git", "hermes", "codex", "claude")},
        search_path="",
        resource_path=tmp_path,
    )
    assert {tool.status for tool in report.tools} == {"NOT_FOUND"}


@pytest.mark.unit
def test_presentation_modes_and_risk_approval_are_explicit() -> None:
    beginner = presentation_policy(ExperienceMode.BEGINNER)
    expert = presentation_policy(ExperienceMode.EXPERT)
    assert beginner["show_raw_contracts"] is False
    assert expert["show_raw_contracts"] is True
    decision = explain_decision(
        "write configuration", "REVERSIBLE", effects=("write one file",), rollback="delete it"
    )
    assert decision.confirmation_token is not None
    with pytest.raises(PermissionError):
        require_approval(decision, "wrong")
    require_approval(decision, decision.confirmation_token)


@pytest.mark.integration
def test_setup_is_plan_first_and_never_mutates_vendor_configuration(tmp_path: Path) -> None:
    plan = plan_integration_setup(tmp_path, ("hermes", "codex", "claude", "manual"))
    state = tmp_path / ".artifex" / "integrations.json"
    assert not state.exists()
    assert all(not action.vendor_configuration_mutated for action in plan.actions)
    with pytest.raises(PermissionError):
        apply_integration_setup(plan, confirmation_token=None)
    applied = apply_integration_setup(
        plan, confirmation_token=plan.decision.confirmation_token
    )
    payload = json.loads(state.read_text(encoding="utf-8"))
    assert applied.applied is True
    assert payload["vendor_configuration_mutated"] is False
    assert payload["authority"] == "ARTIFEX_PROJECT_STATE"


@pytest.mark.adversarial
def test_setup_rejects_unknown_integration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        plan_integration_setup(tmp_path, ("untrusted",))


@pytest.mark.integration
def test_manifest_lifecycle_is_reversible_and_preserves_unrelated_files(tmp_path: Path) -> None:
    source = tmp_path / "source.exe"
    source.write_bytes(b"version-one")
    root = tmp_path / "installed"
    plan = install_plan(source, root)
    result = install(source, root, confirmation_token=plan.confirmation_token)
    executable = Path(result.executable)
    unrelated = root / "user-notes.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    source.write_bytes(b"version-two")
    next_plan = upgrade_plan(root)
    upgraded = upgrade(source, root, confirmation_token=next_plan.confirmation_token)
    assert executable.read_bytes() == b"version-two"
    assert upgraded.backup is not None and Path(upgraded.backup).read_bytes() == b"version-one"
    remove_plan = uninstall_plan(root)
    removed = uninstall(root, confirmation_token=remove_plan.confirmation_token)
    assert str(executable) in removed["removed"]
    assert upgraded.backup in removed["removed"]
    assert unrelated.read_text(encoding="utf-8") == "preserve"
    assert root.is_dir()


@pytest.mark.adversarial
def test_uninstall_refuses_modified_or_escaping_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root)
    result = install(source, root, confirmation_token=plan.confirmation_token)
    Path(result.executable).write_bytes(b"locally modified")
    remove_plan = uninstall_plan(root)
    with pytest.raises(ValueError, match="modified"):
        uninstall(root, confirmation_token=remove_plan.confirmation_token)

    manifest = Path(result.manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["files"][0]["path"] = "../outside"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe"):
        uninstall_plan(root)


@pytest.mark.integration
def test_doctor_fix_is_dry_run_by_default_and_allowlisted(tmp_path: Path) -> None:
    state = tmp_path / ".artifex"
    report = run_distribution_doctor(tmp_path, fix=True)
    assert report.dry_run is True
    assert not state.exists()
    assert report.fixes[0]["status"] == "PLANNED"
    applied = run_distribution_doctor(tmp_path, fix=True, apply=True)
    assert applied.fixes[0]["status"] == "APPLIED"
    assert state.is_dir()
    with pytest.raises(ValueError, match="requires"):
        run_distribution_doctor(tmp_path, apply=True)


@pytest.mark.unit
def test_application_exposes_distribution_operations(tmp_path: Path) -> None:
    application = Application()
    operations = set(application.operation_names)
    assert {
        "distribution.discover",
        "distribution.setup.plan",
        "distribution.install.plan",
        "distribution.upgrade.plan",
        "distribution.uninstall.plan",
        "beginner.start",
    } <= operations
    result = application.dispatch(
        OperationRequest(
            "distribution.presentation",
            {"mode": "GUIDED"},
            OperationContext(project_root=str(tmp_path), actor="test"),
        )
    )
    assert result.ok and result.value["mode"] == "GUIDED"


@pytest.mark.conformance
def test_all_v1_interfaces_remain_standalone_first_class() -> None:
    integrations = (
        HermesIntegration.simulated(),
        CodexIntegration(CodexDetection(True, "codex", "1.2.3")),
        ClaudeIntegration(ClaudeDetection(True, "claude", "1.2.3")),
        ManualIntegration(),
    )
    assert {item.metadata.integration_id for item in integrations} == {
        "hermes",
        "codex",
        "claude",
        "manual",
    }
    assert all(item.health().status.value == "PASS" for item in integrations)


@pytest.mark.packaging
def test_native_build_contract_and_ci_cover_all_target_platforms() -> None:
    root = Path(__file__).resolve().parents[1]
    build_script = (root / "packaging" / "build.py").read_text(encoding="utf-8")
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '"--onefile"' in build_script
    assert '"--smoke"' in build_script
    assert '"requires_user_python": False' in build_script
    assert "ubuntu-latest" in workflow
    assert "windows-latest" in workflow
    assert "macos-latest" in workflow
    assert "packaging/build.py --clean --smoke" in workflow
