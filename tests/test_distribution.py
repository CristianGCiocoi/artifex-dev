from __future__ import annotations

import hashlib
import json
import runpy
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.distribution import (
    ApprovalStore,
    ExperienceMode,
    ResourceEnvelope,
    apply_integration_setup,
    complete_deferred_uninstall,
    discover_environment,
    explain_decision,
    install,
    install_plan,
    lifecycle,
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
def test_presentation_modes_and_risk_approval_are_explicit(tmp_path: Path) -> None:
    beginner = presentation_policy(ExperienceMode.BEGINNER)
    expert = presentation_policy(ExperienceMode.EXPERT)
    assert beginner["show_raw_contracts"] is False
    assert expert["show_raw_contracts"] is True
    store = ApprovalStore(tmp_path / "approvals")
    decision = explain_decision(
        "write configuration",
        "REVERSIBLE",
        effects=("write one file",),
        rollback="delete it",
        binding={"target": "one"},
        approval_store=store,
    )
    assert decision.confirmation_token is not None
    with pytest.raises(PermissionError):
        require_approval(decision, "wrong", approval_store=store)
    require_approval(decision, decision.confirmation_token, approval_store=store)
    with pytest.raises(PermissionError, match="consumed"):
        require_approval(decision, decision.confirmation_token, approval_store=store)


@pytest.mark.adversarial
def test_approval_tokens_are_random_expiring_and_bound(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals")
    now = datetime(2026, 8, 21, tzinfo=UTC)
    first = explain_decision(
        "mutate",
        "REVERSIBLE",
        effects=("write A",),
        rollback="restore A",
        binding={"target": "A"},
        approval_store=store,
        now=now,
        ttl_seconds=2,
    )
    second = explain_decision(
        "mutate",
        "REVERSIBLE",
        effects=("write A",),
        rollback="restore A",
        binding={"target": "A"},
        approval_store=store,
        now=now,
        ttl_seconds=2,
    )
    assert first.confirmation_token != second.confirmation_token
    assert len(first.confirmation_token or "") > 40
    with pytest.raises(PermissionError, match="expired"):
        require_approval(
            first,
            first.confirmation_token,
            approval_store=store,
            now=now + timedelta(seconds=3),
        )
    different = explain_decision(
        "mutate",
        "REVERSIBLE",
        effects=("write B",),
        rollback="restore B",
        binding={"target": "B"},
        approval_store=store,
        issue_token=False,
    )
    with pytest.raises(PermissionError, match="different operation"):
        require_approval(
            different, second.confirmation_token, approval_store=store, now=now
        )


@pytest.mark.adversarial
def test_approval_store_corruption_and_invalid_inputs_fail_closed(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals")
    with pytest.raises(ValueError, match="TTL"):
        store.issue("a" * 64, ttl_seconds=0)
    with pytest.raises(PermissionError, match="valid explicit"):
        store.consume(None, "a" * 64)
    token, _ = store.issue("a" * 64, now=datetime(2026, 8, 21))
    record = next(store.root.glob("*.json"))
    record.write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="record is invalid"):
        store.consume(token, "a" * 64)


@pytest.mark.integration
def test_setup_is_plan_first_and_never_mutates_vendor_configuration(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approval-store")
    plan = plan_integration_setup(
        tmp_path,
        ("hermes", "codex", "claude", "manual"),
        approval_store=store,
    )
    state = tmp_path / ".artifex" / "integrations.json"
    assert not state.exists()
    assert all(not action.vendor_configuration_mutated for action in plan.actions)
    with pytest.raises(PermissionError):
        apply_integration_setup(plan, confirmation_token=None, approval_store=store)
    applied = apply_integration_setup(
        plan,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=store,
    )
    payload = json.loads(state.read_text(encoding="utf-8"))
    assert applied.applied is True
    assert payload["vendor_configuration_mutated"] is False
    assert payload["authority"] == "ARTIFEX_PROJECT_STATE"


@pytest.mark.adversarial
def test_setup_rejects_unknown_integration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        plan_integration_setup(tmp_path, ("untrusted",))


@pytest.mark.adversarial
def test_setup_approval_is_bound_to_exact_integration_selection(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approval-store")
    approved = plan_integration_setup(
        tmp_path, ("manual", "codex"), approval_store=store
    )
    changed = plan_integration_setup(
        tmp_path,
        ("manual", "claude"),
        approval_store=store,
        issue_token=False,
    )
    with pytest.raises(PermissionError, match="different operation"):
        apply_integration_setup(
            changed,
            confirmation_token=approved.decision.confirmation_token,
            approval_store=store,
        )
    assert not (tmp_path / ".artifex" / "integrations.json").exists()


@pytest.mark.integration
def test_manifest_lifecycle_is_reversible_and_preserves_unrelated_files(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source.exe"
    source.write_bytes(b"version-one")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    executable = Path(result.executable)
    unrelated = root / "user-notes.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    source.write_bytes(b"version-two")
    next_plan = upgrade_plan(
        source, root, approval_store=approvals, security_root=security
    )
    upgraded = upgrade(
        source,
        root,
        confirmation_token=next_plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    assert executable.read_bytes() == b"version-two"
    assert upgraded.backup is not None and Path(upgraded.backup).read_bytes() == b"version-one"
    remove_plan = uninstall_plan(
        root, approval_store=approvals, security_root=security
    )
    removed = uninstall(
        root,
        confirmation_token=remove_plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    assert str(executable) in removed["removed"]
    assert upgraded.backup in removed["removed"]
    assert unrelated.read_text(encoding="utf-8") == "preserve"
    assert root.is_dir()


@pytest.mark.adversarial
def test_uninstall_refuses_modified_or_escaping_manifest(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    Path(result.executable).write_bytes(b"locally modified")
    remove_plan = uninstall_plan(root, approval_store=approvals, security_root=security)
    with pytest.raises(ValueError, match="modified"):
        uninstall(
            root,
            confirmation_token=remove_plan.confirmation_token,
            approval_store=approvals,
            security_root=security,
        )

    manifest = Path(result.manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["files"][0]["path"] = "../outside"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication"):
        uninstall_plan(root, approval_store=approvals, security_root=security)


@pytest.mark.adversarial
def test_tampered_manifest_cannot_reclassify_unmanaged_child(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    unmanaged = root / "user-data.txt"
    unmanaged.write_text("must survive", encoding="utf-8")
    manifest = Path(result.manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["files"] = [
        {"path": unmanaged.name, "sha256": hashlib.sha256(unmanaged.read_bytes()).hexdigest()}
    ]
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication"):
        uninstall_plan(root, approval_store=approvals, security_root=security)
    assert unmanaged.read_text(encoding="utf-8") == "must survive"


@pytest.mark.adversarial
def test_install_rolls_back_binary_key_and_manifest_on_manifest_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)

    def fail_manifest(*_: object, **__: object) -> None:
        raise OSError("injected manifest persistence failure")

    monkeypatch.setattr(lifecycle, "_write_manifest", fail_manifest)
    with pytest.raises(OSError, match="injected"):
        install(
            source,
            root,
            confirmation_token=plan.confirmation_token,
            approval_store=approvals,
            security_root=security,
        )
    assert not root.exists() or not any(root.iterdir())
    assert not list(security.rglob("*.key"))


@pytest.mark.adversarial
def test_missing_install_key_and_malformed_signed_values_fail_closed(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)
    install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    next(security.rglob("*.key")).unlink()
    with pytest.raises(ValueError, match="security key is missing"):
        uninstall_plan(root, approval_store=approvals, security_root=security)
    with pytest.raises(ValueError, match="no managed files"):
        lifecycle._manifest_entries({}, "files", required=True)
    with pytest.raises(ValueError, match="invalid install manifest"):
        lifecycle._manifest_entries({"files": ["not-an-object"]}, "files", required=True)
    assert lifecycle._verify_signed_value({}, b"k" * 32) is False
    signed = lifecycle._signed_value({"kind": "test"}, b"k" * 32)
    signed["authentication"]["algorithm"] = "UNTRUSTED"
    assert lifecycle._verify_signed_value(signed, b"k" * 32) is False
    assert lifecycle._pid_exists(-1) is False


@pytest.mark.integration
def test_deferred_self_uninstall_completes_after_parent_exit(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source.exe"
    source.write_bytes(b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(source, root, approval_store=approvals)
    installed = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    unmanaged = root / "keep.txt"
    unmanaged.write_text("keep", encoding="utf-8")
    remove_plan = uninstall_plan(root, approval_store=approvals, security_root=security)
    launched: list[tuple[Path, Path, int]] = []
    result = uninstall(
        root,
        confirmation_token=remove_plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        running_executable=installed.executable,
        force_deferred=True,
        deferred_launcher=lambda executable, request, pid: launched.append(
            (executable, request, pid)
        ),
    )
    assert result["status"] == "DEFERRED"
    assert Path(installed.executable).exists()
    assert len(launched) == 1
    request_path = launched[0][1]
    with pytest.raises(TimeoutError, match="parent process"):
        complete_deferred_uninstall(
            request_path,
            security_root=security,
            parent_checker=lambda _: True,
            wait_timeout_seconds=0,
        )
    original_request = request_path.read_text(encoding="utf-8")
    tampered_request = json.loads(original_request)
    tampered_request["manifest_fingerprint"] = "0" * 64
    request_path.write_text(json.dumps(tampered_request), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication"):
        complete_deferred_uninstall(
            request_path, security_root=security, parent_checker=lambda _: False
        )
    request_path.write_text(original_request, encoding="utf-8")
    completed = complete_deferred_uninstall(
        request_path, security_root=security, parent_checker=lambda _: False
    )
    assert completed["status"] == "COMPLETE"
    assert not Path(installed.executable).exists()
    assert not Path(installed.manifest).exists()
    assert unmanaged.read_text(encoding="utf-8") == "keep"


@pytest.mark.adversarial
def test_upgrade_token_is_source_bound_and_failure_restores_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = tmp_path / "source"
    source.write_bytes(b"v1")
    root = tmp_path / "installed"
    initial = install_plan(source, root, approval_store=approvals)
    installed = install(
        source,
        root,
        confirmation_token=initial.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    source.write_bytes(b"v2")
    stale = upgrade_plan(source, root, approval_store=approvals, security_root=security)
    source.write_bytes(b"changed-after-approval")
    with pytest.raises(PermissionError, match="different operation"):
        upgrade(
            source,
            root,
            confirmation_token=stale.confirmation_token,
            approval_store=approvals,
            security_root=security,
        )
    executable = Path(installed.executable)
    manifest = Path(installed.manifest)
    assert executable.read_bytes() == b"v1"
    original_manifest = manifest.read_bytes()
    valid = upgrade_plan(source, root, approval_store=approvals, security_root=security)

    def fail_manifest(*_: object, **__: object) -> None:
        raise OSError("injected upgrade manifest failure")

    monkeypatch.setattr(lifecycle, "_write_manifest", fail_manifest)
    with pytest.raises(OSError, match="injected"):
        upgrade(
            source,
            root,
            confirmation_token=valid.confirmation_token,
            approval_store=approvals,
            security_root=security,
        )
    assert executable.read_bytes() == b"v1"
    assert manifest.read_bytes() == original_manifest
    assert not list(root.glob("*.bak"))


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


@pytest.mark.adversarial
def test_native_build_clean_rejects_root_external_and_symlink_targets(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    validator = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "packaging" / "build.py")
    )["validated_clean_targets"]
    output = repository / "dist" / "native"
    work = repository / "build" / "native"
    assert validator(repository, output, work) == (output.resolve(), work.resolve())
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(ValueError, match="only remove"):
        validator(repository, repository, work)
    with pytest.raises(ValueError, match="only remove"):
        validator(repository, tmp_path / "external", work)
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    external = tmp_path / "external-dist"
    external.mkdir()
    try:
        (repository / "dist").symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError, match=r"inside|symlink"):
        validator(repository, output, work)
