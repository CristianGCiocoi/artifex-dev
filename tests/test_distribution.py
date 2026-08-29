from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from artifex import cli as cli_module
from artifex.application import Application, OperationContext, OperationRequest
from artifex.application import api as application_api
from artifex.cli import app
from artifex.distribution import (
    ApprovalStore,
    ExperienceMode,
    ResourceEnvelope,
    ServiceRegistrationManifest,
    ServiceRegistrationObservation,
    apply_integration_setup,
    artifact,
    complete_deferred_uninstall,
    create_artifact_manifest,
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
    verify_artifact,
)
from artifex.integrations.claude import ClaudeDetection, ClaudeIntegration
from artifex.integrations.codex import CodexDetection, CodexIntegration
from artifex.integrations.hermes import HermesIntegration
from artifex.integrations.manual import ManualIntegration


def _write_test_artifact(directory: Path, content: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / ("artifex.exe" if os.name == "nt" else "artifex")
    source.write_bytes(content)
    bundled_runtime = directory / "_internal" / "runtime.bin"
    bundled_runtime.parent.mkdir(parents=True, exist_ok=True)
    bundled_runtime.write_bytes(b"runtime:" + content)
    _rewrite_artifact_manifest(source)
    return source


def _rewrite_artifact_manifest(source: Path) -> None:
    manifest = create_artifact_manifest(
        source,
        pyinstaller_version="test-pyinstaller",
        source_commit="0" * 40,
    )
    (source.parent / "artifex-artifact.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def _test_identity_probe(source: Path, _: float) -> dict[str, object]:
    manifest = json.loads(
        (source.parent / "artifex-artifact.json").read_text(encoding="utf-8")
    )
    return {
        "product": manifest["product"],
        "version": manifest["product_version"],
        "build_id": manifest["build_id"],
        "format": manifest["format"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "artifact": manifest["artifact"],
        "sha256": manifest["sha256"],
    }


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


@pytest.mark.adversarial
def test_discovery_uses_nearest_existing_ancestor_for_uncreated_project(
    tmp_path: Path,
) -> None:
    target = tmp_path / "not-created" / "nested" / "project"

    report = discover_environment(
        command_overrides={name: None for name in ("git", "hermes", "codex", "claude")},
        search_path="",
        resource_path=target,
    )

    assert report.resources.disk_free_bytes > 0
    assert not target.exists()


@pytest.mark.adversarial
def test_artifact_verification_rejects_missing_and_checksum_only_manifests(
    tmp_path: Path,
) -> None:
    source = tmp_path / ("artifex.exe" if os.name == "nt" else "artifex")
    source.write_bytes(b"arbitrary bytes")
    with pytest.raises(ValueError, match="adjacent artifact manifest"):
        verify_artifact(source, identity_probe=_test_identity_probe)
    (tmp_path / "artifex-artifact.json").write_text(
        json.dumps({"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="schema or fields"):
        verify_artifact(source, identity_probe=_test_identity_probe)


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("platform", "wrong-os", "platform"),
        ("architecture", "wrong-arch", "architecture"),
        ("artifact", "wrong-name.exe", "filename"),
        ("product_version", "999.0.0", "product or release"),
        ("format", "zip", "pyinstaller-onedir"),
    ],
)
def test_artifact_verification_rejects_incompatible_identity(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    source = _write_test_artifact(tmp_path / "release", b"native")
    manifest_path = source.parent / "artifex-artifact.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        verify_artifact(source, identity_probe=_test_identity_probe)


@pytest.mark.adversarial
def test_artifact_identity_probe_must_execute_and_match_manifest(tmp_path: Path) -> None:
    source = _write_test_artifact(tmp_path / "release", b"native")

    def failing_probe(_: Path, __: float) -> dict[str, object]:
        raise ValueError("probe failed")

    with pytest.raises(ValueError, match="probe failed"):
        verify_artifact(source, identity_probe=failing_probe)
    spoofed = _test_identity_probe(source, 1)
    spoofed["product"] = "NOT_ARTIFEX"
    with pytest.raises(ValueError, match="does not match"):
        verify_artifact(source, identity_probe=lambda _source, _timeout: spoofed)


@pytest.mark.adversarial
def test_artifact_manifest_rejects_unknown_fields_and_bundle_tampering(
    tmp_path: Path,
) -> None:
    source = _write_test_artifact(tmp_path / "release", b"native")
    manifest_path = source.parent / "artifex-artifact.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["format"] == "pyinstaller-onedir"
    assert manifest["python_version"]
    assert manifest["pyinstaller_version"]
    assert len(manifest["source_commit"]) == 40
    assert manifest["requires_user_python"] is False
    manifest["unexpected"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="schema or fields"):
        verify_artifact(source, identity_probe=_test_identity_probe)
    _write_test_artifact(source.parent, b"native")
    (source.parent / "_internal" / "runtime.bin").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="inventory"):
        verify_artifact(source, identity_probe=_test_identity_probe)


@pytest.mark.unit
def test_bounded_artifact_probe_accepts_only_successful_identity_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_test_artifact(tmp_path / "release", b"native")
    identity = _test_identity_probe(source, 1)

    class Result:
        returncode = 0
        stdout = json.dumps({"ok": True, "value": identity})

    monkeypatch.setattr(artifact.subprocess, "run", lambda *args, **kwargs: Result())
    assert artifact.probe_artifact_identity(source, 1) == identity

    class FailedResult:
        returncode = 9
        stdout = "{}"

    monkeypatch.setattr(
        artifact.subprocess, "run", lambda *args, **kwargs: FailedResult()
    )
    with pytest.raises(ValueError, match="exited with code 9"):
        artifact.probe_artifact_identity(source, 1)

    class InvalidResult:
        returncode = 0
        stdout = "not-json"

    monkeypatch.setattr(
        artifact.subprocess, "run", lambda *args, **kwargs: InvalidResult()
    )
    with pytest.raises(ValueError, match="did not return JSON"):
        artifact.probe_artifact_identity(source, 1)


@pytest.mark.unit
def test_native_artifact_platform_names_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(artifact.platform, "system", lambda: "unsupported-os")
    with pytest.raises(ValueError, match="unsupported native artifact platform"):
        artifact.canonical_platform()
    monkeypatch.setattr(artifact.platform, "machine", lambda: "unsupported-cpu")
    with pytest.raises(ValueError, match="unsupported native artifact architecture"):
        artifact.canonical_architecture()


@pytest.mark.unit
def test_frozen_runtime_identity_is_content_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artifact.sys, "frozen", True, raising=False)
    identity = artifact.runtime_release_identity()
    executable = Path(sys.executable).resolve()
    assert identity["product"] == "ARTIFEX"
    assert identity["format"] == "pyinstaller-onedir"
    assert identity["artifact"] == executable.name
    assert identity["sha256"] == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert str(identity["build_id"]).endswith(str(identity["sha256"])[:16])


@pytest.mark.integration
def test_internal_symlinks_are_inventoried_and_preserved_through_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"native")
    link = source.parent / "runtime-link.bin"
    try:
        link.symlink_to("_internal/runtime.bin")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    if os.name == "nt":
        error = "symlinks are unsupported on Windows"
        with pytest.raises(ValueError, match=error):
            create_artifact_manifest(source)
        with pytest.raises(ValueError, match=error):
            verify_artifact(source, identity_probe=_test_identity_probe)
        root = tmp_path / "must-not-install"
        with pytest.raises(ValueError, match=error):
            install_plan(
                source, root, approval_store=approvals, identity_probe=_test_identity_probe
            )
        assert not root.exists()
        return

    framework = source.parent / "_internal" / "Python.framework"
    version = framework / "Versions" / "3.12"
    version.mkdir(parents=True)
    (version / "Python").write_bytes(b"framework-runtime")
    current = framework / "Versions" / "Current"
    framework_binary = framework / "Python"
    current.symlink_to("3.12", target_is_directory=True)
    framework_binary.symlink_to("Versions/Current/Python")
    _rewrite_artifact_manifest(source)
    verified = verify_artifact(source, identity_probe=_test_identity_probe)
    link_entry = next(item for item in verified.files if item["path"] == link.name)
    assert link_entry["kind"] == "symlink"
    assert link_entry["target"] == "_internal/runtime.bin"
    assert next(
        item for item in verified.files if item["path"].endswith("Versions/Current")
    )["target"] == "3.12"
    manifest_path = source.parent / "artifex-artifact.json"
    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    next(item for item in tampered["files"] if item["path"] == link.name)[
        "target"
    ] = "../outside"
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match=r"symlink inventory|inventory"):
        verify_artifact(source, identity_probe=_test_identity_probe)
    _rewrite_artifact_manifest(source)

    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    installed = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    installed_link = root / link.name
    assert installed_link.is_symlink()
    assert os.readlink(installed_link) == "_internal/runtime.bin"
    installed_framework_binary = root / "_internal" / "Python.framework" / "Python"
    assert installed_framework_binary.is_symlink()
    assert installed_framework_binary.read_bytes() == b"framework-runtime"

    _write_test_artifact(source.parent, b"native-v2")
    upgrade_decision = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    upgraded = upgrade(
        source,
        root,
        confirmation_token=upgrade_decision.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    assert installed_link.is_symlink()
    assert installed_link.read_bytes() == b"runtime:native-v2"
    assert upgraded.backup is not None
    assert (Path(upgraded.backup) / link.name).is_symlink()

    _write_test_artifact(source.parent, b"native-v3")
    rollback_decision = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )

    def fail_manifest(*_: object, **__: object) -> None:
        raise OSError("injected symlink lifecycle rollback")

    monkeypatch.setattr(lifecycle, "_write_manifest", fail_manifest)
    with pytest.raises(OSError, match="symlink lifecycle rollback"):
        upgrade(
            source,
            root,
            confirmation_token=rollback_decision.confirmation_token,
            approval_store=approvals,
            security_root=security,
            identity_probe=_test_identity_probe,
        )
    assert installed_link.is_symlink()
    assert installed_link.read_bytes() == b"runtime:native-v2"

    remove_plan = uninstall_plan(root, approval_store=approvals, security_root=security)
    uninstall(
        root,
        confirmation_token=remove_plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
    )
    assert not os.path.lexists(installed_link)
    assert not Path(installed.executable).exists()


@pytest.mark.adversarial
@pytest.mark.parametrize("link_case", ["absolute", "escape", "dangling", "cycle"])
def test_artifact_symlinks_fail_closed(
    tmp_path: Path, link_case: str
) -> None:
    release = tmp_path / link_case
    source = _write_test_artifact(release, b"native")
    link = release / "unsafe-link"
    external = tmp_path / "external.bin"
    external.write_bytes(b"outside")
    try:
        if link_case == "absolute":
            link.symlink_to(external.resolve())
        elif link_case == "escape":
            link.symlink_to("../external.bin")
        elif link_case == "dangling":
            link.symlink_to("missing.bin")
        else:
            other = release / "other-link"
            link.symlink_to(other.name)
            other.symlink_to(link.name)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(
        ValueError, match=r"relative|escapes|dangling|cyclic|unsupported on Windows"
    ):
        create_artifact_manifest(source)


@pytest.mark.adversarial
def test_installed_symlink_retargeting_fails_closed(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"native")
    link = source.parent / "runtime-link.bin"
    try:
        link.symlink_to("_internal/runtime.bin")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    if os.name == "nt":
        with pytest.raises(ValueError, match="symlinks are unsupported on Windows"):
            _rewrite_artifact_manifest(source)
        return
    _rewrite_artifact_manifest(source)
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    installed_link = root / link.name
    installed_link.unlink()
    installed_link.symlink_to(tmp_path / "outside")
    remove_plan = uninstall_plan(root, approval_store=approvals, security_root=security)
    with pytest.raises(ValueError, match="modified"):
        uninstall(
            root,
            confirmation_token=remove_plan.confirmation_token,
            approval_store=approvals,
            security_root=security,
        )


@pytest.mark.adversarial
def test_windows_symlink_policy_rejects_all_manifest_entry_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = "_internal/runtime.bin"
    entry = {
        "path": "runtime-link.bin",
        "kind": "symlink",
        "target": target,
        "sha256": hashlib.sha256(target.encode()).hexdigest(),
    }
    monkeypatch.setattr(artifact, "_supports_bundle_symlinks", lambda: False)
    monkeypatch.setattr(lifecycle, "_supports_bundle_symlinks", lambda: False)
    error = "symlinks are unsupported on Windows"

    with pytest.raises(ValueError, match=error):
        artifact._file_entries([entry])
    with pytest.raises(ValueError, match=error):
        lifecycle._manifest_entries({"files": [entry]}, "files", required=True)
    source = tmp_path / "artifex.exe"
    source.write_bytes(b"native")
    verified = artifact.VerifiedArtifact(
        source,
        tmp_path,
        tmp_path / "artifex-artifact.json",
        {},
        "0" * 64,
        (entry,),
    )
    with pytest.raises(ValueError, match=error):
        lifecycle._copy_verified_bundle(verified, tmp_path / "installed")
    with pytest.raises(ValueError, match=error):
        lifecycle._request_artifact_files(tmp_path, {"files": [entry]})

    synthetic_link = tmp_path / "synthetic-link"
    synthetic_link.write_bytes(b"not dereferenced")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == synthetic_link or original_is_symlink(path),
    )
    with pytest.raises(ValueError, match=error):
        artifact._bundle_files(tmp_path)


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
    source = _write_test_artifact(tmp_path / "release", b"version-one")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    executable = Path(result.executable)
    unrelated = root / "user-notes.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    _write_test_artifact(source.parent, b"version-two")
    next_plan = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    upgraded = upgrade(
        source,
        root,
        confirmation_token=next_plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    assert executable.read_bytes() == b"version-two"
    assert upgraded.backup is not None
    backup_executable = Path(upgraded.backup) / executable.name
    assert backup_executable.read_bytes() == b"version-one"
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
    assert str(backup_executable) in removed["removed"]
    assert unrelated.read_text(encoding="utf-8") == "preserve"
    assert root.is_dir()


@pytest.mark.adversarial
def test_uninstall_refuses_modified_or_escaping_manifest(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
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
    source = _write_test_artifact(tmp_path / "release", b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    result = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
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
    source = _write_test_artifact(tmp_path / "release", b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )

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
            identity_probe=_test_identity_probe,
        )
    assert not root.exists() or not any(root.iterdir())
    assert not list(security.rglob("*.key"))


@pytest.mark.adversarial
def test_missing_install_key_and_malformed_signed_values_fail_closed(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
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
    source = _write_test_artifact(tmp_path / "release", b"trusted")
    root = tmp_path / "installed"
    plan = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    installed = install(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
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


@pytest.mark.integration
def test_deferred_self_upgrade_completes_without_running_file_replacement(
    tmp_path: Path,
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"v1")
    root = tmp_path / "installed"
    initial = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    installed = install(
        source,
        root,
        confirmation_token=initial.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    _write_test_artifact(source.parent, b"v2")
    plan = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    launched: list[tuple[Path, Path, int]] = []
    deferred = upgrade(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
        running_executable=installed.executable,
        force_deferred=True,
        deferred_launcher=lambda executable, request, pid: launched.append(
            (executable, request, pid)
        ),
    )
    assert deferred.status == "DEFERRED"
    assert Path(installed.executable).read_bytes() == b"v1"
    assert not (root / ".b").exists()
    completed = complete_deferred_uninstall(
        launched[0][1], security_root=security, parent_checker=lambda _: False
    )
    assert completed["operation"] == "upgrade"
    assert Path(installed.executable).read_bytes() == b"v2"
    assert len(list((root / ".b").glob("*"))) == 1
    persisted = json.loads(Path(installed.manifest).read_text(encoding="utf-8"))
    assert persisted["artifact_manifest"]["sha256"] == hashlib.sha256(b"v2").hexdigest()


@pytest.mark.adversarial
def test_deferred_upgrade_failure_leaves_no_orphan_and_restores_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"v1")
    root = tmp_path / "installed"
    initial = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    installed = install(
        source,
        root,
        confirmation_token=initial.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    original_manifest = Path(installed.manifest).read_bytes()
    _write_test_artifact(source.parent, b"v2")
    plan = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    launched: list[tuple[Path, Path, int]] = []
    upgrade(
        source,
        root,
        confirmation_token=plan.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
        running_executable=installed.executable,
        force_deferred=True,
        deferred_launcher=lambda executable, request, pid: launched.append(
            (executable, request, pid)
        ),
    )

    def fail_manifest(*_: object, **__: object) -> None:
        raise OSError("injected deferred manifest failure")

    monkeypatch.setattr(lifecycle, "_write_manifest", fail_manifest)
    with pytest.raises(OSError, match="injected deferred"):
        complete_deferred_uninstall(
            launched[0][1], security_root=security, parent_checker=lambda _: False
        )
    assert Path(installed.executable).read_bytes() == b"v1"
    assert Path(installed.manifest).read_bytes() == original_manifest
    assert not (root / ".b").exists()
    assert not list((security / "staged-artifacts").glob("*"))


@pytest.mark.adversarial
def test_upgrade_token_is_source_bound_and_failure_restores_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    source = _write_test_artifact(tmp_path / "release", b"v1")
    root = tmp_path / "installed"
    initial = install_plan(
        source, root, approval_store=approvals, identity_probe=_test_identity_probe
    )
    installed = install(
        source,
        root,
        confirmation_token=initial.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    _write_test_artifact(source.parent, b"v2")
    stale = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )
    _write_test_artifact(source.parent, b"changed-after-approval")
    with pytest.raises(PermissionError, match="different operation"):
        upgrade(
            source,
            root,
            confirmation_token=stale.confirmation_token,
            approval_store=approvals,
            security_root=security,
            identity_probe=_test_identity_probe,
        )
    executable = Path(installed.executable)
    manifest = Path(installed.manifest)
    assert executable.read_bytes() == b"v1"
    original_manifest = manifest.read_bytes()
    valid = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
    )

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
            identity_probe=_test_identity_probe,
        )
    assert executable.read_bytes() == b"v1"
    assert manifest.read_bytes() == original_manifest
    assert not (root / ".b").exists()


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


@pytest.mark.integration
def test_application_distribution_beginner_services_are_portable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    application = Application()
    context = OperationContext(project_root=str(tmp_path), actor="test")
    requests = (
        OperationRequest(
            "distribution.discover", {"resource_path": str(tmp_path)}, context
        ),
        OperationRequest("distribution.doctor", {"fix": True}, context),
        OperationRequest(
            "distribution.setup.plan", {"integration_ids": ["manual"]}, context
        ),
        OperationRequest(
            "beginner.start",
            {"intent": "I want to build a portable tool", "project_name": "portable"},
            context,
        ),
        OperationRequest("system.version", {}, context),
    )
    results = [application.dispatch(request) for request in requests]
    assert all(result.ok for result in results)
    assert results[1].value["dry_run"] is True
    assert results[2].value["actions"][0]["integration_id"] == "manual"
    assert results[3].value["presentation"]["mode"] == "BEGINNER"
    assert results[4].value["product"] == "ARTIFEX"
    invalid_requests = (
        OperationRequest("distribution.discover", {"resource_path": 3}, context),
        OperationRequest("distribution.doctor", {"project_root": 3}, context),
        OperationRequest(
            "distribution.setup.apply",
            {"integration_ids": ["manual"], "confirmation_token": 3},
            context,
        ),
    )
    assert all(not application.dispatch(request).ok for request in invalid_requests)


@pytest.mark.unit
def test_application_lifecycle_routes_explicit_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Stub:
        def __init__(self, operation: str) -> None:
            self.operation = operation

        def to_dict(self) -> dict[str, str]:
            return {"operation": self.operation}

    monkeypatch.setattr(
        application_api,
        "install_plan",
        lambda source, root, **kwargs: Stub("install-plan"),
    )
    monkeypatch.setattr(
        application_api,
        "install",
        lambda source, root, confirmation_token, **kwargs: Stub("install"),
    )
    monkeypatch.setattr(
        application_api,
        "upgrade_plan",
        lambda source, root, **kwargs: Stub("upgrade-plan"),
    )
    monkeypatch.setattr(
        application_api,
        "upgrade",
        lambda source, root, confirmation_token, **kwargs: Stub("upgrade"),
    )
    monkeypatch.setattr(
        application_api,
        "uninstall_plan",
        lambda root, **kwargs: Stub("uninstall-plan"),
    )
    monkeypatch.setattr(
        application_api,
        "uninstall",
        lambda root, confirmation_token, **kwargs: {"operation": "uninstall"},
    )
    monkeypatch.setattr(
        application_api,
        "plan_integration_setup",
        lambda root, identifiers, issue_token=False: Stub("setup-plan"),
    )
    monkeypatch.setattr(
        application_api,
        "apply_integration_setup",
        lambda plan, confirmation_token: Stub("setup-apply"),
    )
    application = Application()
    context = OperationContext(project_root=str(tmp_path), actor="test")
    source = str(tmp_path / "artifact")
    root = str(tmp_path / "installed")
    operations = (
        ("distribution.install.plan", {"source_executable": source, "install_root": root}),
        (
            "distribution.install",
            {
                "source_executable": source,
                "install_root": root,
                "confirmation_token": "token",
            },
        ),
        ("distribution.upgrade.plan", {"source_executable": source, "install_root": root}),
        (
            "distribution.upgrade",
            {
                "source_executable": source,
                "install_root": root,
                "confirmation_token": "token",
            },
        ),
        ("distribution.uninstall.plan", {"install_root": root}),
        (
            "distribution.uninstall",
            {"install_root": root, "confirmation_token": "token"},
        ),
        (
            "distribution.setup.apply",
            {"integration_ids": ["manual"], "confirmation_token": "token"},
        ),
    )
    results = [
        application.dispatch(OperationRequest(name, arguments, context))
        for name, arguments in operations
    ]
    assert all(result.ok for result in results)
    assert [result.value["operation"] for result in results] == [
        "install-plan",
        "install",
        "upgrade-plan",
        "upgrade",
        "uninstall-plan",
        "uninstall",
        "setup-apply",
    ]


@pytest.mark.integration
def test_public_distribution_lifecycle_owns_managed_service_transaction(
    tmp_path: Path,
) -> None:
    class Adapter:
        platform_id = "test-managed-service"

        def __init__(self) -> None:
            self.current: ServiceRegistrationManifest | None = None
            self.running = False

        def inspect(self, service_id: str) -> ServiceRegistrationObservation:
            if self.current is None:
                return ServiceRegistrationObservation(False)
            assert self.current.service_id == service_id
            return ServiceRegistrationObservation(
                True, self.current.manifest_sha256
            )

        def register(self, manifest: ServiceRegistrationManifest) -> None:
            self.current = manifest

        def replace(
            self,
            current: ServiceRegistrationManifest,
            desired: ServiceRegistrationManifest,
        ) -> None:
            assert self.current == current
            self.current = desired

        def unregister(self, manifest: ServiceRegistrationManifest) -> None:
            assert self.current == manifest
            self.current = None

        def start_and_wait(
            self,
            manifest: ServiceRegistrationManifest,
            *,
            timeout_seconds: float,
        ) -> None:
            del timeout_seconds
            assert self.current == manifest
            self.running = True

        def stop_and_wait(
            self,
            manifest: ServiceRegistrationManifest,
            *,
            timeout_seconds: float,
        ) -> None:
            del timeout_seconds
            assert self.current == manifest
            self.running = False

    adapter = Adapter()
    approvals = ApprovalStore(tmp_path / "approvals")
    security = tmp_path / "security"
    state_root = tmp_path / "service-state"
    source = _write_test_artifact(tmp_path / "release", b"v1")
    root = tmp_path / "installed"
    service_id = "qualified-runtime"

    install_decision = install_plan(
        source,
        root,
        approval_store=approvals,
        identity_probe=_test_identity_probe,
        managed_service=True,
        service_state_root=state_root,
        service_id=service_id,
        service_readiness_timeout_seconds=0.5,
    )
    installed = install(
        source,
        root,
        confirmation_token=install_decision.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
        managed_service=True,
        service_state_root=state_root,
        service_id=service_id,
        service_adapter=adapter,
        service_readiness_timeout_seconds=0.5,
    )
    assert adapter.running is True
    assert adapter.current is not None
    assert adapter.current.arguments[:2] == ("service", "serve")
    assert installed.service_registration is not None

    _write_test_artifact(source.parent, b"v2")
    upgrade_decision = upgrade_plan(
        source,
        root,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
        service_readiness_timeout_seconds=0.5,
    )
    upgraded = upgrade(
        source,
        root,
        confirmation_token=upgrade_decision.confirmation_token,
        approval_store=approvals,
        security_root=security,
        identity_probe=_test_identity_probe,
        force_deferred=False,
        service_adapter=adapter,
        service_readiness_timeout_seconds=0.5,
    )
    assert Path(upgraded.executable).read_bytes() == b"v2"
    assert adapter.running is True
    assert adapter.current is not None
    assert adapter.current.executable_sha256 == hashlib.sha256(b"v2").hexdigest()

    uninstall_decision = uninstall_plan(
        root,
        approval_store=approvals,
        security_root=security,
        service_readiness_timeout_seconds=0.5,
    )
    removed = uninstall(
        root,
        confirmation_token=uninstall_decision.confirmation_token,
        approval_store=approvals,
        security_root=security,
        force_deferred=False,
        service_adapter=adapter,
        service_readiness_timeout_seconds=0.5,
    )
    assert removed["status"] == "COMPLETE"
    assert adapter.current is None
    assert adapter.running is False
    assert not Path(installed.manifest).exists()


@pytest.mark.unit
def test_application_routes_managed_service_lifecycle_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Stub:
        def __init__(self, operation: str) -> None:
            self.operation = operation

        def to_dict(self) -> dict[str, str]:
            return {"operation": self.operation}

    captured: dict[str, dict[str, Any]] = {}

    def capture_install(
        source: str, root: str, confirmation_token: str | None, **kwargs: Any
    ) -> Stub:
        captured["install"] = {
            "source": source,
            "root": root,
            "confirmation_token": confirmation_token,
            **kwargs,
        }
        return Stub("install")

    def capture_upgrade(
        source: str, root: str, confirmation_token: str | None, **kwargs: Any
    ) -> Stub:
        captured["upgrade"] = {
            "source": source,
            "root": root,
            "confirmation_token": confirmation_token,
            **kwargs,
        }
        return Stub("upgrade")

    def capture_uninstall(
        root: str, confirmation_token: str | None, **kwargs: Any
    ) -> dict[str, str]:
        captured["uninstall"] = {
            "root": root,
            "confirmation_token": confirmation_token,
            **kwargs,
        }
        return {"operation": "uninstall"}

    monkeypatch.setattr(application_api, "install", capture_install)
    monkeypatch.setattr(application_api, "upgrade", capture_upgrade)
    monkeypatch.setattr(application_api, "uninstall", capture_uninstall)
    application = Application()
    context = OperationContext(project_root=str(tmp_path), actor="test")
    source = str(tmp_path / "artifact.exe")
    root = str(tmp_path / "installed")
    state_root = str(tmp_path / "service-state")
    common = {
        "source_executable": source,
        "install_root": root,
        "confirmation_token": "token",
        "managed_service": True,
        "service_state_root": state_root,
        "service_id": "qualified-runtime",
        "service_readiness_timeout_seconds": 17,
    }

    assert application.dispatch(
        OperationRequest("distribution.install", common, context)
    ).ok
    assert application.dispatch(
        OperationRequest("distribution.upgrade", common, context)
    ).ok
    assert application.dispatch(
        OperationRequest(
            "distribution.uninstall",
            {
                "install_root": root,
                "confirmation_token": "token",
                "managed_service": True,
                "service_id": "qualified-runtime",
                "service_readiness_timeout_seconds": 17,
            },
            context,
        )
    ).ok

    for operation in ("install", "upgrade"):
        assert captured[operation]["managed_service"] is True
        assert captured[operation]["service_state_root"] == state_root
        assert captured[operation]["service_id"] == "qualified-runtime"
        assert captured[operation]["service_readiness_timeout_seconds"] == 17.0
    assert captured["uninstall"]["managed_service"] is True
    assert captured["uninstall"]["service_id"] == "qualified-runtime"
    assert captured["uninstall"]["service_readiness_timeout_seconds"] == 17.0


@pytest.mark.unit
def test_cli_routes_managed_service_lifecycle_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emitted: list[tuple[str, dict[str, Any]]] = []

    def capture(
        operation: str,
        arguments: dict[str, Any] | None = None,
        *,
        project_root: str | None = None,
    ) -> None:
        del project_root
        emitted.append((operation, arguments or {}))

    monkeypatch.setattr(cli_module, "_emit", capture)
    runner = CliRunner()
    source = str(tmp_path / "artifact.exe")
    root = str(tmp_path / "installed")
    state_root = str(tmp_path / "service-state")
    commands = (
        [
            "install",
            "--apply",
            "--install-root",
            root,
            "--source-executable",
            source,
            "--managed-service",
            "--service-state-root",
            state_root,
            "--service-id",
            "qualified-runtime",
            "--service-readiness-timeout-seconds",
            "17",
        ],
        [
            "upgrade",
            "--apply",
            "--install-root",
            root,
            "--source-executable",
            source,
            "--managed-service",
            "--service-state-root",
            state_root,
            "--service-id",
            "qualified-runtime",
            "--service-readiness-timeout-seconds",
            "17",
        ],
        [
            "uninstall",
            "--apply",
            "--install-root",
            root,
            "--managed-service",
            "--service-id",
            "qualified-runtime",
            "--service-readiness-timeout-seconds",
            "17",
        ],
    )
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.stdout

    assert [operation for operation, _ in emitted] == [
        "distribution.install",
        "distribution.upgrade",
        "distribution.uninstall",
    ]
    for _, arguments in emitted:
        assert arguments["managed_service"] is True
        assert arguments["service_id"] == "qualified-runtime"
        assert arguments["service_readiness_timeout_seconds"] == 17
    assert emitted[0][1]["service_state_root"] == state_root
    assert emitted[1][1]["service_state_root"] == state_root


@pytest.mark.integration
def test_distribution_cli_routes_beginner_safe_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    runner = CliRunner()
    commands = (
        ["mode", "expert"],
        ["doctor", "--project-root", str(tmp_path), "--fix"],
        ["setup", "--project-root", str(tmp_path), "--integration", "manual"],
    )
    payloads: list[dict[str, Any]] = []
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.stdout
        payloads.append(json.loads(result.stdout))
    assert all(payload["ok"] is True for payload in payloads)
    assert payloads[0]["value"]["mode"] == "EXPERT"
    assert payloads[1]["value"]["dry_run"] is True
    assert payloads[2]["value"]["applied"] is False


@pytest.mark.unit
def test_lifecycle_cli_builds_explicit_plan_and_apply_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def capture(
        operation: str,
        arguments: dict[str, Any] | None = None,
        *,
        project_root: str | None = None,
    ) -> None:
        assert project_root is None
        calls.append((operation, arguments or {}))

    monkeypatch.setattr(cli_module, "_emit", capture)
    cli_module.install_command("installed", "release/artifex", False, None)
    cli_module.install_command("installed", "release/artifex", True, "install-token")
    cli_module.upgrade_command("installed", "release/artifex", False, None)
    cli_module.upgrade_command("installed", "release/artifex", True, "upgrade-token")
    cli_module.uninstall_command("installed", False, None)
    cli_module.uninstall_command("installed", True, "uninstall-token")
    assert [operation for operation, _ in calls] == [
        "distribution.install.plan",
        "distribution.install",
        "distribution.upgrade.plan",
        "distribution.upgrade",
        "distribution.uninstall.plan",
        "distribution.uninstall",
    ]
    assert calls[0][1]["confirmation_token"] is None
    assert "confirmation_token" not in calls[2][1]
    assert calls[3][1]["confirmation_token"] == "upgrade-token"


@pytest.mark.adversarial
def test_portable_artifact_schema_helpers_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError, match="not found"):
        create_artifact_manifest(missing)
    with pytest.raises(ValueError, match="inventory entry"):
        artifact._file_entries([{"path": "x", "kind": "unknown", "sha256": "0" * 64}])
    with pytest.raises(ValueError, match="symlink inventory"):
        artifact._file_entries(
            [
                {
                    "path": "x",
                    "kind": "symlink",
                    "target": "target",
                    "sha256": "0" * 64,
                }
            ]
        )
    monkeypatch.setattr(artifact.platform, "system", lambda: "Windows")
    with pytest.raises(ValueError, match="symlinks are unsupported on Windows"):
        artifact._file_entries(
            [
                {
                    "path": "runtime-link.bin",
                    "kind": "symlink",
                    "target": "_internal/runtime.bin",
                    "sha256": hashlib.sha256(b"_internal/runtime.bin").hexdigest(),
                }
            ]
        )

    def failed_run(*_: object, **__: object) -> object:
        raise OSError("cannot execute")

    monkeypatch.setattr(artifact.subprocess, "run", failed_run)
    with pytest.raises(ValueError, match="identity probe failed"):
        artifact.probe_artifact_identity(tmp_path / "artifact", 1)

    class InvalidPayload:
        returncode = 0
        stdout = json.dumps({"ok": False})

    monkeypatch.setattr(
        artifact.subprocess, "run", lambda *args, **kwargs: InvalidPayload()
    )
    with pytest.raises(ValueError, match="successful ARTIFEX"):
        artifact.probe_artifact_identity(tmp_path / "artifact", 1)

    class MissingIdentity:
        returncode = 0
        stdout = json.dumps({"ok": True, "value": "not-an-object"})

    monkeypatch.setattr(
        artifact.subprocess, "run", lambda *args, **kwargs: MissingIdentity()
    )
    with pytest.raises(ValueError, match="identity metadata"):
        artifact.probe_artifact_identity(tmp_path / "artifact", 1)


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
    assert '"--onedir"' in build_script
    assert '"--contents-directory"' in build_script
    assert '"--smoke"' in build_script
    assert "create_artifact_manifest" in build_script
    assert "ubuntu-latest" in workflow
    assert "windows-latest" in workflow
    assert "macos-latest" in workflow
    assert "packaging/build.py --clean --smoke" in workflow
    assert workflow.count("fail-fast: false") == 2


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
