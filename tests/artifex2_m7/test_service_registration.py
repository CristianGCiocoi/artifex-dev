from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artifex.distribution import (
    ServiceRegistrationDriftError,
    ServiceRegistrationManager,
    ServiceRegistrationManifest,
    ServiceRegistrationObservation,
    ServiceRegistrationSpec,
    UnsupportedServicePlatformError,
    select_service_registration_adapter,
    service_registration,
)


class RecordingAdapter:
    platform_id = "test-explicit-adapter"

    def __init__(self) -> None:
        self.current: ServiceRegistrationManifest | None = None
        self.actions: list[tuple[str, str]] = []
        self.fail_after: str | None = None

    def inspect(self, service_id: str) -> ServiceRegistrationObservation:
        if self.current is None:
            return ServiceRegistrationObservation(False)
        assert self.current.service_id == service_id
        return ServiceRegistrationObservation(True, self.current.manifest_sha256)

    def register(self, manifest: ServiceRegistrationManifest) -> None:
        self.current = manifest
        self.actions.append(("register", manifest.manifest_sha256))
        self._fail("register")

    def replace(
        self,
        current: ServiceRegistrationManifest,
        desired: ServiceRegistrationManifest,
    ) -> None:
        assert self.current is not None
        assert self.current.manifest_sha256 == current.manifest_sha256
        self.current = desired
        self.actions.append(("replace", desired.manifest_sha256))
        self._fail("replace")

    def unregister(self, manifest: ServiceRegistrationManifest) -> None:
        assert self.current is not None
        assert self.current.manifest_sha256 == manifest.manifest_sha256
        self.current = None
        self.actions.append(("unregister", manifest.manifest_sha256))
        self._fail("unregister")

    def _fail(self, action: str) -> None:
        if self.fail_after == action:
            self.fail_after = None
            raise OSError(f"injected {action} failure")


def _spec(tmp_path: Path, version: str, content: bytes) -> ServiceRegistrationSpec:
    executable = tmp_path / f"artifex-service-{version}.bin"
    executable.write_bytes(content)
    return ServiceRegistrationSpec(
        service_id="artifex-runtime",
        service_version=version,
        executable=str(executable.resolve()),
        executable_sha256=hashlib.sha256(content).hexdigest(),
        arguments=("service", "run"),
        working_directory=str((tmp_path / "runtime").resolve()),
        state_root=str((tmp_path / "state").resolve()),
    )


@pytest.mark.unit
def test_registration_manifest_is_deterministic_and_frontend_independent(
    tmp_path: Path,
) -> None:
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    first = manifest.canonical_bytes()
    second = manifest.canonical_bytes()
    assert first == second
    value = json.loads(first)
    assert value["authority"] == "ARTIFEX_INSTALLER_REGISTRATION"
    assert value["frontend_lifecycle_authoritative"] is False
    assert value["manifest_sha256"] == manifest.manifest_sha256
    assert ServiceRegistrationManifest.from_dict(value) == manifest

    value["activation_policy"] = "MANUAL"
    with pytest.raises(ValueError, match="digest"):
        ServiceRegistrationManifest.from_dict(value)


@pytest.mark.adversarial
def test_unqualified_platform_adapter_fails_closed_without_writing(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(
        manifest_path,
        adapter=select_service_registration_adapter("unqualified-test-os"),
    )
    with pytest.raises(UnsupportedServicePlatformError, match="explicit supported-platform"):
        manager.plan_install(_spec(tmp_path, "2.0.0", b"service-v1"))
    assert not manifest_path.exists()


@pytest.mark.integration
def test_install_upgrade_uninstall_are_deterministic_and_idempotent(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    initial_spec = _spec(tmp_path, "2.0.0", b"service-v1")

    install_plan = manager.plan_install(initial_spec)
    assert install_plan.no_op is False
    assert install_plan.plan_sha256 == manager.plan_install(initial_spec).plan_sha256
    installed = manager.install(install_plan)
    assert installed.status == "APPLIED"
    assert json.loads(manifest_path.read_text(encoding="utf-8"))[
        "manifest_sha256"
    ] == installed.manifest_sha256

    repeat_install = manager.install(manager.plan_install(initial_spec))
    assert repeat_install.status == "NOOP"
    assert [action for action, _ in adapter.actions] == ["register"]

    upgraded_spec = _spec(tmp_path, "2.1.0", b"service-v2")
    upgraded = manager.upgrade(manager.plan_upgrade(upgraded_spec))
    assert upgraded.status == "APPLIED"
    assert upgraded.previous_manifest_sha256 == installed.manifest_sha256
    repeat_upgrade = manager.upgrade(manager.plan_upgrade(upgraded_spec))
    assert repeat_upgrade.status == "NOOP"

    removed = manager.uninstall(manager.plan_uninstall("artifex-runtime"))
    assert removed.status == "APPLIED"
    assert not manifest_path.exists()
    repeat_uninstall = manager.uninstall(manager.plan_uninstall("artifex-runtime"))
    assert repeat_uninstall.status == "NOOP"
    assert [action for action, _ in adapter.actions] == [
        "register",
        "replace",
        "unregister",
    ]


@pytest.mark.adversarial
def test_install_manifest_failure_rolls_back_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    plan = manager.plan_install(_spec(tmp_path, "2.0.0", b"service-v1"))

    def fail_write(*_: object) -> None:
        raise OSError("injected manifest failure")

    monkeypatch.setattr(service_registration, "_write_manifest", fail_write)
    with pytest.raises(OSError, match="injected manifest"):
        manager.install(plan)
    assert adapter.current is None
    assert not manifest_path.exists()
    assert [action for action, _ in adapter.actions] == ["register", "unregister"]


@pytest.mark.adversarial
def test_upgrade_manifest_failure_restores_registration_and_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    initial = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(initial))
    original_bytes = manifest_path.read_bytes()
    original_digest = initial.manifest().manifest_sha256
    plan = manager.plan_upgrade(_spec(tmp_path, "2.1.0", b"service-v2"))

    def fail_write(*_: object) -> None:
        raise OSError("injected manifest failure")

    monkeypatch.setattr(service_registration, "_write_manifest", fail_write)
    with pytest.raises(OSError, match="injected manifest"):
        manager.upgrade(plan)
    assert adapter.current is not None
    assert adapter.current.manifest_sha256 == original_digest
    assert manifest_path.read_bytes() == original_bytes
    assert [action for action, _ in adapter.actions] == [
        "register",
        "replace",
        "replace",
    ]


@pytest.mark.adversarial
def test_uninstall_adapter_failure_is_compensated_and_manifest_is_preserved(
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    spec = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(spec))
    original_bytes = manifest_path.read_bytes()
    adapter.fail_after = "unregister"

    with pytest.raises(OSError, match="injected unregister"):
        manager.uninstall(manager.plan_uninstall("artifex-runtime"))
    assert adapter.current == spec.manifest()
    assert manifest_path.read_bytes() == original_bytes
    assert [action for action, _ in adapter.actions] == [
        "register",
        "unregister",
        "register",
    ]


@pytest.mark.adversarial
def test_uninstall_record_failure_restores_registration_and_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    spec = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(spec))
    original_bytes = manifest_path.read_bytes()
    original_unlink = Path.unlink

    def delete_then_fail(path: Path, missing_ok: bool = False) -> None:
        original_unlink(path, missing_ok=missing_ok)
        if path == manifest_path:
            raise OSError("injected record removal failure")

    monkeypatch.setattr(Path, "unlink", delete_then_fail)
    with pytest.raises(OSError, match="record removal"):
        manager.uninstall(manager.plan_uninstall("artifex-runtime"))
    assert adapter.current == spec.manifest()
    assert manifest_path.read_bytes() == original_bytes


@pytest.mark.adversarial
def test_drift_and_executable_substitution_fail_before_mutation(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    spec = _spec(tmp_path, "2.0.0", b"service-v1")
    plan = manager.plan_install(spec)
    Path(spec.executable).write_bytes(b"substituted")
    # Both a new plan and an already-created plan reject substituted bytes.
    with pytest.raises(ValueError, match="SHA-256"):
        manager.plan_install(spec)
    with pytest.raises(ValueError, match="SHA-256"):
        manager.install(plan)
    Path(spec.executable).write_bytes(b"service-v1")
    manager.install(plan)
    adapter.current = None
    with pytest.raises(ServiceRegistrationDriftError, match="OS service is absent"):
        manager.plan_uninstall("artifex-runtime")
