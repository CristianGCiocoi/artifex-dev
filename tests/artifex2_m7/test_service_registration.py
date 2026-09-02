from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifex.distribution import (
    ServiceRegistrationDriftError,
    ServiceRegistrationError,
    ServiceRegistrationManager,
    ServiceRegistrationManifest,
    ServiceRegistrationObservation,
    ServiceRegistrationRollbackError,
    ServiceRegistrationSpec,
    UnsupportedServicePlatformError,
    WindowsTaskSchedulerRegistrationAdapter,
    select_service_registration_adapter,
    service_registration,
)
from artifex.distribution.service_registration import (
    SERVICE_DIAGNOSTIC_RECORD_NAME,
    SERVICE_READINESS_RECORD_NAME,
    _command_text,
)


class FakeTaskScheduler:
    def __init__(self) -> None:
        self.tasks: dict[str, str] = {}
        self.commands: list[tuple[str, ...]] = []
        self.running = False
        self.shutdown_success = True
        self.end_returncode = 0

    def run(
        self, command: tuple[str, ...], timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        self.commands.append(command)
        arguments = command[1:]
        if arguments == ("/user", "/fo", "csv", "/nh"):
            return self._result(command, 0, '"ARTIFEX\\operator","S-1-5-21-42"\n')
        if arguments[:1] == ("/Query",) and "/TN" in arguments and "/XML" in arguments:
            task_name = arguments[arguments.index("/TN") + 1]
            task_xml = self.tasks.get(task_name)
            if task_xml is None:
                return self._result(command, 1, stderr="task not found")
            return self._result(command, 0, task_xml)
        if arguments[:1] == ("/Query",) and "/TN" in arguments and "/V" in arguments:
            task_name = arguments[arguments.index("/TN") + 1]
            if task_name not in self.tasks:
                return self._result(command, 1, stderr="task not found")
            state = "Running" if self.running else "Ready"
            return self._result(command, 0, f'"{task_name}","N/A","{state}"\n')
        if arguments == ("/Query", "/FO", "CSV", "/NH"):
            listing = "".join(f'"{name}","Ready"\n' for name in self.tasks)
            return self._result(command, 0, listing)
        if arguments[:1] == ("/Create",):
            task_name = arguments[arguments.index("/TN") + 1]
            task_path = Path(arguments[arguments.index("/XML") + 1])
            replace = "/F" in arguments
            if task_name in self.tasks and not replace:
                return self._result(command, 1, stderr="task already exists")
            self.tasks[task_name] = task_path.read_text(encoding="utf-16")
            return self._result(command, 0)
        if arguments[:1] == ("/Delete",):
            task_name = arguments[arguments.index("/TN") + 1]
            self.tasks.pop(task_name, None)
            self.running = False
            return self._result(command, 0)
        if arguments[:1] == ("/Run",):
            self.running = True
            return self._result(command, 0)
        if arguments[:1] == ("/End",):
            if self.end_returncode:
                return self._result(command, self.end_returncode, stderr="end failed")
            self.running = False
            return self._result(command, 0)
        return self._result(command, 1, stderr="unexpected command")

    def shutdown(self, _: Path) -> bool:
        if self.shutdown_success:
            self.running = False
        return self.shutdown_success

    @staticmethod
    def _result(
        command: tuple[str, ...],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def _windows_adapter(
    scheduler: FakeTaskScheduler,
    *,
    readiness_probe: object | None = None,
) -> WindowsTaskSchedulerRegistrationAdapter:
    return WindowsTaskSchedulerRegistrationAdapter(
        runner=scheduler.run,
        user_sid="S-1-5-21-42",
        user_name=r"ARTIFEX\operator",
        schtasks_executable=r"C:\Windows\System32\schtasks.exe",
        whoami_executable=r"C:\Windows\System32\whoami.exe",
        readiness_probe=(
            readiness_probe if callable(readiness_probe) else lambda _: scheduler.running
        ),
        shutdown_probe=scheduler.shutdown,
    )


def test_windows_adapter_discovers_user_sid_from_native_byte_output() -> None:
    def runner(
        command: tuple[str, ...], timeout_seconds: float
    ) -> subprocess.CompletedProcess[bytes]:
        del timeout_seconds
        assert command[1:] == ("/user", "/fo", "csv", "/nh")
        return subprocess.CompletedProcess(
            command,
            0,
            b'"ARTIFEX\\operator","S-1-5-21-42"\r\n',
            b"",
        )

    adapter = WindowsTaskSchedulerRegistrationAdapter(
        runner=runner,
        schtasks_executable=r"C:\Windows\System32\schtasks.exe",
        whoami_executable=r"C:\Windows\System32\whoami.exe",
    )

    assert adapter._user_sid == "S-1-5-21-42"
    assert adapter._user_name == r"ARTIFEX\operator"


def test_windows_task_xml_uses_stream_encoding_over_stale_declaration() -> None:
    rendered = '<?xml version="1.0" encoding="UTF-16"?><Task></Task>\n'
    native_output = rendered.encode("utf-8")

    assert len(native_output) % 2 == 1
    assert _command_text(native_output, xml=True) == rendered


def test_windows_task_xml_still_accepts_bomless_utf16_stream() -> None:
    rendered = '<?xml version="1.0" encoding="UTF-16"?><Task></Task>'

    assert _command_text(rendered.encode("utf-16-le"), xml=True) == rendered


@pytest.mark.integration
def test_windows_start_retries_are_bounded_and_persist_readiness(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    starts = 0

    def transient_start(
        command: tuple[str, ...], timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal starts
        if command[1:2] == ("/Run",):
            starts += 1
            if starts == 1:
                return subprocess.CompletedProcess(command, 1, "", "transient start")
        return scheduler.run(command, timeout_seconds)

    adapter = WindowsTaskSchedulerRegistrationAdapter(
        runner=transient_start,
        user_sid="S-1-5-21-42",
        user_name=r"ARTIFEX\operator",
        schtasks_executable=r"C:\Windows\System32\schtasks.exe",
        whoami_executable=r"C:\Windows\System32\whoami.exe",
        readiness_probe=lambda _: scheduler.running,
        shutdown_probe=scheduler.shutdown,
    )
    manifest = _spec(tmp_path, "2.0.2", b"service-v2").manifest()
    Path(manifest.state_root).mkdir(parents=True)
    adapter.register(manifest)
    adapter.start_and_wait(manifest, timeout_seconds=2.0)

    assert starts == 2
    receipt = json.loads(
        (Path(manifest.state_root) / SERVICE_READINESS_RECORD_NAME).read_text(encoding="utf-8")
    )
    assert receipt["status"] == "READY"
    assert receipt["attempts"] == 2
    assert receipt["persistence_checked"] is True
    assert receipt["semantic_health_checked"] is True


@pytest.mark.adversarial
def test_windows_start_failure_preserves_bounded_diagnostics(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler, readiness_probe=lambda _: False)
    manifest = _spec(tmp_path, "2.0.2", b"service-v2").manifest()
    Path(manifest.state_root).mkdir(parents=True)
    adapter.register(manifest)

    with pytest.raises(TimeoutError, match="did not become ready"):
        adapter.start_and_wait(manifest, timeout_seconds=0.3)
    diagnostic = json.loads(
        (Path(manifest.state_root) / SERVICE_DIAGNOSTIC_RECORD_NAME).read_text(encoding="utf-8")
    )
    assert diagnostic["status"] == "FAILED"
    assert diagnostic["bounded"] is True
    assert 1 <= diagnostic["attempts"] <= 3
    assert scheduler.running is False


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

    def start_and_wait(
        self, manifest: ServiceRegistrationManifest, *, timeout_seconds: float
    ) -> None:
        del manifest, timeout_seconds

    def stop_and_wait(
        self, manifest: ServiceRegistrationManifest, *, timeout_seconds: float
    ) -> None:
        del manifest, timeout_seconds

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
        arguments=(
            "service",
            "serve",
            "--state-root",
            str((tmp_path / "state").resolve()),
            "--service-id",
            "artifex-runtime",
        ),
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
    assert (
        json.loads(manifest_path.read_text(encoding="utf-8"))["manifest_sha256"]
        == installed.manifest_sha256
    )

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
def test_healthy_service_without_persistent_registration_is_rolled_back(
    tmp_path: Path,
) -> None:
    class VanishingRegistrationAdapter(RecordingAdapter):
        def __init__(self) -> None:
            super().__init__()
            self.vanish_once = False

        def start_and_wait(
            self, manifest: ServiceRegistrationManifest, *, timeout_seconds: float
        ) -> None:
            del manifest, timeout_seconds
            self.vanish_once = True

        def inspect(self, service_id: str) -> ServiceRegistrationObservation:
            if self.vanish_once:
                self.vanish_once = False
                return ServiceRegistrationObservation(False)
            return super().inspect(service_id)

    adapter = VanishingRegistrationAdapter()
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(manifest_path, adapter=adapter)
    spec = _spec(tmp_path, "2.0.2", b"service-v2")

    with pytest.raises(ServiceRegistrationDriftError, match="did not persist"):
        manager.install(manager.plan_install(spec))
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


@pytest.mark.integration
def test_windows_task_scheduler_registration_is_owned_and_deterministic(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(
        manifest_path,
        adapter=adapter,
        readiness_timeout_seconds=0.5,
    )
    spec = _spec(tmp_path, "2.0.0", b"service-v1")

    installed = manager.install(manager.plan_install(spec))

    assert installed.status == "APPLIED"
    assert scheduler.running is True
    assert len(scheduler.tasks) == 1
    task_xml = next(iter(scheduler.tasks.values()))
    assert "InteractiveToken" in task_xml
    assert r"ARTIFEX\operator" in task_xml
    assert "LeastPrivilege" not in task_xml
    assert "UseUnifiedSchedulingEngine" in task_xml
    assert "RestartOnFailure" in task_xml
    assert "service serve" in task_xml
    assert str((tmp_path / "state").resolve()) in task_xml
    assert adapter.inspect("artifex-runtime").manifest_sha256 == (spec.manifest().manifest_sha256)
    create_commands = [command for command in scheduler.commands if "/Create" in command]
    assert len(create_commands) == 1
    assert "/F" not in create_commands[0]

    repeated = manager.install(manager.plan_install(spec))
    assert repeated.status == "NOOP"
    assert len([command for command in scheduler.commands if "/Create" in command]) == 1


@pytest.mark.integration
def test_windows_task_scheduler_upgrade_and_uninstall_are_bounded_and_idempotent(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    manager = ServiceRegistrationManager(
        tmp_path / "state" / "service-registration.json",
        adapter=_windows_adapter(scheduler),
        readiness_timeout_seconds=0.5,
    )
    initial = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(initial))

    upgraded = _spec(tmp_path, "2.1.0", b"service-v2")
    result = manager.upgrade(manager.plan_upgrade(upgraded))
    assert result.status == "APPLIED"
    replace_commands = [
        command for command in scheduler.commands if "/Create" in command and "/F" in command
    ]
    assert len(replace_commands) == 1
    assert scheduler.running is True

    removed = manager.uninstall(manager.plan_uninstall("artifex-runtime"))
    assert removed.status == "APPLIED"
    assert scheduler.tasks == {}
    assert scheduler.running is False
    assert manager.uninstall(manager.plan_uninstall("artifex-runtime")).status == "NOOP"


@pytest.mark.adversarial
def test_windows_task_scheduler_drift_blocks_overwrite_and_delete(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manager = ServiceRegistrationManager(
        tmp_path / "state" / "service-registration.json",
        adapter=adapter,
        readiness_timeout_seconds=0.5,
    )
    spec = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(spec))
    task_name = next(iter(scheduler.tasks))
    scheduler.tasks[task_name] = re.sub(
        r"(<Command>).*?(</Command>)",
        r"\1C:\\unowned\\service.exe\2",
        scheduler.tasks[task_name],
        count=1,
    )
    mutations_before = tuple(
        command
        for command in scheduler.commands
        if any(action in command for action in ("/Create", "/Delete"))
    )

    with pytest.raises(ServiceRegistrationDriftError, match="Command"):
        manager.plan_upgrade(_spec(tmp_path, "2.1.0", b"service-v2"))
    with pytest.raises(ServiceRegistrationDriftError, match="Command"):
        manager.plan_uninstall("artifex-runtime")

    mutations_after = tuple(
        command
        for command in scheduler.commands
        if any(action in command for action in ("/Create", "/Delete"))
    )
    assert mutations_after == mutations_before


@pytest.mark.adversarial
def test_windows_task_scheduler_registration_uri_drift_is_rejected(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    manager = ServiceRegistrationManager(
        tmp_path / "state" / "service-registration.json",
        adapter=_windows_adapter(scheduler),
        readiness_timeout_seconds=0.5,
    )
    spec = _spec(tmp_path, "2.0.0", b"service-v1")
    manager.install(manager.plan_install(spec))
    task_name = next(iter(scheduler.tasks))
    scheduler.tasks[task_name] = re.sub(
        r"(<URI>).*?(</URI>)",
        r"\1\\ARTIFEX-unowned\2",
        scheduler.tasks[task_name],
        count=1,
    )

    with pytest.raises(ServiceRegistrationDriftError, match="registration URI"):
        manager.plan_uninstall("artifex-runtime")


@pytest.mark.adversarial
def test_windows_task_scheduler_trigger_user_drift_is_rejected(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    adapter.register(manifest)
    task_name = next(iter(scheduler.tasks))
    scheduler.tasks[task_name] = re.sub(
        r"(<LogonTrigger[^>]*>.*?<UserId>).*?(</UserId>)",
        r"\1ARTIFEX\\unowned\2",
        scheduler.tasks[task_name],
        count=1,
        flags=re.DOTALL,
    )

    with pytest.raises(ServiceRegistrationDriftError, match="trigger user"):
        adapter.inspect(manifest.service_id)


@pytest.mark.adversarial
def test_windows_task_scheduler_elevated_run_level_is_rejected(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    adapter.register(manifest)
    task_name = next(iter(scheduler.tasks))
    scheduler.tasks[task_name] = scheduler.tasks[task_name].replace(
        "</Principal>", "<RunLevel>HighestAvailable</RunLevel></Principal>", 1
    )

    with pytest.raises(ServiceRegistrationDriftError, match="Principal definition"):
        adapter.inspect(manifest.service_id)


@pytest.mark.adversarial
def test_windows_task_scheduler_readiness_timeout_rolls_back_registration(
    tmp_path: Path,
) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler, readiness_probe=lambda _: False)
    manifest_path = tmp_path / "state" / "service-registration.json"
    manager = ServiceRegistrationManager(
        manifest_path,
        adapter=adapter,
        readiness_timeout_seconds=0.01,
    )

    with pytest.raises(TimeoutError, match="did not become ready"):
        manager.install(manager.plan_install(_spec(tmp_path, "2.0.0", b"service-v1")))

    assert scheduler.tasks == {}
    assert scheduler.running is False
    assert not manifest_path.exists()


@pytest.mark.adversarial
def test_endpoint_loss_cannot_substitute_for_program_termination(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    scheduler.shutdown_success = False
    adapter = _windows_adapter(scheduler, readiness_probe=lambda _: False)
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    adapter.register(manifest)
    scheduler.running = True

    adapter.stop_and_wait(manifest, timeout_seconds=0.01)

    assert scheduler.running is False
    assert any("/End" in command for command in scheduler.commands)


@pytest.mark.adversarial
def test_failed_forced_stop_blocks_registration_rollback(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    scheduler.end_returncode = 5
    manager = ServiceRegistrationManager(
        tmp_path / "state" / "service-registration.json",
        adapter=_windows_adapter(scheduler, readiness_probe=lambda _: False),
        readiness_timeout_seconds=0.01,
    )

    with pytest.raises(ServiceRegistrationRollbackError, match="rollback"):
        manager.install(manager.plan_install(_spec(tmp_path, "2.0.0", b"service-v1")))

    assert scheduler.running is True
    assert scheduler.tasks


@pytest.mark.adversarial
def test_augmented_task_xml_is_not_installer_owned(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    adapter.register(manifest)
    task_name = next(iter(scheduler.tasks))
    scheduler.tasks[task_name] = scheduler.tasks[task_name].replace(
        "</Actions>",
        "<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId>"
        "</ComHandler></Actions>",
    )

    with pytest.raises(ServiceRegistrationDriftError, match="Actions"):
        adapter.inspect(manifest.service_id)


@pytest.mark.adversarial
def test_running_task_cannot_be_unregistered(tmp_path: Path) -> None:
    scheduler = FakeTaskScheduler()
    adapter = _windows_adapter(scheduler)
    manifest = _spec(tmp_path, "2.0.0", b"service-v1").manifest()
    adapter.register(manifest)
    scheduler.running = True

    with pytest.raises(ServiceRegistrationError, match="while its program is running"):
        adapter.unregister(manifest)

    assert scheduler.tasks


@pytest.mark.parametrize("build", [26200, 26100])
def test_windows_platform_guard_accepts_each_authorized_build(
    build: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_registration.sys, "platform", "win32")
    monkeypatch.setattr(service_registration.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(
        service_registration.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(build=build, product_type=1),
        raising=False,
    )
    assert service_registration._is_qualified_windows_11_x64() is True


@pytest.mark.parametrize("build", [26099, 26101, 26199, 26201])
def test_windows_platform_guard_rejects_unqualified_builds(
    build: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_registration.sys, "platform", "win32")
    monkeypatch.setattr(service_registration.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(
        service_registration.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(build=build, product_type=1),
        raising=False,
    )
    assert service_registration._is_qualified_windows_11_x64() is False


def test_windows_platform_guard_rejects_server_product_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service_registration.sys, "platform", "win32")
    monkeypatch.setattr(service_registration.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(
        service_registration.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(build=26200, product_type=3),
        raising=False,
    )
    assert service_registration._is_qualified_windows_11_x64() is False
