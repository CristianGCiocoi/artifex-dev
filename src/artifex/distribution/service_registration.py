"""Fail-closed, transactional registration of the ARTIFEX managed service.

This module owns only the installer-side registration record. Runtime process
state and runtime authority remain owned by the managed-service composition.
No operating-system adapter is selected implicitly while the supported
platform matrix is unresolved.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import locale
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, Protocol

SERVICE_REGISTRATION_SCHEMA = "artifex.service-registration/v1"
SERVICE_REGISTRATION_AUTHORITY = "ARTIFEX_INSTALLER_REGISTRATION"
SERVICE_REGISTRATION_MANIFEST_NAME = "service-registration.json"
WINDOWS_11_CORE_PLATFORM_ID = (
    "windows-11-24h2-or-25h2-x64-per-user-task-scheduler-v1"
)

_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_TASK_DESCRIPTION_PREFIX = "ARTIFEX-SERVICE-REGISTRATION-V1:"
_WINDOWS_11_25H2_PREFERRED_BUILD = 26200
_WINDOWS_11_24H2_BUILD = 26100
_DEFAULT_SERVICE_READINESS_SECONDS = 30.0

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SERVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_OPERATIONS = frozenset({"INSTALL", "UPGRADE", "UNINSTALL"})
_ACTIVATION_POLICIES = frozenset({"PLATFORM_MANAGED", "MANUAL"})


class ServiceRegistrationError(RuntimeError):
    """Base error for installer-owned service registration."""


class UnsupportedServicePlatformError(ServiceRegistrationError):
    """Raised when no explicitly qualified OS registration adapter exists."""


class ServiceRegistrationDriftError(ServiceRegistrationError):
    """Raised when the OS registration and deterministic record disagree."""


class ServiceRegistrationRollbackError(ServiceRegistrationError):
    """Raised when a compensating registration action also fails."""


@dataclass(frozen=True, slots=True)
class ServiceRegistrationSpec:
    """Platform-neutral desired registration for the managed runtime host."""

    service_id: str
    service_version: str
    executable: str
    executable_sha256: str
    arguments: tuple[str, ...]
    working_directory: str
    state_root: str
    activation_policy: str = "PLATFORM_MANAGED"

    def __post_init__(self) -> None:
        if not _SERVICE_ID_PATTERN.fullmatch(self.service_id):
            raise ValueError("service_id is invalid")
        if not self.service_version.strip():
            raise ValueError("service_version must be non-empty")
        if not _DIGEST_PATTERN.fullmatch(self.executable_sha256):
            raise ValueError("executable_sha256 must be a lowercase SHA-256 digest")
        if not self.arguments or any(not value.strip() for value in self.arguments):
            raise ValueError("arguments must contain non-empty values")
        if self.activation_policy not in _ACTIVATION_POLICIES:
            raise ValueError("activation_policy is unsupported")
        for value, label in (
            (self.executable, "executable"),
            (self.working_directory, "working_directory"),
            (self.state_root, "state_root"),
        ):
            if not Path(value).is_absolute():
                raise ValueError(f"{label} must be an absolute path")

    def manifest(self) -> ServiceRegistrationManifest:
        return ServiceRegistrationManifest(
            service_id=self.service_id,
            service_version=self.service_version,
            executable=str(Path(self.executable).resolve()),
            executable_sha256=self.executable_sha256,
            arguments=self.arguments,
            working_directory=str(Path(self.working_directory).resolve()),
            state_root=str(Path(self.state_root).resolve()),
            activation_policy=self.activation_policy,
        )


@dataclass(frozen=True, slots=True)
class ServiceRegistrationManifest:
    """Deterministic, installer-owned service-registration artifact."""

    service_id: str
    service_version: str
    executable: str
    executable_sha256: str
    arguments: tuple[str, ...]
    working_directory: str
    state_root: str
    activation_policy: str

    def __post_init__(self) -> None:
        # Reuse the complete public validation contract.
        ServiceRegistrationSpec(
            service_id=self.service_id,
            service_version=self.service_version,
            executable=self.executable,
            executable_sha256=self.executable_sha256,
            arguments=self.arguments,
            working_directory=self.working_directory,
            state_root=self.state_root,
            activation_policy=self.activation_policy,
        )

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical(self._payload())).hexdigest()

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SERVICE_REGISTRATION_SCHEMA,
            "authority": SERVICE_REGISTRATION_AUTHORITY,
            "service_id": self.service_id,
            "service_version": self.service_version,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "arguments": list(self.arguments),
            "working_directory": self.working_directory,
            "state_root": self.state_root,
            "activation_policy": self.activation_policy,
            "frontend_lifecycle_authoritative": False,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self._payload()
        value["manifest_sha256"] = self.manifest_sha256
        return value

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict()) + b"\n"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ServiceRegistrationManifest:
        required = {
            "schema",
            "authority",
            "service_id",
            "service_version",
            "executable",
            "executable_sha256",
            "arguments",
            "working_directory",
            "state_root",
            "activation_policy",
            "frontend_lifecycle_authoritative",
            "manifest_sha256",
        }
        if set(value) != required:
            raise ValueError("service registration manifest fields are invalid")
        if value["schema"] != SERVICE_REGISTRATION_SCHEMA:
            raise ValueError("service registration manifest schema is unsupported")
        if value["authority"] != SERVICE_REGISTRATION_AUTHORITY:
            raise ValueError("service registration manifest authority is invalid")
        if value["frontend_lifecycle_authoritative"] is not False:
            raise ValueError("frontend lifecycle cannot own managed runtime lifetime")
        arguments = value["arguments"]
        if not isinstance(arguments, list) or any(not isinstance(item, str) for item in arguments):
            raise ValueError("service registration arguments are invalid")
        text_fields = (
            "service_id",
            "service_version",
            "executable",
            "executable_sha256",
            "working_directory",
            "state_root",
            "activation_policy",
        )
        if any(not isinstance(value[field], str) for field in text_fields):
            raise ValueError("service registration manifest values are invalid")
        manifest = cls(
            service_id=value["service_id"],
            service_version=value["service_version"],
            executable=value["executable"],
            executable_sha256=value["executable_sha256"],
            arguments=tuple(arguments),
            working_directory=value["working_directory"],
            state_root=value["state_root"],
            activation_policy=value["activation_policy"],
        )
        if value["manifest_sha256"] != manifest.manifest_sha256:
            raise ValueError("service registration manifest digest is invalid")
        return manifest


@dataclass(frozen=True, slots=True)
class ServiceRegistrationObservation:
    """Minimum independently observed OS registration identity."""

    registered: bool
    manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.registered:
            if self.manifest_sha256 is None or not _DIGEST_PATTERN.fullmatch(
                self.manifest_sha256
            ):
                raise ValueError("registered service observation requires a manifest digest")
        elif self.manifest_sha256 is not None:
            raise ValueError("absent service observation cannot carry a manifest digest")


class ServiceRegistrationAdapter(Protocol):
    """Explicit OS adapter boundary; mutation methods must be idempotent."""

    @property
    def platform_id(self) -> str: ...

    def inspect(self, service_id: str) -> ServiceRegistrationObservation: ...

    def register(self, manifest: ServiceRegistrationManifest) -> None: ...

    def replace(
        self,
        current: ServiceRegistrationManifest,
        desired: ServiceRegistrationManifest,
    ) -> None: ...

    def unregister(self, manifest: ServiceRegistrationManifest) -> None: ...

    def start_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None: ...

    def stop_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None: ...


class UnsupportedServiceRegistrationAdapter:
    """Fail-closed adapter used until a platform cell is explicitly qualified."""

    def __init__(self, platform_id: str) -> None:
        normalized = platform_id.strip()
        if not normalized:
            raise ValueError("platform_id must be non-empty")
        self._platform_id = normalized

    @property
    def platform_id(self) -> str:
        return self._platform_id

    def inspect(self, service_id: str) -> ServiceRegistrationObservation:
        del service_id
        self._unsupported()

    def register(self, manifest: ServiceRegistrationManifest) -> None:
        del manifest
        self._unsupported()

    def replace(
        self,
        current: ServiceRegistrationManifest,
        desired: ServiceRegistrationManifest,
    ) -> None:
        del current, desired
        self._unsupported()

    def unregister(self, manifest: ServiceRegistrationManifest) -> None:
        del manifest
        self._unsupported()

    def start_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None:
        del manifest, timeout_seconds
        self._unsupported()

    def stop_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None:
        del manifest, timeout_seconds
        self._unsupported()

    def _unsupported(self) -> Never:
        raise UnsupportedServicePlatformError(
            f"service registration adapter for {self.platform_id!r} is not qualified; "
            "an explicit supported-platform adapter is required"
        )


TaskCommandRunner = Callable[[tuple[str, ...], float], subprocess.CompletedProcess[Any]]
ServiceProbe = Callable[[Path], bool]


class WindowsTaskSchedulerRegistrationAdapter:
    """Authorized Windows 11 x64 per-user Task Scheduler adapter.

    Windows 11 25H2 is the preferred baseline; 24H2 remains an exact authorized
    cell. Selection fails closed for every other Windows build and architecture.
    """

    platform_id = WINDOWS_11_CORE_PLATFORM_ID

    def __init__(
        self,
        *,
        runner: TaskCommandRunner | None = None,
        user_sid: str | None = None,
        user_name: str | None = None,
        schtasks_executable: str | Path | None = None,
        whoami_executable: str | Path | None = None,
        readiness_probe: ServiceProbe | None = None,
        shutdown_probe: ServiceProbe | None = None,
    ) -> None:
        self._runner = runner or _run_task_command
        system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        self._schtasks = str(
            Path(schtasks_executable or system_root / "System32" / "schtasks.exe")
        )
        self._whoami = str(
            Path(whoami_executable or system_root / "System32" / "whoami.exe")
        )
        if user_sid is None or user_name is None:
            discovered_name, discovered_sid = self._discover_user_identity()
        else:
            discovered_name, discovered_sid = user_name, user_sid
        self._user_sid = user_sid or discovered_sid
        self._user_name = user_name or discovered_name
        if not re.fullmatch(r"S-1-(?:\d+-)+\d+", self._user_sid, flags=re.IGNORECASE):
            raise ValueError("current Windows user SID is invalid")
        if (
            not self._user_name
            or "\\" not in self._user_name
            or any(ord(character) < 32 for character in self._user_name)
        ):
            raise ValueError("current Windows user name is invalid")
        self._readiness_probe = readiness_probe or _default_readiness_probe
        self._shutdown_probe = shutdown_probe or _default_shutdown_probe

    def inspect(self, service_id: str) -> ServiceRegistrationObservation:
        if not _SERVICE_ID_PATTERN.fullmatch(service_id):
            raise ValueError("service_id is invalid")
        task_xml = self._query_task_xml(self._task_name(service_id))
        if task_xml is None:
            return ServiceRegistrationObservation(False)
        manifest = self._manifest_from_task(task_xml, service_id)
        return ServiceRegistrationObservation(True, manifest.manifest_sha256)

    def register(self, manifest: ServiceRegistrationManifest) -> None:
        self._assert_managed_service_manifest(manifest)
        observed = self.inspect(manifest.service_id)
        if observed.registered:
            if observed.manifest_sha256 == manifest.manifest_sha256:
                return
            raise ServiceRegistrationDriftError(
                "refusing to overwrite an existing Windows scheduled task"
            )
        self._create_task(manifest, replace=False)
        try:
            self._require_observation(manifest)
        except Exception as exc:
            try:
                self._checked(
                    (
                        self._schtasks,
                        "/Delete",
                        "/TN",
                        self._task_name(manifest.service_id),
                        "/F",
                    )
                )
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "Windows task registration verification failed and exact-new-task "
                    "compensation also failed"
                ) from rollback_exc
            raise exc

    def replace(
        self,
        current: ServiceRegistrationManifest,
        desired: ServiceRegistrationManifest,
    ) -> None:
        self._assert_managed_service_manifest(current)
        self._assert_managed_service_manifest(desired)
        if current.service_id != desired.service_id:
            raise ValueError("service replacement identity cannot change")
        self._require_observation(current)
        prior_xml = self._query_task_xml(self._task_name(current.service_id))
        if prior_xml is None:
            raise ServiceRegistrationDriftError(
                "Windows scheduled task disappeared before replacement"
            )
        self._create_task(desired, replace=True)
        try:
            self._require_observation(desired)
        except Exception as exc:
            try:
                self._create_task_xml(current.service_id, prior_xml, replace=True)
                self._require_observation(current)
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "Windows task replacement verification failed and prior task "
                    "restoration also failed"
                ) from rollback_exc
            raise exc

    def unregister(self, manifest: ServiceRegistrationManifest) -> None:
        self._assert_managed_service_manifest(manifest)
        observed = self.inspect(manifest.service_id)
        if not observed.registered:
            return
        if observed.manifest_sha256 != manifest.manifest_sha256:
            raise ServiceRegistrationDriftError(
                "refusing to delete a Windows scheduled task with different ownership"
            )
        if self._task_is_running(manifest.service_id):
            raise ServiceRegistrationError(
                "refusing to delete a Windows scheduled task while its program is running"
            )
        self._checked(
            (
                self._schtasks,
                "/Delete",
                "/TN",
                self._task_name(manifest.service_id),
                "/F",
            )
        )
        if self.inspect(manifest.service_id).registered:
            raise ServiceRegistrationError("Windows scheduled task deletion did not persist")

    def start_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None:
        self._require_observation(manifest)
        _validate_timeout(timeout_seconds)
        self._checked(
            (self._schtasks, "/Run", "/TN", self._task_name(manifest.service_id))
        )
        deadline = time.monotonic() + timeout_seconds
        state_root = Path(manifest.state_root)
        while time.monotonic() < deadline:
            if self._readiness_probe(state_root):
                return
            time.sleep(0.1)
        ended = self._runner(
            (self._schtasks, "/End", "/TN", self._task_name(manifest.service_id)),
            10.0,
        )
        if ended.returncode != 0:
            raise ServiceRegistrationRollbackError(
                f"managed service readiness timed out and forced stop failed: "
                f"{_bounded_detail(ended)}"
            )
        self._wait_until_stopped(manifest, timeout_seconds=min(timeout_seconds, 5.0))
        raise TimeoutError("managed service did not become ready before timeout")

    def stop_and_wait(
        self,
        manifest: ServiceRegistrationManifest,
        *,
        timeout_seconds: float,
    ) -> None:
        self._require_observation(manifest)
        _validate_timeout(timeout_seconds)
        state_root = Path(manifest.state_root)
        shutdown_requested = self._shutdown_probe(state_root)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if (
                shutdown_requested
                and not self._task_is_running(manifest.service_id)
                and not self._readiness_probe(state_root)
            ):
                return
            time.sleep(0.1)
        ended = self._runner(
            (self._schtasks, "/End", "/TN", self._task_name(manifest.service_id)),
            10.0,
        )
        if ended.returncode != 0:
            raise ServiceRegistrationError(
                f"failed to stop Windows scheduled task: {_bounded_detail(ended)}"
            )
        self._wait_until_stopped(manifest, timeout_seconds=min(timeout_seconds, 5.0))

    def _wait_until_stopped(
        self, manifest: ServiceRegistrationManifest, *, timeout_seconds: float
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        state_root = Path(manifest.state_root)
        while time.monotonic() < deadline:
            if (
                not self._task_is_running(manifest.service_id)
                and not self._readiness_probe(state_root)
            ):
                return
            time.sleep(0.1)
        raise TimeoutError("managed service program did not stop before timeout")

    def _task_is_running(self, service_id: str) -> bool:
        result = self._runner(
            (
                self._schtasks,
                "/Query",
                "/TN",
                self._task_name(service_id),
                "/FO",
                "CSV",
                "/V",
                "/NH",
            ),
            15.0,
        )
        if result.returncode != 0:
            raise ServiceRegistrationError(
                f"cannot observe Windows scheduled task state: {_bounded_detail(result)}"
            )
        rows = tuple(csv.reader(io.StringIO(_command_text(result.stdout))))
        if len(rows) != 1 or len(rows[0]) < 3:
            raise ServiceRegistrationError("Windows scheduled task state is unreadable")
        return rows[0][2].strip().casefold() == "running"

    def _discover_user_identity(self) -> tuple[str, str]:
        result = self._checked((self._whoami, "/user", "/fo", "csv", "/nh"))
        rows = tuple(csv.reader(io.StringIO(_command_text(result.stdout))))
        if len(rows) != 1 or len(rows[0]) < 2:
            raise UnsupportedServicePlatformError(
                "cannot determine current Windows user identity"
            )
        return rows[0][0].strip(), rows[0][1].strip()

    def _task_name(self, service_id: str) -> str:
        sid_hash = hashlib.sha256(self._user_sid.upper().encode("ascii")).hexdigest()[:16]
        return rf"\ARTIFEX-{sid_hash}-{service_id}"

    def _query_task_xml(self, task_name: str) -> bytes | None:
        result = self._runner(
            (self._schtasks, "/Query", "/TN", task_name, "/XML"), 15.0
        )
        if result.returncode == 0:
            rendered = _command_text(result.stdout, xml=True).lstrip("\ufeff")
            rendered = re.sub(
                r"encoding=([\"'])utf-16\1",
                'encoding="utf-8"',
                rendered,
                count=1,
                flags=re.IGNORECASE,
            )
            return rendered.encode("utf-8")
        listing = self._runner(
            (self._schtasks, "/Query", "/FO", "CSV", "/NH"), 15.0
        )
        if listing.returncode != 0:
            raise ServiceRegistrationError(
                f"cannot inspect Windows scheduled tasks: {_bounded_detail(listing)}"
            )
        names = {
            row[0].strip().casefold()
            for row in csv.reader(io.StringIO(_command_text(listing.stdout)))
            if row
        }
        if task_name.casefold() in names:
            raise ServiceRegistrationError(
                "Windows scheduled task exists but its definition is unreadable"
            )
        return None

    def _create_task(
        self, manifest: ServiceRegistrationManifest, *, replace: bool
    ) -> None:
        self._create_task_xml(
            manifest.service_id,
            self._task_xml(manifest),
            replace=replace,
        )

    def _create_task_xml(
        self, service_id: str, task_xml: bytes, *, replace: bool
    ) -> None:
        descriptor, name = tempfile.mkstemp(prefix="artifex-task-", suffix=".xml")
        task_file = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(task_xml)
                stream.flush()
                os.fsync(stream.fileno())
            command = [
                self._schtasks,
                "/Create",
                "/TN",
                self._task_name(service_id),
                "/XML",
                str(task_file),
            ]
            if replace:
                command.append("/F")
            self._checked(tuple(command))
        finally:
            task_file.unlink(missing_ok=True)

    def _task_xml(self, manifest: ServiceRegistrationManifest) -> bytes:
        ET.register_namespace("", _TASK_NAMESPACE)
        task = ET.Element(_task_tag("Task"), {"version": "1.4"})
        registration = ET.SubElement(task, _task_tag("RegistrationInfo"))
        ET.SubElement(registration, _task_tag("Description")).text = _task_description(
            manifest
        )
        ET.SubElement(registration, _task_tag("URI")).text = self._task_name(
            manifest.service_id
        )
        triggers = ET.SubElement(task, _task_tag("Triggers"))
        trigger = ET.SubElement(triggers, _task_tag("LogonTrigger"), {"id": "UserLogon"})
        ET.SubElement(trigger, _task_tag("UserId")).text = self._user_name
        principals = ET.SubElement(task, _task_tag("Principals"))
        principal = ET.SubElement(principals, _task_tag("Principal"), {"id": "Author"})
        ET.SubElement(principal, _task_tag("UserId")).text = self._user_sid
        ET.SubElement(principal, _task_tag("LogonType")).text = "InteractiveToken"
        settings = ET.SubElement(task, _task_tag("Settings"))
        for name, value in (
            ("DisallowStartIfOnBatteries", "false"),
            ("StopIfGoingOnBatteries", "false"),
            ("ExecutionTimeLimit", "PT0S"),
            ("MultipleInstancesPolicy", "IgnoreNew"),
            ("StartWhenAvailable", "true"),
        ):
            ET.SubElement(settings, _task_tag(name)).text = value
        restart = ET.SubElement(settings, _task_tag("RestartOnFailure"))
        ET.SubElement(restart, _task_tag("Interval")).text = "PT1M"
        ET.SubElement(restart, _task_tag("Count")).text = "3"
        idle = ET.SubElement(settings, _task_tag("IdleSettings"))
        ET.SubElement(idle, _task_tag("StopOnIdleEnd")).text = "true"
        ET.SubElement(idle, _task_tag("RestartOnIdle")).text = "false"
        ET.SubElement(settings, _task_tag("UseUnifiedSchedulingEngine")).text = "true"
        actions = ET.SubElement(task, _task_tag("Actions"), {"Context": "Author"})
        action = ET.SubElement(actions, _task_tag("Exec"))
        ET.SubElement(action, _task_tag("Command")).text = manifest.executable
        ET.SubElement(action, _task_tag("Arguments")).text = subprocess.list2cmdline(
            list(manifest.arguments)
        )
        ET.SubElement(action, _task_tag("WorkingDirectory")).text = manifest.working_directory
        return bytes(ET.tostring(task, encoding="utf-16", xml_declaration=True))

    def _manifest_from_task(
        self, task_xml: bytes, service_id: str
    ) -> ServiceRegistrationManifest:
        try:
            root = ET.fromstring(task_xml)
        except ET.ParseError as exc:
            raise ServiceRegistrationDriftError(
                "Windows scheduled task XML is invalid"
            ) from exc
        if _local_name(root.tag) != "Task":
            raise ServiceRegistrationDriftError("Windows scheduled task root is invalid")
        self._validate_exact_task_shape(root)
        manifest = _manifest_from_task_description(_required_task_text(root, "Description"))
        if manifest.service_id != service_id:
            raise ServiceRegistrationDriftError("Windows scheduled task service identity drifted")
        if _required_task_text(root, "URI").casefold() != self._task_name(
            service_id
        ).casefold():
            raise ServiceRegistrationDriftError(
                "Windows scheduled task registration URI drifted"
            )
        self._assert_managed_service_manifest(manifest)
        trigger = _required_task_element(root, "LogonTrigger")
        principal = _required_task_element(root, "Principal")
        _require_single_task_element(root, "Exec")
        expected = {
            "LogonType": "InteractiveToken",
            "Command": manifest.executable,
            "Arguments": subprocess.list2cmdline(list(manifest.arguments)),
            "WorkingDirectory": manifest.working_directory,
            "MultipleInstancesPolicy": "IgnoreNew",
            "DisallowStartIfOnBatteries": "false",
            "StopIfGoingOnBatteries": "false",
            "ExecutionTimeLimit": "PT0S",
            "StartWhenAvailable": "true",
            "UseUnifiedSchedulingEngine": "true",
            "StopOnIdleEnd": "true",
            "RestartOnIdle": "false",
        }
        for name, value in expected.items():
            observed = _required_task_text(root, name)
            if name in {"Command", "WorkingDirectory"}:
                matches = os.path.normcase(os.path.abspath(observed)) == os.path.normcase(
                    os.path.abspath(value)
                )
            else:
                matches = observed.casefold() == value.casefold()
            if not matches:
                raise ServiceRegistrationDriftError(
                    f"Windows scheduled task {name} does not match installer ownership"
                )
        principal_user = _required_child_text(principal, "UserId")
        trigger_user = _required_child_text(trigger, "UserId")
        if (
            principal_user.casefold() != self._user_sid.casefold()
            or trigger_user.casefold() != self._user_name.casefold()
        ):
            raise ServiceRegistrationDriftError(
                "Windows scheduled task principal or trigger user drifted"
            )
        if _required_task_text(root, "Count") != "3" or _required_task_text(
            root, "Interval"
        ) != "PT1M":
            raise ServiceRegistrationDriftError(
                "Windows scheduled task restart policy drifted"
            )
        return manifest

    def _validate_exact_task_shape(self, root: ET.Element) -> None:
        expected_children = {
            "RegistrationInfo",
            "Triggers",
            "Principals",
            "Settings",
            "Actions",
        }
        if root.attrib != {"version": "1.4"} or {
            _local_name(child.tag) for child in root
        } != expected_children or len(root) != len(expected_children):
            raise ServiceRegistrationDriftError(
                "Windows scheduled task contains an unexpected top-level definition"
            )

        exact_shapes: tuple[tuple[str, set[str], dict[str, str]], ...] = (
            ("RegistrationInfo", {"Description", "URI"}, {}),
            ("Triggers", {"LogonTrigger"}, {}),
            ("LogonTrigger", {"UserId"}, {"id": "UserLogon"}),
            ("Principals", {"Principal"}, {}),
            (
                "Principal",
                {"UserId", "LogonType"},
                {"id": "Author"},
            ),
            (
                "Settings",
                {
                    "MultipleInstancesPolicy",
                    "DisallowStartIfOnBatteries",
                    "StopIfGoingOnBatteries",
                    "StartWhenAvailable",
                    "ExecutionTimeLimit",
                    "RestartOnFailure",
                    "IdleSettings",
                    "UseUnifiedSchedulingEngine",
                },
                {},
            ),
            ("RestartOnFailure", {"Interval", "Count"}, {}),
            ("IdleSettings", {"StopOnIdleEnd", "RestartOnIdle"}, {}),
            ("Actions", {"Exec"}, {"Context": "Author"}),
            ("Exec", {"Command", "Arguments", "WorkingDirectory"}, {}),
        )
        for name, children, attributes in exact_shapes:
            elements = [element for element in root.iter() if _local_name(element.tag) == name]
            if len(elements) != 1:
                raise ServiceRegistrationDriftError(
                    f"Windows scheduled task requires exactly one {name}"
                )
            element = elements[0]
            if element.attrib != attributes or {
                _local_name(child.tag) for child in element
            } != children or len(element) != len(children):
                raise ServiceRegistrationDriftError(
                    f"Windows scheduled task {name} definition drifted"
                )

    def _assert_managed_service_manifest(
        self, manifest: ServiceRegistrationManifest
    ) -> None:
        if manifest.activation_policy != "PLATFORM_MANAGED":
            raise ValueError("Windows scheduled service requires PLATFORM_MANAGED activation")
        arguments = manifest.arguments
        if arguments[:2] != ("service", "serve"):
            raise ValueError("Windows scheduled service command must be 'service serve'")
        _require_option(arguments, "--state-root", manifest.state_root)
        _require_option(arguments, "--service-id", manifest.service_id)

    def _require_observation(self, manifest: ServiceRegistrationManifest) -> None:
        observed = self.inspect(manifest.service_id)
        if not observed.registered or observed.manifest_sha256 != manifest.manifest_sha256:
            raise ServiceRegistrationDriftError(
                "Windows scheduled task does not match the expected registration"
            )

    def _checked(self, command: tuple[str, ...]) -> subprocess.CompletedProcess[Any]:
        result = self._runner(command, 15.0)
        if result.returncode != 0:
            raise ServiceRegistrationError(
                f"Windows Task Scheduler operation failed: {_bounded_detail(result)}"
            )
        return result


def select_service_registration_adapter(
    platform_id: str | None = None,
) -> ServiceRegistrationAdapter:
    """Select only the Product-approved Windows 11 25H2/24H2 x64 Core cells."""

    requested = platform_id or WINDOWS_11_CORE_PLATFORM_ID
    if requested == WINDOWS_11_CORE_PLATFORM_ID and _is_qualified_windows_11_x64():
        return WindowsTaskSchedulerRegistrationAdapter()
    return UnsupportedServiceRegistrationAdapter(platform_id or sys.platform)


@dataclass(frozen=True, slots=True)
class ServiceRegistrationPlan:
    operation: str
    service_id: str
    platform_id: str
    current_manifest_sha256: str | None
    desired_manifest: ServiceRegistrationManifest | None
    no_op: bool

    def __post_init__(self) -> None:
        if self.operation not in _OPERATIONS:
            raise ValueError("service registration operation is unsupported")
        if not self.platform_id.strip():
            raise ValueError("platform_id must be non-empty")

    @property
    def desired_manifest_sha256(self) -> str | None:
        return (
            self.desired_manifest.manifest_sha256
            if self.desired_manifest is not None
            else None
        )

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical(self._payload())).hexdigest()

    def _payload(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "service_id": self.service_id,
            "platform_id": self.platform_id,
            "current_manifest_sha256": self.current_manifest_sha256,
            "desired_manifest_sha256": self.desired_manifest_sha256,
            "no_op": self.no_op,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self._payload()
        value["plan_sha256"] = self.plan_sha256
        value["desired_manifest"] = (
            self.desired_manifest.to_dict()
            if self.desired_manifest is not None
            else None
        )
        return value


@dataclass(frozen=True, slots=True)
class ServiceRegistrationResult:
    operation: str
    status: str
    service_id: str
    platform_id: str
    previous_manifest_sha256: str | None
    manifest_sha256: str | None
    manifest_path: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "operation": self.operation,
            "status": self.status,
            "service_id": self.service_id,
            "platform_id": self.platform_id,
            "previous_manifest_sha256": self.previous_manifest_sha256,
            "manifest_sha256": self.manifest_sha256,
            "manifest_path": self.manifest_path,
        }


class ServiceRegistrationManager:
    """Coordinate registration and its deterministic record as one transaction."""

    def __init__(
        self,
        manifest_path: str | Path,
        *,
        adapter: ServiceRegistrationAdapter | None = None,
        readiness_timeout_seconds: float = _DEFAULT_SERVICE_READINESS_SECONDS,
    ) -> None:
        path = Path(manifest_path).resolve()
        if path == Path(path.anchor):
            raise ValueError("refusing broad service registration manifest path")
        self.manifest_path = path
        self.adapter = adapter or select_service_registration_adapter()
        _validate_timeout(readiness_timeout_seconds)
        self.readiness_timeout_seconds = readiness_timeout_seconds

    def plan_install(self, spec: ServiceRegistrationSpec) -> ServiceRegistrationPlan:
        desired = spec.manifest()
        _verify_executable(desired)
        current = self._current(desired.service_id)
        if current is not None and current.manifest_sha256 != desired.manifest_sha256:
            raise FileExistsError("service is already registered; use upgrade")
        return self._plan("INSTALL", desired.service_id, current, desired)

    def plan_upgrade(
        self,
        spec: ServiceRegistrationSpec,
        *,
        allow_current_executable_transition: bool = False,
    ) -> ServiceRegistrationPlan:
        desired = spec.manifest()
        _verify_executable(desired)
        current = self._current(
            desired.service_id,
            verify_executable=not allow_current_executable_transition,
        )
        if current is None:
            raise FileNotFoundError("service registration is absent; use install")
        return self._plan("UPGRADE", desired.service_id, current, desired)

    def plan_uninstall(self, service_id: str) -> ServiceRegistrationPlan:
        if not _SERVICE_ID_PATTERN.fullmatch(service_id):
            raise ValueError("service_id is invalid")
        current = self._current(service_id)
        return self._plan("UNINSTALL", service_id, current, None)

    def install(self, plan: ServiceRegistrationPlan) -> ServiceRegistrationResult:
        self._require_operation(plan, "INSTALL")
        desired = self._required_desired(plan)
        _verify_executable(desired)
        current = self._current(plan.service_id)
        if current is not None:
            if current.manifest_sha256 == desired.manifest_sha256:
                self.adapter.start_and_wait(
                    current, timeout_seconds=self.readiness_timeout_seconds
                )
                return self._result(plan, current, current, "NOOP")
            raise ServiceRegistrationDriftError("install plan no longer matches current state")
        if plan.current_manifest_sha256 is not None:
            raise ServiceRegistrationDriftError("install plan was not bound to an absent state")
        try:
            self.adapter.register(desired)
            _write_manifest(self.manifest_path, desired)
            self.adapter.start_and_wait(
                desired, timeout_seconds=self.readiness_timeout_seconds
            )
        except Exception as exc:
            try:
                self.adapter.unregister(desired)
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "service install failed and registration rollback also failed"
                ) from rollback_exc
            self.manifest_path.unlink(missing_ok=True)
            raise exc
        return self._result(plan, None, desired, "APPLIED")

    def upgrade(
        self,
        plan: ServiceRegistrationPlan,
        *,
        allow_current_executable_transition: bool = False,
        service_already_stopped: bool = False,
    ) -> ServiceRegistrationResult:
        self._require_operation(plan, "UPGRADE")
        desired = self._required_desired(plan)
        _verify_executable(desired)
        current = self._current(
            plan.service_id,
            verify_executable=not allow_current_executable_transition,
        )
        if current is None:
            raise ServiceRegistrationDriftError("upgrade plan no longer has a current state")
        if current.manifest_sha256 == desired.manifest_sha256:
            self.adapter.start_and_wait(
                current, timeout_seconds=self.readiness_timeout_seconds
            )
            return self._result(plan, current, current, "NOOP")
        if current.manifest_sha256 != plan.current_manifest_sha256:
            raise ServiceRegistrationDriftError("upgrade plan is stale")
        previous_record = self.manifest_path.read_bytes()
        stopped = service_already_stopped
        replaced = False
        try:
            if not service_already_stopped:
                self.adapter.stop_and_wait(
                    current, timeout_seconds=self.readiness_timeout_seconds
                )
                stopped = True
            self.adapter.replace(current, desired)
            replaced = True
            _write_manifest(self.manifest_path, desired)
            self.adapter.start_and_wait(
                desired, timeout_seconds=self.readiness_timeout_seconds
            )
        except Exception as exc:
            try:
                if replaced:
                    self.adapter.replace(desired, current)
                _restore_manifest(self.manifest_path, previous_record)
                if stopped:
                    self.adapter.start_and_wait(
                        current, timeout_seconds=self.readiness_timeout_seconds
                    )
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "service upgrade failed and transactional rollback also failed"
                ) from rollback_exc
            raise exc
        return self._result(plan, current, desired, "APPLIED")

    def uninstall(self, plan: ServiceRegistrationPlan) -> ServiceRegistrationResult:
        self._require_operation(plan, "UNINSTALL")
        current = self._current(plan.service_id)
        if current is None:
            if plan.current_manifest_sha256 is None:
                return self._result(plan, None, None, "NOOP")
            raise ServiceRegistrationDriftError("uninstall plan no longer has a current state")
        if current.manifest_sha256 != plan.current_manifest_sha256:
            raise ServiceRegistrationDriftError("uninstall plan is stale")
        previous_record = self.manifest_path.read_bytes()
        stopped = False
        try:
            self.adapter.stop_and_wait(
                current, timeout_seconds=self.readiness_timeout_seconds
            )
            stopped = True
            self.adapter.unregister(current)
            self.manifest_path.unlink()
        except Exception as exc:
            try:
                self.adapter.register(current)
                _restore_manifest(self.manifest_path, previous_record)
                if stopped:
                    self.adapter.start_and_wait(
                        current, timeout_seconds=self.readiness_timeout_seconds
                    )
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "service uninstall failed and transactional rollback also failed"
                ) from rollback_exc
            raise exc
        return self._result(plan, current, None, "APPLIED")

    def _current(
        self, service_id: str, *, verify_executable: bool = True
    ) -> ServiceRegistrationManifest | None:
        current = _read_manifest(self.manifest_path)
        observation = self.adapter.inspect(service_id)
        if current is None:
            if observation.registered:
                raise ServiceRegistrationDriftError(
                    "OS service is registered without an installer-owned manifest"
                )
            return None
        if current.service_id != service_id:
            raise ServiceRegistrationDriftError("service registration identity does not match")
        if not observation.registered:
            raise ServiceRegistrationDriftError(
                "installer-owned manifest exists but OS service is absent"
            )
        if observation.manifest_sha256 != current.manifest_sha256:
            raise ServiceRegistrationDriftError(
                "OS service registration does not match installer-owned manifest"
            )
        if verify_executable:
            _verify_executable(current)
        return current

    def _plan(
        self,
        operation: str,
        service_id: str,
        current: ServiceRegistrationManifest | None,
        desired: ServiceRegistrationManifest | None,
    ) -> ServiceRegistrationPlan:
        desired_digest = desired.manifest_sha256 if desired is not None else None
        current_digest = current.manifest_sha256 if current is not None else None
        return ServiceRegistrationPlan(
            operation=operation,
            service_id=service_id,
            platform_id=self.adapter.platform_id,
            current_manifest_sha256=current_digest,
            desired_manifest=desired,
            no_op=(
                current_digest == desired_digest
                if desired is not None
                else current_digest is None
            ),
        )

    def _require_operation(self, plan: ServiceRegistrationPlan, operation: str) -> None:
        if plan.operation != operation or plan.platform_id != self.adapter.platform_id:
            raise ValueError("service registration plan operation or platform is invalid")
        if plan.plan_sha256 != hashlib.sha256(_canonical(plan._payload())).hexdigest():
            raise ValueError("service registration plan digest is invalid")

    @staticmethod
    def _required_desired(plan: ServiceRegistrationPlan) -> ServiceRegistrationManifest:
        if plan.desired_manifest is None or plan.desired_manifest.service_id != plan.service_id:
            raise ValueError("service registration plan has no valid desired manifest")
        return plan.desired_manifest

    def _result(
        self,
        plan: ServiceRegistrationPlan,
        previous: ServiceRegistrationManifest | None,
        current: ServiceRegistrationManifest | None,
        status: str,
    ) -> ServiceRegistrationResult:
        return ServiceRegistrationResult(
            operation=plan.operation,
            status=status,
            service_id=plan.service_id,
            platform_id=self.adapter.platform_id,
            previous_manifest_sha256=(
                previous.manifest_sha256 if previous is not None else None
            ),
            manifest_sha256=current.manifest_sha256 if current is not None else None,
            manifest_path=str(self.manifest_path),
        )


def _read_manifest(path: Path) -> ServiceRegistrationManifest | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ServiceRegistrationDriftError("service registration manifest path is unsafe")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceRegistrationDriftError("service registration manifest is corrupt") from exc
    if not isinstance(raw, dict):
        raise ServiceRegistrationDriftError("service registration manifest is invalid")
    try:
        return ServiceRegistrationManifest.from_dict(raw)
    except ValueError as exc:
        raise ServiceRegistrationDriftError(str(exc)) from exc


def _write_manifest(path: Path, manifest: ServiceRegistrationManifest) -> None:
    _write_bytes_atomic(path, manifest.canonical_bytes())


def _write_bytes_atomic(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_manifest(path: Path, original: bytes) -> None:
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        current = None
    if current != original:
        _write_bytes_atomic(path, original)


def _verify_executable(manifest: ServiceRegistrationManifest) -> None:
    executable = Path(manifest.executable)
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("service executable must be a regular file")
    digest = hashlib.sha256()
    with executable.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != manifest.executable_sha256:
        raise ValueError("service executable SHA-256 does not match registration spec")


def _is_qualified_windows_11_x64() -> bool:
    if sys.platform != "win32" or platform.machine().casefold() not in {"amd64", "x86_64"}:
        return False
    try:
        version = sys.getwindowsversion()
        return getattr(version, "product_type", None) == 1 and version.build in (
            _WINDOWS_11_25H2_PREFERRED_BUILD,
            _WINDOWS_11_24H2_BUILD,
        )
    except AttributeError:
        return False


def _run_task_command(
    command: tuple[str, ...], timeout_seconds: float
) -> subprocess.CompletedProcess[bytes]:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
        creationflags=creation_flags,
    )


def _command_text(value: str | bytes, *, xml: bool = False) -> str:
    if isinstance(value, str):
        return value
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        return value.decode("utf-16")
    if value.startswith(b"\xef\xbb\xbf"):
        return value.decode("utf-8-sig")
    if xml:
        # ``schtasks /Query /XML`` can emit UTF-8 bytes while retaining the
        # task document's ``encoding="UTF-16"`` declaration.  The declaration
        # describes the stored task XML, not necessarily the redirected byte
        # stream.  Prefer byte-order evidence over that stale declaration.
        if value.startswith(b"<\x00?\x00x\x00m\x00l\x00"):
            return value.decode("utf-16-le")
        if value.startswith(b"\x00<\x00?\x00x\x00m\x00l"):
            return value.decode("utf-16-be")
        return value.decode("utf-8", errors="strict")
    encoding = "utf-8" if xml else locale.getpreferredencoding(False)
    return value.decode(encoding, errors="strict")


def _default_readiness_probe(state_root: Path) -> bool:
    try:
        from artifex.managed_service import LocalServiceClient

        status = LocalServiceClient(state_root, timeout_seconds=1.0).status()
    except Exception:
        return False
    value = status.get("value")
    return bool(
        status.get("ok") is True
        and isinstance(value, Mapping)
        and value.get("lifecycle_state") == "RUNNING"
    )


def _default_shutdown_probe(state_root: Path) -> bool:
    try:
        from artifex.managed_service import LocalServiceClient

        result = LocalServiceClient(state_root, timeout_seconds=2.0).shutdown()
    except Exception:
        return False
    return result.get("ok") is True


def _task_tag(name: str) -> str:
    return f"{{{_TASK_NAMESPACE}}}{name}"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _task_texts(root: ET.Element, name: str) -> tuple[str, ...]:
    return tuple(
        (element.text or "").strip()
        for element in root.iter()
        if _local_name(element.tag) == name
    )


def _required_task_text(root: ET.Element, name: str) -> str:
    values = _task_texts(root, name)
    if len(values) != 1 or not values[0]:
        raise ServiceRegistrationDriftError(
            f"Windows scheduled task requires exactly one {name} value"
        )
    return values[0]


def _required_task_element(root: ET.Element, name: str) -> ET.Element:
    values = tuple(element for element in root.iter() if _local_name(element.tag) == name)
    if len(values) != 1:
        raise ServiceRegistrationDriftError(
            f"Windows scheduled task requires exactly one {name} element"
        )
    return values[0]


def _required_child_text(element: ET.Element, name: str) -> str:
    values = tuple(
        (child.text or "").strip()
        for child in element
        if _local_name(child.tag) == name
    )
    if len(values) != 1 or not values[0]:
        raise ServiceRegistrationDriftError(
            f"Windows scheduled task requires exactly one {name} child value"
        )
    return values[0]


def _require_single_task_element(root: ET.Element, name: str) -> None:
    _required_task_element(root, name)


def _task_description(manifest: ServiceRegistrationManifest) -> str:
    encoded = base64.urlsafe_b64encode(manifest.canonical_bytes()).decode("ascii")
    return f"{_TASK_DESCRIPTION_PREFIX}{encoded}"


def _manifest_from_task_description(value: str) -> ServiceRegistrationManifest:
    if not value.startswith(_TASK_DESCRIPTION_PREFIX):
        raise ServiceRegistrationDriftError(
            "Windows scheduled task has no ARTIFEX ownership description"
        )
    try:
        decoded = base64.urlsafe_b64decode(value[len(_TASK_DESCRIPTION_PREFIX) :])
        raw = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ServiceRegistrationDriftError(
            "Windows scheduled task ownership description is invalid"
        ) from exc
    if not isinstance(raw, dict):
        raise ServiceRegistrationDriftError(
            "Windows scheduled task ownership manifest is invalid"
        )
    try:
        return ServiceRegistrationManifest.from_dict(raw)
    except ValueError as exc:
        raise ServiceRegistrationDriftError(str(exc)) from exc


def read_service_registration_manifest(
    path: str | Path,
) -> ServiceRegistrationManifest | None:
    """Read and authenticate an installer-owned registration manifest."""

    return _read_manifest(Path(path).resolve())


def _require_option(arguments: tuple[str, ...], option: str, expected: str) -> None:
    positions = tuple(index for index, value in enumerate(arguments) if value == option)
    if len(positions) != 1 or positions[0] + 1 >= len(arguments):
        raise ValueError(f"managed service command requires exactly one {option}")
    if os.path.normcase(os.path.abspath(arguments[positions[0] + 1])) != os.path.normcase(
        os.path.abspath(expected)
    ):
        raise ValueError(f"managed service command {option} does not match manifest")


def _validate_timeout(value: float) -> None:
    if not 0 < value <= 300:
        raise ValueError("service readiness timeout must be between 0 and 300 seconds")


def _bounded_detail(result: subprocess.CompletedProcess[Any]) -> str:
    raw = result.stderr or result.stdout
    detail = _command_text(raw) if raw else f"exit {result.returncode}"
    detail = detail.strip()
    return detail[:500]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


__all__ = [
    "SERVICE_REGISTRATION_AUTHORITY",
    "SERVICE_REGISTRATION_MANIFEST_NAME",
    "SERVICE_REGISTRATION_SCHEMA",
    "WINDOWS_11_CORE_PLATFORM_ID",
    "ServiceRegistrationAdapter",
    "ServiceRegistrationDriftError",
    "ServiceRegistrationError",
    "ServiceRegistrationManager",
    "ServiceRegistrationManifest",
    "ServiceRegistrationObservation",
    "ServiceRegistrationPlan",
    "ServiceRegistrationResult",
    "ServiceRegistrationRollbackError",
    "ServiceRegistrationSpec",
    "UnsupportedServicePlatformError",
    "UnsupportedServiceRegistrationAdapter",
    "WindowsTaskSchedulerRegistrationAdapter",
    "read_service_registration_manifest",
    "select_service_registration_adapter",
]
