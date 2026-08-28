"""Fail-closed, transactional registration of the ARTIFEX managed service.

This module owns only the installer-side registration record. Runtime process
state and runtime authority remain owned by the managed-service composition.
No operating-system adapter is selected implicitly while the supported
platform matrix is unresolved.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, Protocol

SERVICE_REGISTRATION_SCHEMA = "artifex.service-registration/v1"
SERVICE_REGISTRATION_AUTHORITY = "ARTIFEX_INSTALLER_REGISTRATION"
SERVICE_REGISTRATION_MANIFEST_NAME = "service-registration.json"

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

    def _unsupported(self) -> Never:
        raise UnsupportedServicePlatformError(
            f"service registration adapter for {self.platform_id!r} is not qualified; "
            "an explicit supported-platform adapter is required"
        )


def select_service_registration_adapter(
    platform_id: str | None = None,
) -> ServiceRegistrationAdapter:
    """Return a fail-closed adapter; no platform support is inferred from the host."""

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
    ) -> None:
        path = Path(manifest_path).resolve()
        if path == Path(path.anchor):
            raise ValueError("refusing broad service registration manifest path")
        self.manifest_path = path
        self.adapter = adapter or select_service_registration_adapter()

    def plan_install(self, spec: ServiceRegistrationSpec) -> ServiceRegistrationPlan:
        desired = spec.manifest()
        _verify_executable(desired)
        current = self._current(desired.service_id)
        if current is not None and current.manifest_sha256 != desired.manifest_sha256:
            raise FileExistsError("service is already registered; use upgrade")
        return self._plan("INSTALL", desired.service_id, current, desired)

    def plan_upgrade(self, spec: ServiceRegistrationSpec) -> ServiceRegistrationPlan:
        desired = spec.manifest()
        _verify_executable(desired)
        current = self._current(desired.service_id)
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
                return self._result(plan, current, current, "NOOP")
            raise ServiceRegistrationDriftError("install plan no longer matches current state")
        if plan.current_manifest_sha256 is not None:
            raise ServiceRegistrationDriftError("install plan was not bound to an absent state")
        try:
            self.adapter.register(desired)
            _write_manifest(self.manifest_path, desired)
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

    def upgrade(self, plan: ServiceRegistrationPlan) -> ServiceRegistrationResult:
        self._require_operation(plan, "UPGRADE")
        desired = self._required_desired(plan)
        _verify_executable(desired)
        current = self._current(plan.service_id)
        if current is None:
            raise ServiceRegistrationDriftError("upgrade plan no longer has a current state")
        if current.manifest_sha256 == desired.manifest_sha256:
            return self._result(plan, current, current, "NOOP")
        if current.manifest_sha256 != plan.current_manifest_sha256:
            raise ServiceRegistrationDriftError("upgrade plan is stale")
        previous_record = self.manifest_path.read_bytes()
        try:
            self.adapter.replace(current, desired)
            _write_manifest(self.manifest_path, desired)
        except Exception as exc:
            try:
                self.adapter.replace(desired, current)
                _restore_manifest(self.manifest_path, previous_record)
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
        try:
            self.adapter.unregister(current)
            self.manifest_path.unlink()
        except Exception as exc:
            try:
                self.adapter.register(current)
                _restore_manifest(self.manifest_path, previous_record)
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "service uninstall failed and transactional rollback also failed"
                ) from rollback_exc
            raise exc
        return self._result(plan, current, None, "APPLIED")

    def _current(self, service_id: str) -> ServiceRegistrationManifest | None:
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


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


__all__ = [
    "SERVICE_REGISTRATION_AUTHORITY",
    "SERVICE_REGISTRATION_MANIFEST_NAME",
    "SERVICE_REGISTRATION_SCHEMA",
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
    "select_service_registration_adapter",
]
