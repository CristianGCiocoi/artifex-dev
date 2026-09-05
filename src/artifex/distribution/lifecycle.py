"""Authenticated, reversible install, upgrade, and self-uninstall lifecycle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Any

from artifex import __version__
from artifex.distribution.approvals import ApprovalStore, user_state_root
from artifex.distribution.artifact import (
    IdentityProbe,
    VerifiedArtifact,
    _supports_bundle_symlinks,
    _symlink_digest,
    _validate_symlink,
    verify_artifact,
)
from artifex.distribution.presentation import explain_decision, require_approval
from artifex.distribution.service_registration import (
    SERVICE_REGISTRATION_MANIFEST_NAME,
    ServiceRegistrationAdapter,
    ServiceRegistrationManager,
    ServiceRegistrationManifest,
    ServiceRegistrationPlan,
    ServiceRegistrationRollbackError,
    ServiceRegistrationSpec,
    read_service_registration_manifest,
)

MANIFEST_NAME = "artifex-install-manifest.json"
MANIFEST_SCHEMA_VERSION = "3.0"
_AUTH_ALGORITHM = "HMAC-SHA256"
_DEFERRED_REQUEST_TTL_SECONDS = 120
_DEFERRED_REQUEST_SCHEMA_VERSION = "2.0"
_DEFERRED_HELPER_PREFIX = ".artifex-lifecycle-"

DeferredLauncher = Callable[[Path, Path, int], None]
ParentChecker = Callable[[int], bool]
RunningProcessStopper = Callable[[Path], list[int]]


@dataclass(frozen=True, slots=True)
class InstallResult:
    operation: str
    install_root: str
    executable: str
    manifest: str
    backup: str | None = None
    status: str = "COMPLETE"
    deferred_request: str | None = None
    service_registration: Mapping[str, Any] | None = None
    state_migration: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "install_root": self.install_root,
            "executable": self.executable,
            "manifest": self.manifest,
            "backup": self.backup,
            "status": self.status,
            "deferred_request": self.deferred_request,
            "service_registration": (
                dict(self.service_registration)
                if self.service_registration is not None
                else None
            ),
            "state_migration": (
                dict(self.state_migration) if self.state_migration is not None else None
            ),
        }


def install_plan(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
    identity_probe: IdentityProbe | None = None,
    managed_service: bool = False,
    service_state_root: str | Path | None = None,
    service_id: str = "artifex-managed-service",
    service_readiness_timeout_seconds: float = 30.0,
) -> Any:
    root = Path(install_root).resolve()
    verified = verify_artifact(source_executable, identity_probe=identity_probe)
    return _install_decision(
        verified,
        root,
        approval_store=approval_store,
        issue_token=issue_token,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        service_readiness_timeout_seconds=service_readiness_timeout_seconds,
    )


def _install_decision(
    verified: VerifiedArtifact,
    root: Path,
    *,
    approval_store: ApprovalStore | None,
    issue_token: bool,
    managed_service: bool,
    service_state_root: str | Path | None,
    service_id: str,
    service_readiness_timeout_seconds: float,
) -> Any:
    source = verified.source
    _validate_service_readiness_timeout(service_readiness_timeout_seconds)
    state_root = _service_state_root(service_state_root) if managed_service else None
    effects = [f"copy {source.name} into {root}", f"write authenticated {MANIFEST_NAME}"]
    if managed_service:
        effects.extend(
            (
                "register one per-user Windows Task Scheduler managed service",
                f"start and verify managed service under {state_root}",
            )
        )
    return explain_decision(
        "install ARTIFEX",
        "REVERSIBLE",
        effects=tuple(effects),
        rollback=f"remove only newly created files under {root}",
        binding={
            "operation": "install",
            "install_root": str(root),
            "source_sha256": _sha256(source),
            "artifact_manifest_fingerprint": verified.manifest_fingerprint,
            "destination": _native_executable_name(),
            "manifest_schema": MANIFEST_SCHEMA_VERSION,
            "artifex_version": __version__,
            "managed_service": managed_service,
            "service_state_root": str(state_root) if state_root is not None else None,
            "service_id": service_id if managed_service else None,
            "service_readiness_timeout_seconds": (
                service_readiness_timeout_seconds if managed_service else None
            ),
        },
        approval_store=approval_store,
        issue_token=issue_token,
    )


def install(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    identity_probe: IdentityProbe | None = None,
    managed_service: bool = False,
    service_state_root: str | Path | None = None,
    service_id: str = "artifex-managed-service",
    service_adapter: ServiceRegistrationAdapter | None = None,
    service_readiness_timeout_seconds: float = 30.0,
) -> InstallResult:
    verified = verify_artifact(source_executable, identity_probe=identity_probe)
    root = Path(install_root).resolve()
    if root == Path(root.anchor) or len(root.parts) < 2:
        raise ValueError("refusing broad install root")
    decision = _install_decision(
        verified,
        root,
        approval_store=approval_store,
        issue_token=False,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        service_readiness_timeout_seconds=service_readiness_timeout_seconds,
    )
    destination = root / str(verified.manifest["artifact"])
    manifest_path = root / MANIFEST_NAME
    if manifest_path.exists() or any(
        _path_lexists(root / item["path"]) for item in verified.files
    ):
        raise FileExistsError("ARTIFEX is already installed; use upgrade")
    require_approval(decision, confirmation_token, approval_store=approval_store)
    root_created = not root.exists()
    root.mkdir(parents=True, exist_ok=True)
    key_path = _key_path(root, security_root)
    key: bytes | None = None
    service_result: Mapping[str, Any] | None = None
    service_spec = (
        _service_spec(
            destination,
            str(verified.manifest["sha256"]),
            service_state_root,
            service_id,
            __version__,
        )
        if managed_service
        else None
    )
    try:
        key = _create_install_key(key_path)
        _copy_verified_bundle(verified, root)
        manifest = _signed_manifest(
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "artifex_version": __version__,
                "install_root": str(root),
                "files": [dict(item) for item in verified.files],
                "backups": [],
                "artifact_manifest": dict(verified.manifest),
                "artifact_manifest_fingerprint": verified.manifest_fingerprint,
                "service_registration": (
                    service_spec.manifest().to_dict() if service_spec is not None else None
                ),
            },
            key,
        )
        _write_manifest(manifest_path, manifest)
        if managed_service:
            registration = _service_manager(
                root,
                adapter=service_adapter,
                readiness_timeout_seconds=service_readiness_timeout_seconds,
            )
            assert service_spec is not None
            service_result = registration.install(
                registration.plan_install(service_spec)
            ).to_dict()
    except Exception:
        manifest_path.unlink(missing_ok=True)
        _remove_manifest_paths(root, verified.files)
        if key is not None:
            key_path.unlink(missing_ok=True)
        if root_created:
            with suppress(OSError):
                root.rmdir()
        raise
    return InstallResult(
        "install",
        str(root),
        str(destination),
        str(manifest_path),
        service_registration=service_result,
    )


def upgrade_plan(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    issue_token: bool = True,
    identity_probe: IdentityProbe | None = None,
    managed_service: bool = False,
    service_state_root: str | Path | None = None,
    service_id: str = "artifex-managed-service",
    service_readiness_timeout_seconds: float = 30.0,
    allow_service_state_root_transition: bool = False,
) -> Any:
    verified = verify_artifact(source_executable, identity_probe=identity_probe)
    root, _, manifest, _ = _load_manifest(install_root, security_root=security_root)
    managed_service, service_state_root, service_id = _resolve_managed_service_request(
        manifest,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        allow_state_root_transition=allow_service_state_root_transition,
    )
    destination = _managed_executable(root, manifest)
    return _upgrade_decision(
        verified,
        root,
        manifest,
        destination,
        approval_store=approval_store,
        issue_token=issue_token,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        service_readiness_timeout_seconds=service_readiness_timeout_seconds,
    )


def _upgrade_decision(
    verified: VerifiedArtifact,
    root: Path,
    manifest: Mapping[str, Any],
    destination: Path,
    *,
    approval_store: ApprovalStore | None,
    issue_token: bool,
    managed_service: bool,
    service_state_root: str | Path | None,
    service_id: str,
    service_readiness_timeout_seconds: float,
) -> Any:
    source = verified.source
    _validate_service_readiness_timeout(service_readiness_timeout_seconds)
    effects = [f"replace manifest-owned file {destination.name}"]
    if managed_service:
        effects.append("stop, replace, restart and verify the per-user managed service")
    return explain_decision(
        "upgrade ARTIFEX",
        "REVERSIBLE",
        effects=tuple(effects),
        rollback="restore the authenticated pre-upgrade artifact and manifest",
        binding={
            "operation": "upgrade",
            "install_root": str(root),
            "source_sha256": _sha256(source),
            "artifact_manifest_fingerprint": verified.manifest_fingerprint,
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "destination": destination.name,
            "managed_service": managed_service,
            "service_state_root": (
                str(_service_state_root(service_state_root)) if managed_service else None
            ),
            "service_id": service_id if managed_service else None,
            "service_readiness_timeout_seconds": (
                service_readiness_timeout_seconds if managed_service else None
            ),
        },
        approval_store=approval_store,
        issue_token=issue_token,
    )


def upgrade(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    identity_probe: IdentityProbe | None = None,
    running_executable: str | Path | None = None,
    force_deferred: bool | None = None,
    deferred_launcher: DeferredLauncher | None = None,
    managed_service: bool = False,
    service_state_root: str | Path | None = None,
    service_id: str = "artifex-managed-service",
    service_adapter: ServiceRegistrationAdapter | None = None,
    service_readiness_timeout_seconds: float = 30.0,
    allow_service_state_root_transition: bool = False,
) -> InstallResult:
    verified = verify_artifact(source_executable, identity_probe=identity_probe)
    root, manifest_path, manifest, key = _load_manifest(
        install_root, security_root=security_root
    )
    managed_service, service_state_root, service_id = _resolve_managed_service_request(
        manifest,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        allow_state_root_transition=allow_service_state_root_transition,
    )
    _verify_managed_checksums(root, manifest)
    destination = _managed_executable(root, manifest)
    decision = _upgrade_decision(
        verified,
        root,
        manifest,
        destination,
        approval_store=approval_store,
        issue_token=False,
        managed_service=managed_service,
        service_state_root=service_state_root,
        service_id=service_id,
        service_readiness_timeout_seconds=service_readiness_timeout_seconds,
    )
    require_approval(decision, confirmation_token, approval_store=approval_store)
    current = (
        Path(running_executable).resolve()
        if running_executable is not None
        else _runtime_executable()
    )
    self_managed = _same_file(current, destination)
    defer = (os.name == "nt" and self_managed) if force_deferred is None else force_deferred
    if defer:
        if managed_service:
            raise ValueError(
                "managed-service upgrade must run from the new shipping candidate "
                "outside the active installation"
            )
        request_file = _prepare_deferred_upgrade(
            root,
            manifest,
            key,
            verified,
            security_root=security_root,
            parent_pid=os.getpid(),
        )
        launcher = deferred_launcher or _launch_deferred_helper
        try:
            launcher(current, request_file, os.getpid())
        except Exception:
            _discard_deferred_request_artifacts(
                request_file, security_root=security_root
            )
            raise
        return InstallResult(
            "upgrade",
            str(root),
            str(destination),
            str(manifest_path),
            status="DEFERRED",
            deferred_request=str(request_file),
        )
    registration: ServiceRegistrationManager | None = None
    prior_service: ServiceRegistrationManifest | None = None
    state_migration: Mapping[str, Any] | None = None
    if managed_service:
        registration = _service_manager(
            root,
            adapter=service_adapter,
            readiness_timeout_seconds=service_readiness_timeout_seconds,
        )
        prior_service = read_service_registration_manifest(
            root / SERVICE_REGISTRATION_MANIFEST_NAME
        )
        if prior_service is None or prior_service.service_id != service_id:
            raise ValueError("managed service registration is missing or has the wrong identity")
        registration.adapter.stop_and_wait(
            prior_service, timeout_seconds=service_readiness_timeout_seconds
        )
        desired_state = _service_state_root(service_state_root)
        prior_state = Path(prior_service.state_root).resolve()
        if desired_state != prior_state:
            try:
                from artifex.distribution.installed_state import migrate_legacy_state

                state_migration = migrate_legacy_state(
                    source=prior_state, target=desired_state
                ).to_dict()
            except Exception as exc:
                registration.adapter.start_and_wait(
                    prior_service, timeout_seconds=service_readiness_timeout_seconds
                )
                raise exc
    old_manifest_bytes = manifest_path.read_bytes()
    try:
        desired_registration = (
            _service_spec(
                destination,
                str(verified.manifest["sha256"]),
                service_state_root,
                service_id,
                __version__,
            ).manifest()
            if managed_service
            else None
        )
        backup = _perform_upgrade(
            root,
            manifest_path,
            manifest,
            key,
            verified,
            service_registration=desired_registration,
        )
    except Exception as exc:
        if registration is not None and prior_service is not None:
            try:
                registration.adapter.start_and_wait(
                    prior_service, timeout_seconds=service_readiness_timeout_seconds
                )
            except Exception as rollback_exc:
                raise ServiceRegistrationRollbackError(
                    "artifact upgrade failed and managed service restart also failed"
                ) from rollback_exc
        raise exc
    service_result: Mapping[str, Any] | None = None
    if registration is not None and prior_service is not None:
        assert desired_registration is not None
        desired_service = ServiceRegistrationSpec(
            service_id=desired_registration.service_id,
            service_version=desired_registration.service_version,
            executable=desired_registration.executable,
            executable_sha256=desired_registration.executable_sha256,
            arguments=desired_registration.arguments,
            working_directory=desired_registration.working_directory,
            state_root=desired_registration.state_root,
            activation_policy=desired_registration.activation_policy,
        )
        try:
            plan = registration.plan_upgrade(
                desired_service, allow_current_executable_transition=True
            )
            service_result = registration.upgrade(
                plan,
                allow_current_executable_transition=True,
                service_already_stopped=True,
            ).to_dict()
        except Exception:
            with suppress(Exception):
                registration.adapter.stop_and_wait(
                    prior_service, timeout_seconds=service_readiness_timeout_seconds
                )
            _rollback_completed_upgrade(
                root,
                manifest_path,
                old_manifest_bytes,
                manifest,
                backup,
            )
            registration.adapter.start_and_wait(
                prior_service, timeout_seconds=service_readiness_timeout_seconds
            )
            raise
    return InstallResult(
        "upgrade",
        str(root),
        str(destination),
        str(manifest_path),
        str(backup),
        service_registration=service_result,
        state_migration=state_migration,
    )


def _perform_upgrade(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    key: bytes,
    verified: VerifiedArtifact,
    *,
    service_registration: ServiceRegistrationManifest | None,
) -> Path:
    old_manifest = manifest_path.read_bytes()
    transaction = uuid.uuid4().hex[:16]
    backup = root / ".b" / transaction
    backup.mkdir(parents=True, exist_ok=False)
    backup_entries: list[dict[str, str]] = []
    old_entries = _manifest_entries(manifest, "files", required=True)
    new_entries = tuple(dict(item) for item in verified.files)
    mutation_started = False
    try:
        for item in _copy_order(old_entries):
            source = _safe_child(root, item["path"])
            target = _safe_child(backup, item["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_manifest_entry(
                source, target, item, source_root=root
            )
            backup_entry = dict(item)
            backup_entry["path"] = target.relative_to(root).as_posix()
            backup_entries.append(backup_entry)
        backup_entries.sort(key=lambda item: item["path"])
        if not all(
            _entry_matches(root, _safe_child(root, item["path"]), item)
            for item in backup_entries
        ):
            raise ValueError("upgrade backup bundle verification failed")
        mutation_started = True
        _copy_verified_bundle(verified, root)
        new_paths = {item["path"] for item in new_entries}
        for item in old_entries:
            if item["path"] not in new_paths:
                _safe_child(root, item["path"]).unlink()
        previous_backups = list(_manifest_entries(manifest, "backups", required=False))
        previous_backups.extend(backup_entries)
        updated = _signed_manifest(
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "artifex_version": __version__,
                "install_root": str(root),
                "files": list(new_entries),
                "backups": previous_backups,
                "artifact_manifest": dict(verified.manifest),
                "artifact_manifest_fingerprint": verified.manifest_fingerprint,
                "service_registration": (
                    service_registration.to_dict()
                    if service_registration is not None
                    else None
                ),
            },
            key,
        )
        _write_manifest(manifest_path, updated)
    except Exception:
        if mutation_started:
            _remove_manifest_paths(root, new_entries)
            backups_by_suffix = {
                Path(item["path"]).relative_to(backup.relative_to(root)).as_posix(): item
                for item in backup_entries
            }
            for old_item in _copy_order(old_entries):
                backup_item = backups_by_suffix[old_item["path"]]
                old_path = _safe_child(root, old_item["path"])
                old_path.parent.mkdir(parents=True, exist_ok=True)
                _copy_manifest_entry(
                    _safe_child(root, backup_item["path"]),
                    old_path,
                    old_item,
                    source_root=backup,
                )
            if not all(
                _entry_matches(root, _safe_child(root, item["path"]), item)
                for item in old_entries
            ):
                raise ValueError("upgrade rollback bundle verification failed") from None
        shutil.rmtree(backup, ignore_errors=True)
        with suppress(OSError):
            backup.parent.rmdir()
        _write_bytes_atomic(manifest_path, old_manifest)
        raise
    return backup


def _rollback_completed_upgrade(
    root: Path,
    manifest_path: Path,
    old_manifest_bytes: bytes,
    old_manifest: Mapping[str, Any],
    backup: Path,
) -> None:
    current = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(current, Mapping):
        raise ValueError("upgraded install manifest is invalid during rollback")
    new_entries = _manifest_entries(current, "files", required=True)
    old_entries = _manifest_entries(old_manifest, "files", required=True)
    _remove_manifest_paths(root, new_entries)
    for item in _copy_order(old_entries):
        source = _safe_child(backup, item["path"])
        destination = _safe_child(root, item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        _copy_manifest_entry(source, destination, item, source_root=backup)
    if not all(
        _entry_matches(root, _safe_child(root, item["path"]), item)
        for item in old_entries
    ):
        raise ValueError("managed-service upgrade rollback verification failed")
    _write_bytes_atomic(manifest_path, old_manifest_bytes)
    shutil.rmtree(backup, ignore_errors=True)
    with suppress(OSError):
        backup.parent.rmdir()


def uninstall_plan(
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    issue_token: bool = True,
    managed_service: bool = False,
    service_id: str = "artifex-managed-service",
    service_readiness_timeout_seconds: float = 30.0,
) -> Any:
    root, _, manifest, _ = _load_manifest(install_root, security_root=security_root)
    installed_service = _installed_service_registration(manifest)
    if installed_service is not None:
        if managed_service and service_id != installed_service.service_id:
            raise ValueError("managed service request does not match installed ownership")
        managed_service = True
        service_id = installed_service.service_id
    elif managed_service:
        raise ValueError("installation does not own a managed service")
    managed = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    _validate_service_readiness_timeout(service_readiness_timeout_seconds)
    effects = [f"remove authenticated manifest-owned file {path.name}" for path in managed]
    if managed_service:
        effects.insert(0, "stop and unregister the per-user managed service")
    return explain_decision(
        "uninstall ARTIFEX",
        "REVERSIBLE",
        effects=tuple(effects),
        rollback="reinstall the frozen artifact; unrelated files remain untouched",
        binding={
            "operation": "uninstall",
            "install_root": str(root),
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "managed_files": [path.name for path in managed],
            "managed_service": managed_service,
            "service_id": service_id if managed_service else None,
            "service_readiness_timeout_seconds": (
                service_readiness_timeout_seconds if managed_service else None
            ),
        },
        approval_store=approval_store,
        issue_token=issue_token,
    )


def uninstall(
    install_root: str | Path,
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    running_executable: str | Path | None = None,
    force_deferred: bool | None = None,
    deferred_launcher: DeferredLauncher | None = None,
    managed_service: bool = False,
    service_id: str = "artifex-managed-service",
    service_adapter: ServiceRegistrationAdapter | None = None,
    service_readiness_timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    root, manifest_path, manifest, key = _load_manifest(
        install_root, security_root=security_root
    )
    installed_service = _installed_service_registration(manifest)
    if installed_service is not None:
        if managed_service and service_id != installed_service.service_id:
            raise ValueError("managed service request does not match installed ownership")
        managed_service = True
        service_id = installed_service.service_id
    elif managed_service:
        raise ValueError("installation does not own a managed service")
    _verify_managed_checksums(root, manifest)
    decision = uninstall_plan(
        root,
        approval_store=approval_store,
        security_root=security_root,
        issue_token=False,
        managed_service=managed_service,
        service_id=service_id,
        service_readiness_timeout_seconds=service_readiness_timeout_seconds,
    )
    require_approval(decision, confirmation_token, approval_store=approval_store)
    targets = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    current = (
        Path(running_executable).resolve()
        if running_executable is not None
        else _runtime_executable()
    )
    self_managed = any(_same_file(current, target) for target in targets)
    defer = (os.name == "nt" and self_managed) if force_deferred is None else force_deferred
    registration: ServiceRegistrationManager | None = None
    prior_service: ServiceRegistrationManifest | None = None
    service_result: Mapping[str, Any] | None = None
    if managed_service:
        registration = _service_manager(
            root,
            adapter=service_adapter,
            readiness_timeout_seconds=service_readiness_timeout_seconds,
        )
        prior_service = read_service_registration_manifest(
            root / SERVICE_REGISTRATION_MANIFEST_NAME
        )
        if prior_service is None or prior_service.service_id != service_id:
            raise ValueError("managed service registration is missing or has the wrong identity")
        if not defer:
            service_result = registration.uninstall(
                registration.plan_uninstall(service_id)
            ).to_dict()
    if defer:
        request_file: Path | None = None
        try:
            request_file = _prepare_deferred_uninstall(
                root,
                manifest,
                key,
                security_root=security_root,
                parent_pid=os.getpid(),
                service_readiness_timeout_seconds=service_readiness_timeout_seconds,
            )
            launcher = deferred_launcher or _launch_deferred_helper
            launcher(current, request_file, os.getpid())
        except Exception as exc:
            if request_file is not None:
                _discard_deferred_request_artifacts(
                    request_file, security_root=security_root
                )
            raise exc
        assert request_file is not None
        return {
            "operation": "uninstall",
            "install_root": str(root),
            "status": "DEFERRED",
            "removed": [],
            "deferred_request": str(request_file),
            "service_registration": {
                "status": "DEFERRED_TO_AUTHENTICATED_HELPER"
            }
            if prior_service is not None
            else None,
        }
    try:
        removed = _perform_uninstall(
            root, manifest_path, manifest, security_root=security_root
        )
    except Exception:
        if registration is not None and prior_service is not None:
            _restore_service_registration(registration, prior_service)
        raise
    return {
        "operation": "uninstall",
        "install_root": str(root),
        "status": "COMPLETE",
        "removed": removed,
        "service_registration": service_result,
    }


def complete_deferred_uninstall(
    request_file: str | Path,
    *,
    security_root: str | Path | None = None,
    wait_timeout_seconds: float = 30.0,
    parent_checker: ParentChecker | None = None,
    service_adapter: ServiceRegistrationAdapter | None = None,
    running_process_stopper: RunningProcessStopper | None = None,
) -> dict[str, Any]:
    (
        request_path,
        request,
        root,
        helper_root,
        derived_security_root,
    ) = _read_deferred_request(request_file)
    if (
        security_root is not None
        and _security_root(security_root) != derived_security_root
    ):
        raise ValueError("deferred lifecycle request security root does not match its binding")
    security_root = derived_security_root
    _, manifest_path, manifest, key = _load_manifest(root, security_root=security_root)
    if not _verify_signed_value(request, key):
        raise ValueError("deferred uninstall request authentication failed")
    kind = request.get("kind")
    if kind not in {"ARTIFEX_DEFERRED_UNINSTALL", "ARTIFEX_DEFERRED_UPGRADE"}:
        raise ValueError("unexpected deferred lifecycle request kind")
    if request.get("schema_version") != _DEFERRED_REQUEST_SCHEMA_VERSION:
        raise ValueError("unsupported deferred lifecycle request schema")
    if request.get("manifest_fingerprint") != _manifest_fingerprint(manifest):
        raise ValueError("deferred uninstall request is stale")
    try:
        expires_at = datetime.fromisoformat(str(request["expires_at"])).astimezone(UTC)
        parent_pid = int(request["parent_pid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid deferred uninstall request identity") from exc
    if datetime.now(UTC) > expires_at:
        raise ValueError("deferred uninstall request expired")
    if request.get("request_id") != _helper_identity(helper_root, root):
        raise ValueError("deferred lifecycle request identity does not match its path")
    helper_root, _ = _validate_deferred_helper_bundle(request, root, manifest)
    checker = parent_checker or _pid_exists
    deadline = time.monotonic() + wait_timeout_seconds
    while checker(parent_pid):
        if time.monotonic() >= deadline:
            raise TimeoutError("parent process did not exit before lifecycle timeout")
        time.sleep(0.1)
    if datetime.now(UTC) > expires_at:
        raise ValueError("deferred uninstall request expired while awaiting parent exit")
    helper_root, _ = _validate_deferred_helper_bundle(request, root, manifest)
    _verify_managed_checksums(root, manifest)
    if kind == "ARTIFEX_DEFERRED_UNINSTALL":
        installed_service = _installed_service_registration(manifest)
        registration: ServiceRegistrationManager | None = None
        if installed_service is not None:
            timeout_value = request.get("service_readiness_timeout_seconds")
            if not isinstance(timeout_value, (int, float)):
                raise ValueError("deferred managed-service timeout is invalid")
            timeout_seconds = float(timeout_value)
            _validate_service_readiness_timeout(timeout_seconds)
            recorded = read_service_registration_manifest(
                root / SERVICE_REGISTRATION_MANIFEST_NAME
            )
            if recorded != installed_service:
                raise ValueError("deferred managed-service ownership is inconsistent")
            registration = _service_manager(
                root,
                adapter=service_adapter,
                readiness_timeout_seconds=timeout_seconds,
            )
            registration.uninstall(
                registration.plan_uninstall(installed_service.service_id)
            )
        stopped_processes: list[int] = []
        try:
            stopper = running_process_stopper or _stop_running_managed_executables
            stopped_processes = stopper(root)
            removed = _perform_uninstall(
                root, manifest_path, manifest, security_root=security_root
            )
        except Exception:
            if registration is not None and installed_service is not None:
                _restore_service_registration(registration, installed_service)
            raise
        result: dict[str, Any] = {
            "operation": "uninstall",
            "install_root": str(root),
            "status": "COMPLETE",
            "removed": removed,
            "stopped_processes": stopped_processes,
        }
    else:
        supplied_staged = Path(str(request.get("staged_artifact", "")))
        if _path_is_link_or_reparse_point(supplied_staged):
            raise ValueError("deferred upgrade staged artifact path is unsafe")
        staged = supplied_staged.resolve()
        artifact_manifest = request.get("artifact_manifest")
        artifact_fingerprint = request.get("artifact_manifest_fingerprint")
        stage_bundle = _validate_candidate_location(staged.parent, helper_root=helper_root)
        if (
            staged.parent != stage_bundle
            or not isinstance(artifact_manifest, Mapping)
            or not isinstance(artifact_fingerprint, str)
            or hashlib.sha256(_canonical(artifact_manifest)).hexdigest()
            != artifact_fingerprint
            or artifact_manifest.get("sha256") != _sha256(staged)
        ):
            raise ValueError("deferred upgrade staged artifact identity is invalid")
        file_entries = _request_artifact_files(stage_bundle, artifact_manifest)
        _validate_helper_inventory(stage_bundle, file_entries)
        verified = VerifiedArtifact(
            staged,
            stage_bundle,
            stage_bundle / "artifex-artifact.json",
            artifact_manifest,
            artifact_fingerprint,
            file_entries,
        )
        try:
            try:
                backup = _perform_upgrade(
                    root,
                    manifest_path,
                    manifest,
                    key,
                    verified,
                    service_registration=_installed_service_registration(manifest),
                )
            finally:
                _remove_candidate_bundle(
                    stage_bundle, file_entries, helper_root=helper_root
                )
        except Exception as operation_error:
            try:
                _schedule_helper_cleanup(
                    helper_root,
                    _manifest_entries(manifest, "files", required=True),
                    install_root=root,
                )
                _validate_protected_request_path(request_path, helper_root=helper_root)
                request_path.unlink(missing_ok=True)
            except Exception as cleanup_error:
                raise ExceptionGroup(
                    "deferred upgrade failed and helper cleanup also failed",
                    [operation_error, cleanup_error],
                ) from operation_error
            raise
        result = {
            "operation": "upgrade",
            "install_root": str(root),
            "status": "COMPLETE",
            "backup": str(backup),
        }
    helper_entries = _manifest_entries(manifest, "files", required=True)
    _schedule_helper_cleanup(helper_root, helper_entries, install_root=root)
    _validate_protected_request_path(request_path, helper_root=helper_root)
    request_path.unlink(missing_ok=True)
    return result


def _perform_uninstall(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    security_root: str | Path | None,
) -> list[str]:
    _verify_managed_checksums(root, manifest)
    file_entries = _manifest_entries(manifest, "files", required=True)
    backup_entries = _manifest_entries(manifest, "backups", required=False)
    targets = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    quarantined: list[tuple[Path, Path]] = []
    key_path = _key_path(root, security_root)
    key_quarantine = key_path.with_suffix(f".remove-{uuid.uuid4().hex}")
    key_moved = False
    try:
        for index, target in enumerate(targets):
            quarantine = root / f".artifex-remove-{uuid.uuid4().hex}-{index}"
            os.replace(target, quarantine)
            quarantined.append((target, quarantine))
        os.replace(key_path, key_quarantine)
        key_moved = True
        manifest_path.unlink()
    except Exception:
        if key_moved and key_quarantine.exists():
            os.replace(key_quarantine, key_path)
        for target, quarantine in reversed(quarantined):
            if quarantine.exists():
                os.replace(quarantine, target)
        raise
    key_quarantine.unlink(missing_ok=True)
    for _, quarantine in quarantined:
        quarantine.unlink(missing_ok=True)
    _remove_manifest_paths(root, [*file_entries, *backup_entries])
    return [str(target) for target, _ in quarantined]


def _prepare_deferred_uninstall(
    root: Path,
    manifest: dict[str, Any],
    key: bytes,
    *,
    security_root: str | Path | None,
    parent_pid: int,
    service_readiness_timeout_seconds: float,
) -> Path:
    operation_security_root = _security_root(security_root)
    helper_root, helper = _stage_deferred_helper_bundle(
        root,
        manifest,
    )
    request_path = _protected_request_path(helper_root)
    try:
        value = _signed_value(
            {
                "schema_version": _DEFERRED_REQUEST_SCHEMA_VERSION,
                "kind": "ARTIFEX_DEFERRED_UNINSTALL",
                "request_id": _helper_identity(helper_root, root),
                "install_root": str(root),
                "security_root": str(operation_security_root),
                "manifest_fingerprint": _manifest_fingerprint(manifest),
                "helper_bundle_root": str(helper_root),
                "helper_executable": str(helper),
                "parent_pid": parent_pid,
                "service_readiness_timeout_seconds": service_readiness_timeout_seconds,
                "expires_at": (
                    datetime.now(UTC) + timedelta(seconds=_DEFERRED_REQUEST_TTL_SECONDS)
                ).isoformat(),
            },
            key,
        )
        _write_manifest(request_path, value)
    except Exception:
        _schedule_helper_cleanup(
            helper_root,
            _manifest_entries(manifest, "files", required=True),
            install_root=root,
        )
        request_path.unlink(missing_ok=True)
        raise
    return request_path


def _prepare_deferred_upgrade(
    root: Path,
    manifest: dict[str, Any],
    key: bytes,
    verified: VerifiedArtifact,
    *,
    security_root: str | Path | None,
    parent_pid: int,
) -> Path:
    operation_security_root = _security_root(security_root)
    helper_root: Path | None = None
    staged_bundle: Path | None = None
    request_path: Path | None = None
    try:
        helper_root, helper = _stage_deferred_helper_bundle(
            root,
            manifest,
        )
        staged_bundle = helper_root / ".candidate"
        staged = staged_bundle / str(verified.manifest["artifact"])
        request_path = _protected_request_path(helper_root)
        staged_bundle.mkdir(parents=False, exist_ok=False)
        _copy_verified_bundle(verified, staged_bundle)
        _validate_helper_inventory(staged_bundle, tuple(verified.files))
        value = _signed_value(
            {
                "schema_version": _DEFERRED_REQUEST_SCHEMA_VERSION,
                "kind": "ARTIFEX_DEFERRED_UPGRADE",
                "request_id": _helper_identity(helper_root, root),
                "install_root": str(root),
                "security_root": str(operation_security_root),
                "manifest_fingerprint": _manifest_fingerprint(manifest),
                "helper_bundle_root": str(helper_root),
                "helper_executable": str(helper),
                "staged_artifact": str(staged),
                "artifact_manifest": dict(verified.manifest),
                "artifact_manifest_fingerprint": verified.manifest_fingerprint,
                "parent_pid": parent_pid,
                "expires_at": (
                    datetime.now(UTC) + timedelta(seconds=_DEFERRED_REQUEST_TTL_SECONDS)
                ).isoformat(),
            },
            key,
        )
        _write_manifest(request_path, value)
    except Exception:
        if staged_bundle is not None and staged_bundle.exists():
            _remove_candidate_bundle(
                staged_bundle,
                tuple(verified.files),
                helper_root=helper_root,
                require_complete=False,
            )
        if helper_root is not None:
            _schedule_helper_cleanup(
                helper_root,
                _manifest_entries(manifest, "files", required=True),
                install_root=root,
            )
        if request_path is not None:
            request_path.unlink(missing_ok=True)
        raise
    assert request_path is not None
    return request_path


def _stage_deferred_helper_bundle(
    root: Path,
    manifest: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Copy the authenticated installed bundle to an isolated helper directory.

    A Nuitka standalone executable cannot be relocated without its companion
    runtime files.  The signed install manifest is the only authority used to
    select files: unrelated install-root content is neither copied nor later
    removed by the helper.
    """

    _verify_managed_checksums(root, manifest)
    entries = _manifest_entries(manifest, "files", required=True)
    installed_executable = _managed_executable(root, manifest)
    # NSIS runs elevated from Program Files.  A sibling of the authenticated
    # installation inherits the same protected parent rather than crossing the
    # privilege boundary through per-user LocalAppData staging.
    helper_parent = root.parent
    if _path_is_link_or_reparse_point(helper_parent):
        raise ValueError("deferred lifecycle helper parent is unsafe")
    _validate_elevated_helper_parent(root)
    helper_root = helper_parent / f"{_helper_directory_prefix(root)}{uuid.uuid4().hex}"
    helper_root.mkdir(parents=False, exist_ok=False)
    try:
        for item in _copy_order(entries):
            source = _safe_child(root, item["path"])
            destination = _safe_child(helper_root, item["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_manifest_entry(source, destination, item, source_root=root)
        _validate_helper_inventory(helper_root, entries)
        executable_relative = installed_executable.relative_to(root).as_posix()
        helper = _safe_child(helper_root, executable_relative)
        if not helper.is_file() or _path_is_link_or_reparse_point(helper):
            raise ValueError("deferred lifecycle helper executable is invalid")
    except Exception:
        _schedule_helper_cleanup(helper_root, entries, install_root=root)
        raise
    return helper_root.resolve(), helper.resolve()


def _validate_deferred_helper_bundle(
    request: Mapping[str, Any],
    root: Path,
    manifest: Mapping[str, Any],
) -> tuple[Path, Path]:
    helper_root_value = request.get("helper_bundle_root")
    helper_value = request.get("helper_executable")
    if not isinstance(helper_root_value, str) or not isinstance(helper_value, str):
        raise ValueError("deferred lifecycle helper identity is missing")
    supplied_helper_root = Path(helper_root_value)
    supplied_helper = Path(helper_value)
    helper_root = _validate_helper_location(supplied_helper_root, install_root=root)
    if _path_is_link_or_reparse_point(supplied_helper):
        raise ValueError("deferred lifecycle helper executable path is unsafe")
    helper = supplied_helper.resolve()
    installed_executable = _managed_executable(root, manifest)
    executable_relative = installed_executable.relative_to(root).as_posix()
    expected_helper = _safe_child(helper_root, executable_relative)
    if helper != expected_helper.resolve() or _path_is_link_or_reparse_point(helper):
        raise ValueError("deferred lifecycle helper executable identity is invalid")
    entries = _manifest_entries(manifest, "files", required=True)
    excluded = (
        helper_root / ".candidate"
        if request.get("kind") == "ARTIFEX_DEFERRED_UPGRADE"
        else None
    )
    _validate_helper_inventory(helper_root, entries, excluded_directory=excluded)
    return helper_root, helper


def _helper_directory_prefix(install_root: Path) -> str:
    identity = os.path.normcase(str(install_root.resolve())).encode("utf-8")
    return f"{_DEFERRED_HELPER_PREFIX}{hashlib.sha256(identity).hexdigest()[:16]}-"


def _validate_helper_location(helper_root: Path, *, install_root: Path) -> Path:
    if _path_is_link_or_reparse_point(helper_root):
        raise ValueError("deferred lifecycle helper root is unsafe")
    root = install_root.resolve()
    helper_parent = root.parent
    if _path_is_link_or_reparse_point(helper_parent):
        raise ValueError("deferred lifecycle helper parent is unsafe")
    _validate_elevated_helper_parent(root)
    resolved = helper_root.resolve()
    prefix = _helper_directory_prefix(root)
    suffix = resolved.name.removeprefix(prefix)
    if (
        resolved.parent != helper_parent
        or not resolved.name.startswith(prefix)
        or len(suffix) != 32
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise ValueError("deferred lifecycle helper root is invalid")
    return resolved


def _validate_elevated_helper_parent(install_root: Path) -> None:
    if os.name != "nt" or "__compiled__" not in globals():
        return
    if not _is_windows_process_elevated():
        return
    protected_roots = {
        Path(value).resolve()
        for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")
        if (value := os.environ.get(name))
    }
    install_parent = install_root.resolve().parent
    if not protected_roots or not any(
        install_parent == protected or protected in install_parent.parents
        for protected in protected_roots
    ):
        raise PermissionError(
            "elevated deferred lifecycle staging requires a protected Program Files root"
        )


def _is_windows_process_elevated() -> bool:
    import ctypes

    windows_dlls = getattr(ctypes, "windll", None)
    if windows_dlls is None:
        raise OSError("Windows elevation state is unavailable")
    try:
        return bool(windows_dlls.shell32.IsUserAnAdmin())
    except (AttributeError, OSError) as exc:
        raise OSError("could not verify Windows elevation state") from exc


def _validate_candidate_location(
    candidate_root: Path, *, helper_root: Path
) -> Path:
    if _path_is_link_or_reparse_point(candidate_root):
        raise ValueError("deferred upgrade candidate root is unsafe")
    resolved = candidate_root.resolve()
    expected = helper_root / ".candidate"
    if resolved != expected:
        raise ValueError("deferred upgrade candidate is outside protected staging")
    return resolved


def _remove_candidate_bundle(
    candidate_root: Path,
    entries: tuple[Mapping[str, str], ...],
    *,
    helper_root: Path | None,
    require_complete: bool = True,
) -> None:
    if helper_root is None:
        raise ValueError("deferred upgrade helper root is unavailable")
    resolved = _validate_candidate_location(candidate_root, helper_root=helper_root)
    if not _path_lexists(resolved):
        return
    if require_complete:
        _validate_helper_inventory(resolved, entries)
    for item in entries:
        target = _safe_child(resolved, item["path"])
        if _path_lexists(target) and (
            _is_windows_reparse_point(target)
            or not _entry_matches(resolved, target, item)
        ):
            raise ValueError("deferred upgrade candidate changed before cleanup")
    _remove_manifest_paths(resolved, entries)
    resolved = _validate_candidate_location(resolved, helper_root=helper_root)
    resolved.rmdir()


def _validate_helper_inventory(
    helper_root: Path,
    entries: tuple[Mapping[str, str], ...],
    *,
    excluded_directory: Path | None = None,
) -> None:
    if not helper_root.is_dir() or _path_is_link_or_reparse_point(helper_root):
        raise ValueError("deferred lifecycle helper bundle is unavailable")
    expected_paths = {item["path"] for item in entries}
    expected_directories: set[str] = set()
    for relative_text in expected_paths:
        relative_path = Path(relative_text)
        expected_directories.update(
            parent.as_posix() for parent in relative_path.parents if parent != Path(".")
        )
    observed_paths: set[str] = set()
    observed_directories: set[str] = set()
    for current, directories, names in os.walk(
        helper_root, followlinks=False, onerror=_raise_helper_walk_error
    ):
        current_path = Path(current)
        if _is_windows_reparse_point(current_path):
            raise ValueError("deferred lifecycle helper contains a reparse point")
        for name in tuple(directories):
            path = current_path / name
            relative_name = path.relative_to(helper_root).as_posix()
            if _is_windows_reparse_point(path):
                directories.remove(name)
                raise ValueError("deferred lifecycle helper contains a reparse point")
            if excluded_directory is not None and path == excluded_directory:
                directories.remove(name)
                continue
            if path.is_symlink():
                directories.remove(name)
                observed_paths.add(relative_name)
            else:
                observed_directories.add(relative_name)
        for name in names:
            path = current_path / name
            if _is_windows_reparse_point(path):
                raise ValueError("deferred lifecycle helper contains a reparse point")
            if not path.is_file() and not path.is_symlink():
                raise ValueError("deferred lifecycle helper contains an unsupported file")
            observed_paths.add(path.relative_to(helper_root).as_posix())
    if observed_paths != expected_paths or observed_directories != expected_directories:
        raise ValueError("deferred lifecycle helper bundle inventory is invalid")
    if not all(
        _entry_matches(helper_root, _safe_child(helper_root, item["path"]), item)
        for item in entries
    ):
        raise ValueError("deferred lifecycle helper bundle checksum is invalid")


def _raise_helper_walk_error(error: OSError) -> None:
    raise error


def _helper_identity(helper_root: Path, install_root: Path) -> str:
    prefix = _helper_directory_prefix(install_root)
    if not helper_root.name.startswith(prefix):
        raise ValueError("deferred lifecycle helper identity is invalid")
    return helper_root.name.removeprefix(prefix)


def _protected_request_path(helper_root: Path) -> Path:
    return helper_root.parent / f"{helper_root.name}.request.json"


def _validate_protected_request_path(
    request_path: Path, *, helper_root: Path
) -> Path:
    if _path_is_link_or_reparse_point(request_path):
        raise ValueError("deferred lifecycle request path is unsafe")
    resolved = request_path.resolve()
    if resolved != _protected_request_path(helper_root):
        raise ValueError("deferred lifecycle request path is invalid")
    return resolved


def _read_deferred_request(
    request_file: str | Path,
) -> tuple[Path, dict[str, Any], Path, Path, Path]:
    supplied_request_path = Path(request_file)
    if _path_is_link_or_reparse_point(supplied_request_path):
        raise ValueError("deferred lifecycle request path is unsafe")
    try:
        request = json.loads(supplied_request_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid deferred uninstall request") from exc
    if not isinstance(request, dict):
        raise ValueError("invalid deferred uninstall request")
    install_root_value = request.get("install_root")
    helper_root_value = request.get("helper_bundle_root")
    security_root_value = request.get("security_root")
    if not all(
        isinstance(value, str) and value
        for value in (install_root_value, helper_root_value, security_root_value)
    ):
        raise ValueError("deferred lifecycle request path binding is incomplete")
    root = Path(str(install_root_value)).resolve()
    helper_root = _validate_helper_location(
        Path(str(helper_root_value)), install_root=root
    )
    request_path = _validate_protected_request_path(
        supplied_request_path, helper_root=helper_root
    )
    operation_security_root = _security_root(str(security_root_value))
    if _path_is_link_or_reparse_point(operation_security_root):
        raise ValueError("deferred lifecycle request security root is unsafe")
    return request_path, request, root, helper_root, operation_security_root


def _discard_deferred_request_artifacts(
    request_path: Path, *, security_root: str | Path | None
) -> None:
    """Remove only authenticated, bounded staging after a launcher failure."""

    try:
        (
            protected_request_path,
            request,
            root,
            helper_root,
            operation_security_root,
        ) = _read_deferred_request(request_path)
        if (
            security_root is not None
            and _security_root(security_root) != operation_security_root
        ):
            return
        _, _, manifest, key = _load_manifest(
            root, security_root=operation_security_root
        )
        if (
            request.get("schema_version") != _DEFERRED_REQUEST_SCHEMA_VERSION
            or request.get("request_id") != _helper_identity(helper_root, root)
            or not _verify_signed_value(request, key)
            or request.get("manifest_fingerprint") != _manifest_fingerprint(manifest)
        ):
            return
        if request.get("kind") == "ARTIFEX_DEFERRED_UPGRADE":
            artifact_manifest = request.get("artifact_manifest")
            if not isinstance(artifact_manifest, Mapping):
                return
            staged = Path(str(request.get("staged_artifact", ""))).resolve()
            candidate_root = _validate_candidate_location(
                staged.parent, helper_root=helper_root
            )
            candidate_entries = _request_artifact_files(
                candidate_root, artifact_manifest
            )
            _remove_candidate_bundle(
                candidate_root, candidate_entries, helper_root=helper_root
            )
        helper_root, _ = _validate_deferred_helper_bundle(request, root, manifest)
        _schedule_helper_cleanup(
            helper_root,
            _manifest_entries(manifest, "files", required=True),
            install_root=root,
        )
        _validate_protected_request_path(
            protected_request_path, helper_root=helper_root
        ).unlink(missing_ok=True)
    except (OSError, ValueError, json.JSONDecodeError):
        # Preserve anything whose authenticated ownership cannot be proven.
        return


def _launch_deferred_helper(
    running_executable: Path, request_file: Path, parent_pid: int
) -> None:
    request_path, request, root, helper_root, operation_security_root = (
        _read_deferred_request(request_file)
    )
    _, _, manifest, key = _load_manifest(
        root, security_root=operation_security_root
    )
    if (
        request.get("schema_version") != _DEFERRED_REQUEST_SCHEMA_VERSION
        or request.get("request_id") != _helper_identity(helper_root, root)
        or not _verify_signed_value(request, key)
        or request.get("manifest_fingerprint") != _manifest_fingerprint(manifest)
        or request.get("parent_pid") != parent_pid
    ):
        raise ValueError("deferred lifecycle helper request authentication failed")
    if not _same_file(Path(running_executable).resolve(), _managed_executable(root, manifest)):
        raise ValueError("deferred lifecycle helper source is not the installed executable")
    _, helper = _validate_deferred_helper_bundle(request, root, manifest)
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
    subprocess.Popen(
        [
            str(helper),
            "_complete-lifecycle",
            "--request-file",
            str(request_path),
            "--parent-pid",
            str(parent_pid),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )


def _load_manifest(
    install_root: str | Path,
    *,
    security_root: str | Path | None,
) -> tuple[Path, Path, dict[str, Any], bytes]:
    root = Path(install_root).resolve()
    path = root / MANIFEST_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"valid ARTIFEX install manifest required: {path}") from exc
    if not isinstance(value, dict) or value.get("install_root") != str(root):
        raise ValueError("install manifest root does not match target")
    if value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported install manifest schema")
    key = _load_install_key(_key_path(root, security_root))
    if not _verify_signed_value(value, key):
        raise ValueError("install manifest authentication failed")
    _manifest_files(root, value)
    _manifest_files(root, value, field="backups", required=False)
    artifact_manifest = value.get("artifact_manifest")
    artifact_fingerprint = value.get("artifact_manifest_fingerprint")
    if not isinstance(artifact_manifest, Mapping) or not isinstance(
        artifact_fingerprint, str
    ):
        raise ValueError("installed artifact identity is missing")
    expected_fingerprint = hashlib.sha256(_canonical(artifact_manifest)).hexdigest()
    if not hmac.compare_digest(artifact_fingerprint, expected_fingerprint):
        raise ValueError("installed artifact manifest fingerprint is invalid")
    file_entries = _manifest_entries(value, "files", required=True)
    artifact_files = artifact_manifest.get("files")
    if not isinstance(artifact_files, list) or file_entries != tuple(artifact_files):
        raise ValueError("installed artifact identity does not match managed bundle")
    executable = _managed_executable(root, value)
    executable_entry = next(
        (item for item in file_entries if item["path"] == executable.relative_to(root).as_posix()),
        None,
    )
    if executable_entry is None or artifact_manifest.get("sha256") != executable_entry["sha256"]:
        raise ValueError("installed artifact identity does not match managed executable")
    return root, path, value, key


def installed_shipping_artifact_sha256(
    install_root: str | Path,
    *,
    security_root: str | Path | None = None,
) -> str:
    """Return the authenticated digest of the installed shipping executable.

    Live provider certification runs in a fresh managed-service process, so it
    cannot depend on a qualifier-only environment variable surviving service
    registration or restart.  The installer-owned manifest is the durable
    authority for the exact shipping executable that the service is running.
    """

    root, _, manifest, _ = _load_manifest(install_root, security_root=security_root)
    _verify_managed_checksums(root, manifest)
    artifact_manifest = manifest["artifact_manifest"]
    if not isinstance(artifact_manifest, Mapping):
        raise ValueError("installed artifact identity is missing")
    digest = artifact_manifest.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("installed shipping artifact digest is invalid")
    return digest


def _manifest_entries(
    manifest: Mapping[str, Any], field: str, *, required: bool
) -> tuple[dict[str, str], ...]:
    values = manifest.get(field, [])
    if not isinstance(values, list) or (required and not values):
        raise ValueError(f"install manifest contains no managed {field}")
    entries: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, dict):
            raise ValueError("invalid install manifest file entry")
        path = item.get("path")
        kind = item.get("kind")
        digest = item.get("sha256")
        expected_fields = (
            {"path", "kind", "sha256"}
            if kind == "file"
            else {"path", "kind", "target", "sha256"}
        )
        if (
            kind not in {"file", "symlink"}
            or set(item) != expected_fields
            or not isinstance(path, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("invalid install manifest file entry")
        entry = {"path": path, "kind": kind, "sha256": digest}
        if kind == "symlink":
            target = item.get("target")
            if (
                not isinstance(target, str)
                or not target
                or Path(target).is_absolute()
                or _symlink_digest(target) != digest
            ):
                raise ValueError("invalid install manifest symlink entry")
            if not _supports_bundle_symlinks():
                raise ValueError("managed bundle symlinks are unsupported on Windows")
            entry["target"] = target
        entries.append(entry)
    return tuple(entries)


def _manifest_files(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    field: str = "files",
    required: bool = True,
) -> tuple[Path, ...]:
    targets: list[Path] = []
    seen: set[str] = set()
    for item in _manifest_entries(manifest, field, required=required):
        relative_text = item["path"]
        target = _safe_child(root, relative_text)
        if item.get("kind") == "symlink":
            _validate_symlink(root, target, item["target"])
        canonical_relative = target.relative_to(root).as_posix()
        if canonical_relative in seen:
            raise ValueError("manifest path escapes install root or is duplicated")
        seen.add(canonical_relative)
        targets.append(target)
    return tuple(targets)


def _managed_executable(root: Path, manifest: Mapping[str, Any]) -> Path:
    artifact_manifest = manifest.get("artifact_manifest")
    if not isinstance(artifact_manifest, Mapping):
        raise ValueError("installed artifact identity is missing")
    name = artifact_manifest.get("artifact")
    if not isinstance(name, str):
        raise ValueError("installed artifact executable identity is invalid")
    executable = _safe_child(root, name)
    if executable not in _manifest_files(root, manifest):
        raise ValueError("installed executable is not manifest managed")
    return executable


def _service_state_root(value: str | Path | None) -> Path:
    from artifex.distribution.installed_state import discover_canonical_state_root

    resolved = discover_canonical_state_root(value)
    if resolved.parent == resolved:
        raise ValueError("managed service state root cannot be a filesystem root")
    return resolved


def _installed_service_registration(
    manifest: Mapping[str, Any],
) -> ServiceRegistrationManifest | None:
    value = manifest.get("service_registration")
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("installed managed-service identity is invalid")
    try:
        return ServiceRegistrationManifest.from_dict(value)
    except ValueError as exc:
        raise ValueError("installed managed-service identity is invalid") from exc


def _resolve_managed_service_request(
    manifest: Mapping[str, Any],
    *,
    managed_service: bool,
    service_state_root: str | Path | None,
    service_id: str,
    allow_state_root_transition: bool = False,
) -> tuple[bool, str | Path | None, str]:
    installed = _installed_service_registration(manifest)
    if installed is None:
        if managed_service:
            raise ValueError("installation does not own a managed service")
        return False, service_state_root, service_id
    if managed_service and service_id != installed.service_id:
        raise ValueError("managed service request does not match installed ownership")
    if (
        service_state_root is not None
        and not allow_state_root_transition
        and _service_state_root(service_state_root) != Path(installed.state_root).resolve()
    ):
        raise ValueError("managed service state root does not match installed ownership")
    selected_root: str | Path = (
        _service_state_root(service_state_root)
        if service_state_root is not None
        else installed.state_root
    )
    return True, selected_root, installed.service_id


def _validate_service_readiness_timeout(value: float) -> None:
    if not 0 < value <= 300:
        raise ValueError("service readiness timeout must be between 0 and 300 seconds")


def _service_manager(
    install_root: Path,
    *,
    adapter: ServiceRegistrationAdapter | None,
    readiness_timeout_seconds: float,
) -> ServiceRegistrationManager:
    return ServiceRegistrationManager(
        install_root / SERVICE_REGISTRATION_MANIFEST_NAME,
        adapter=adapter,
        readiness_timeout_seconds=readiness_timeout_seconds,
    )


def _service_spec(
    executable: Path,
    executable_sha256: str,
    state_root: str | Path | None,
    service_id: str,
    service_version: str,
) -> ServiceRegistrationSpec:
    resolved_state = _service_state_root(state_root)
    return ServiceRegistrationSpec(
        service_id=service_id,
        service_version=service_version,
        executable=str(executable.resolve()),
        executable_sha256=executable_sha256,
        arguments=(
            "service",
            "serve",
            "--state-root",
            str(resolved_state),
            "--service-id",
            service_id,
        ),
        working_directory=str(executable.resolve().parent),
        state_root=str(resolved_state),
        activation_policy="PLATFORM_MANAGED",
    )


def _restore_service_registration(
    manager: ServiceRegistrationManager,
    manifest: ServiceRegistrationManifest,
) -> None:
    manager.install(
        ServiceRegistrationPlan(
            operation="INSTALL",
            service_id=manifest.service_id,
            platform_id=manager.adapter.platform_id,
            current_manifest_sha256=None,
            desired_manifest=manifest,
            no_op=False,
        )
    )


def _verify_managed_checksums(root: Path, manifest: Mapping[str, Any]) -> None:
    all_paths: set[Path] = set()
    for field, required in (("files", True), ("backups", False)):
        entries = _manifest_entries(manifest, field, required=required)
        targets = _manifest_files(root, manifest, field=field, required=required)
        for item, target in zip(entries, targets, strict=True):
            if target in all_paths:
                raise ValueError("managed path is duplicated across manifest sections")
            all_paths.add(target)
            if not _entry_matches(root, target, item):
                raise ValueError(
                    f"managed file is missing or modified; refusing mutation: {target}"
                )


def _safe_child(root: Path, relative_text: str) -> Path:
    relative = Path(relative_text)
    if (
        relative.is_absolute()
        or bool(relative.anchor)
        or bool(PureWindowsPath(relative_text).drive)
        or not relative.parts
        or ".." in relative.parts
        or relative_text != relative.as_posix()
    ):
        raise ValueError("unsafe install manifest path")
    if _path_is_link_or_reparse_point(root):
        raise ValueError("manifest root is a symlink or reparse point")
    canonical_root = root.resolve()
    target = canonical_root.joinpath(*relative.parts)
    cursor = canonical_root
    for part in relative.parts[:-1]:
        cursor /= part
        if _path_lexists(cursor) and _path_is_link_or_reparse_point(cursor):
            raise ValueError("manifest path traverses a symlink or reparse point")
    return target


def _copy_verified_bundle(verified: VerifiedArtifact, destination_root: Path) -> None:
    if not _supports_bundle_symlinks() and any(
        item.get("kind") == "symlink" for item in verified.files
    ):
        raise ValueError("managed bundle symlinks are unsupported on Windows")
    for item in _copy_order(verified.files):
        source = _safe_child(verified.bundle_root, item["path"])
        destination = _safe_child(destination_root, item["path"])
        if not _entry_matches(verified.bundle_root, source, item):
            raise ValueError("verified artifact bundle changed before copying")
        destination.parent.mkdir(parents=True, exist_ok=True)
        _copy_manifest_entry(
            source,
            destination,
            item,
            source_root=verified.bundle_root,
        )
    if not all(
        _entry_matches(
            destination_root, _safe_child(destination_root, item["path"]), item
        )
        for item in verified.files
    ):
        raise ValueError("copied artifact bundle verification failed")


def _copy_order(
    entries: tuple[Mapping[str, str], ...] | list[dict[str, str]],
) -> tuple[Mapping[str, str], ...]:
    return tuple(
        sorted(entries, key=lambda item: (item.get("kind") == "symlink", item["path"]))
    )


def _entry_matches(root: Path, path: Path, item: Mapping[str, str]) -> bool:
    kind = item.get("kind")
    digest = item.get("sha256", "")
    if kind == "file":
        return (
            path.is_file()
            and not _path_is_link_or_reparse_point(path)
            and hmac.compare_digest(_sha256(path), digest)
        )
    if kind == "symlink":
        target = item.get("target")
        if not isinstance(target, str) or not path.is_symlink():
            return False
        try:
            observed = os.readlink(path)
            _validate_symlink(root, path, observed)
        except (OSError, ValueError):
            return False
        return observed == target and hmac.compare_digest(_symlink_digest(observed), digest)
    return False


def _copy_manifest_entry(
    source: Path,
    destination: Path,
    item: Mapping[str, str],
    *,
    source_root: Path,
) -> None:
    if not _entry_matches(source_root, source, item):
        raise ValueError("manifest-owned source changed before copying")
    if _path_lexists(destination):
        if _is_windows_reparse_point(destination):
            raise ValueError("manifest destination is a reparse point")
        if destination.is_dir() and not destination.is_symlink():
            raise ValueError("manifest destination collides with a directory")
        destination.unlink()
    if item.get("kind") == "symlink":
        target = item["target"]
        os.symlink(target, destination, target_is_directory=source.resolve().is_dir())
        return
    _copy_atomic(source, destination)


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _is_windows_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError("could not inspect path for a Windows reparse point") from exc
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & reparse_attribute)


def _path_is_link_or_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError("could not inspect lifecycle path") from exc
    return stat.S_ISLNK(metadata.st_mode) or _is_windows_reparse_point(path)


def _remove_manifest_paths(
    root: Path, entries: tuple[Mapping[str, str], ...] | list[dict[str, str]]
) -> None:
    parents: set[Path] = set()
    for item in entries:
        target = _safe_child(root, item["path"])
        target.unlink(missing_ok=True)
        cursor = target.parent
        while cursor != root:
            parents.add(cursor)
            cursor = cursor.parent
    for directory in sorted(
        parents,
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        with suppress(OSError):
            directory.rmdir()


def _request_artifact_files(
    bundle_root: Path, artifact_manifest: Mapping[str, Any]
) -> tuple[Mapping[str, str], ...]:
    raw = artifact_manifest.get("files")
    if not isinstance(raw, list) or not raw:
        raise ValueError("deferred upgrade bundle inventory is invalid")
    entries: list[Mapping[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise ValueError("deferred upgrade bundle inventory is invalid")
        relative = item.get("path")
        kind = item.get("kind")
        digest = item.get("sha256")
        expected_fields = (
            {"path", "kind", "sha256"}
            if kind == "file"
            else {"path", "kind", "target", "sha256"}
        )
        if (
            kind not in {"file", "symlink"}
            or set(item) != expected_fields
            or not isinstance(relative, str)
            or not isinstance(digest, str)
        ):
            raise ValueError("deferred upgrade bundle inventory is invalid")
        if kind == "symlink" and not _supports_bundle_symlinks():
            raise ValueError("managed bundle symlinks are unsupported on Windows")
        target = _safe_child(bundle_root, relative)
        normalized = {key: str(value) for key, value in item.items()}
        if not _entry_matches(bundle_root, target, normalized):
            raise ValueError("deferred upgrade staged bundle changed")
        entries.append(normalized)
    return tuple(entries)


def _signed_manifest(value: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    return _signed_value(value, key)


def _signed_value(value: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    unsigned = {key_name: item for key_name, item in value.items() if key_name != "authentication"}
    signature = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
    return {
        **unsigned,
        "authentication": {"algorithm": _AUTH_ALGORITHM, "signature": signature},
    }


def _verify_signed_value(value: Mapping[str, Any], key: bytes) -> bool:
    authentication = value.get("authentication")
    if not isinstance(authentication, Mapping):
        return False
    if authentication.get("algorithm") != _AUTH_ALGORITHM:
        return False
    supplied = authentication.get("signature")
    if not isinstance(supplied, str):
        return False
    unsigned = {key_name: item for key_name, item in value.items() if key_name != "authentication"}
    expected = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def _manifest_fingerprint(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(manifest)).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _security_root(override: str | Path | None) -> Path:
    return (
        (user_state_root() / "security").resolve()
        if override is None
        else Path(override).resolve()
    )


def _key_path(install_root: Path, security_root: str | Path | None) -> Path:
    identity = os.path.normcase(str(install_root)).encode("utf-8")
    return _security_root(security_root) / "install-keys" / (
        hashlib.sha256(identity).hexdigest() + ".key"
    )


def _create_install_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise FileExistsError("installation security key already exists") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(key)
        stream.flush()
        os.fsync(stream.fileno())
    return key


def _load_install_key(path: Path) -> bytes:
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise ValueError("installation security key is missing") from exc
    if len(key) != 32:
        raise ValueError("installation security key is invalid")
    return key


def _native_executable_name() -> str:
    return "artifex.exe" if os.name == "nt" else "artifex"


def _copy_atomic(source: Path, destination: Path) -> None:
    # Keep the temporary leaf short: native one-directory bundles contain deep
    # schema paths and the Windows helper must remain below legacy MAX_PATH even
    # when its install root is already long.
    descriptor, name = tempfile.mkstemp(dir=destination.parent, prefix=".af-")
    os.close(descriptor)
    temporary = Path(name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _write_manifest(path: Path, value: Mapping[str, Any]) -> None:
    _write_bytes_atomic(path, json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n")


def _write_bytes_atomic(path: Path, content: bytes) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".af-")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _runtime_executable() -> Path:
    """Return the invoked shipping executable for the active runtime.

    Nuitka standalone keeps the shipping launcher in ``sys.argv[0]`` while
    ``sys.executable`` is not a reliable identity for self-update/uninstall
    decisions.  PyInstaller and ordinary Python retain their documented
    ``sys.executable`` identity.
    """

    if "__compiled__" in globals():
        return Path(sys.argv[0]).absolute().resolve()
    return Path(sys.executable).resolve()


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            windows_dlls = getattr(ctypes, "windll", None)
            if windows_dlls is not None:
                handle = windows_dlls.kernel32.OpenProcess(0x00100000, False, pid)
                if not handle:
                    return False
                windows_dlls.kernel32.CloseHandle(handle)
                return True
        except (AttributeError, OSError):
            return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _stop_running_managed_executables(
    root: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    platform_name: str | None = None,
) -> list[int]:
    """Stop installed ARTIFEX frontends before manifest-owned file removal.

    The deferred lifecycle helper runs from a verified copy outside the install
    root.  Once the managed service has been stopped and unregistered, any
    process still executing the exact installed executable is a user frontend
    that would keep the Windows image locked.  Match the full executable path,
    not only the process name, so unrelated ARTIFEX copies are untouched.
    """

    effective_platform = platform_name or os.name
    if effective_platform != "nt":
        return []
    # This branch models Windows even when a cross-platform test injects the
    # platform name from a non-Windows host.  Keep the Windows shipping name
    # explicit so the generated exact-path guard is host-independent.
    executable = (root / "artifex.exe").resolve()
    target = str(executable).replace("'", "''")
    process_name = executable.name.replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$target = [IO.Path]::GetFullPath('{target}')
$current = {os.getpid()}
$matches = @(Get-CimInstance Win32_Process -Filter "Name = '{process_name}'" | Where-Object {{
    $_.ProcessId -ne $current -and
    $_.ExecutablePath -and
    [String]::Equals(
        [IO.Path]::GetFullPath($_.ExecutablePath),
        $target,
        [StringComparison]::OrdinalIgnoreCase
    )
}})
foreach ($process in $matches) {{
    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    Wait-Process -Id $process.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
    Write-Output $process.ProcessId
}}
""".strip()
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    invoke = runner or subprocess.run
    completed = invoke(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown Windows process error").strip()
        raise RuntimeError(
            "could not close the installed ARTIFEX frontend before uninstall: "
            + detail[:500]
        )
    stopped: list[int] = []
    for line in completed.stdout.splitlines():
        value = line.strip()
        if value.isdigit():
            stopped.append(int(value))
    return stopped


def _schedule_helper_cleanup(
    helper_root: Path,
    entries: tuple[Mapping[str, str], ...],
    *,
    install_root: Path,
) -> None:
    """Remove only authenticated helper paths, deferring Windows-locked paths.

    Cleanup deliberately does not recurse.  Every file comes from the signed
    install inventory, and every directory is merely a parent of such a file.
    Unexpected content is preserved and turns cleanup into an explicit failure.
    """

    resolved_root = _validate_helper_location(helper_root, install_root=install_root)
    if not _path_lexists(resolved_root):
        return
    targets: list[tuple[Path, Mapping[str, str]]] = []
    directories: set[Path] = set()
    for item in entries:
        target = _safe_child(resolved_root, item["path"])
        targets.append((target, item))
        cursor = target.parent
        while cursor != resolved_root:
            directories.add(cursor)
            cursor = cursor.parent

    scheduled: set[Path] = set()
    for expected_target, item in targets:
        target = _safe_child(resolved_root, item["path"])
        if target != expected_target:
            raise ValueError("deferred lifecycle cleanup target changed")
        if not _path_lexists(target):
            continue
        if _is_windows_reparse_point(target) or not _entry_matches(
            resolved_root, target, item
        ):
            raise ValueError("deferred lifecycle helper changed before cleanup")
        try:
            target.unlink(missing_ok=True)
        except OSError:
            if os.name != "nt":
                raise
            _schedule_path_cleanup_on_reboot(target)
            scheduled.add(target)

    for expected_directory in sorted(
        directories, key=lambda item: len(item.parts), reverse=True
    ):
        relative = expected_directory.relative_to(resolved_root).as_posix()
        directory = _safe_child(resolved_root, relative)
        if directory != expected_directory:
            raise ValueError("deferred lifecycle cleanup directory changed")
        if not _path_lexists(directory):
            continue
        if _path_is_link_or_reparse_point(directory):
            raise ValueError("deferred lifecycle cleanup directory is unsafe")
        try:
            directory.rmdir()
        except OSError:
            if os.name != "nt":
                raise
            _require_only_scheduled_children(directory, scheduled)
            _schedule_path_cleanup_on_reboot(directory)
            scheduled.add(directory)

    resolved_root = _validate_helper_location(
        resolved_root, install_root=install_root
    )
    if not _path_lexists(resolved_root):
        return
    try:
        resolved_root.rmdir()
    except OSError:
        if os.name != "nt":
            raise
        _require_only_scheduled_children(resolved_root, scheduled)
        _schedule_path_cleanup_on_reboot(resolved_root)


def _require_only_scheduled_children(directory: Path, scheduled: set[Path]) -> None:
    try:
        children = tuple(directory.iterdir())
    except OSError as exc:
        raise ValueError("could not inspect deferred lifecycle cleanup directory") from exc
    for child in children:
        if _path_is_link_or_reparse_point(child) or child not in scheduled:
            raise ValueError("deferred lifecycle helper contains unowned cleanup content")


def _schedule_path_cleanup_on_reboot(
    path: Path,
    *,
    mover: Callable[[str, str | None, int], int] | None = None,
) -> None:
    if os.name != "nt":
        raise OSError("delayed lifecycle cleanup is only available on Windows")
    import ctypes

    move_file = mover
    if move_file is None:
        windows_dlls = getattr(ctypes, "windll", None)
        if windows_dlls is None:
            raise OSError("Windows delayed-delete API is unavailable")
        move_file = windows_dlls.kernel32.MoveFileExW
    try:
        scheduled = move_file(str(path), None, 0x00000004)
    except (AttributeError, OSError) as exc:
        raise OSError("Windows delayed-delete request failed") from exc
    if not scheduled:
        get_last_error = getattr(ctypes, "get_last_error", None)
        error_code = int(get_last_error()) if callable(get_last_error) else 0
        raise OSError(
            error_code,
            f"Windows refused delayed deletion for lifecycle path: {path}",
        )
