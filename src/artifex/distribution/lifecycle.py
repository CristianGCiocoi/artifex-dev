"""Authenticated, reversible install, upgrade, and self-uninstall lifecycle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
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
        launcher(current, request_file, os.getpid())
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
                request_file.unlink(missing_ok=True)
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
    request_path = Path(request_file).resolve()
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid deferred uninstall request") from exc
    if not isinstance(request, dict):
        raise ValueError("invalid deferred uninstall request")
    root = Path(str(request.get("install_root", ""))).resolve()
    _, manifest_path, manifest, key = _load_manifest(root, security_root=security_root)
    if not _verify_signed_value(request, key):
        raise ValueError("deferred uninstall request authentication failed")
    kind = request.get("kind")
    if kind not in {"ARTIFEX_DEFERRED_UNINSTALL", "ARTIFEX_DEFERRED_UPGRADE"}:
        raise ValueError("unexpected deferred lifecycle request kind")
    if request.get("manifest_fingerprint") != _manifest_fingerprint(manifest):
        raise ValueError("deferred uninstall request is stale")
    try:
        expires_at = datetime.fromisoformat(str(request["expires_at"])).astimezone(UTC)
        parent_pid = int(request["parent_pid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid deferred uninstall request identity") from exc
    if datetime.now(UTC) > expires_at:
        raise ValueError("deferred uninstall request expired")
    checker = parent_checker or _pid_exists
    deadline = time.monotonic() + wait_timeout_seconds
    while checker(parent_pid):
        if time.monotonic() >= deadline:
            raise TimeoutError("parent process did not exit before lifecycle timeout")
        time.sleep(0.1)
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
        staged = Path(str(request.get("staged_artifact", ""))).resolve()
        staging_root = (_security_root(security_root) / "staged-artifacts").resolve()
        artifact_manifest = request.get("artifact_manifest")
        artifact_fingerprint = request.get("artifact_manifest_fingerprint")
        if (
            staging_root not in staged.parents
            or staged.is_symlink()
            or not isinstance(artifact_manifest, Mapping)
            or not isinstance(artifact_fingerprint, str)
            or hashlib.sha256(_canonical(artifact_manifest)).hexdigest()
            != artifact_fingerprint
            or artifact_manifest.get("sha256") != _sha256(staged)
        ):
            raise ValueError("deferred upgrade staged artifact identity is invalid")
        stage_bundle = staged.parent
        file_entries = _request_artifact_files(stage_bundle, artifact_manifest)
        verified = VerifiedArtifact(
            staged,
            stage_bundle,
            stage_bundle / "artifex-artifact.json",
            artifact_manifest,
            artifact_fingerprint,
            file_entries,
        )
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
            _remove_staged_bundle(stage_bundle, staging_root)
        result = {
            "operation": "upgrade",
            "install_root": str(root),
            "status": "COMPLETE",
            "backup": str(backup),
        }
    request_path.unlink(missing_ok=True)
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        _schedule_helper_cleanup(_runtime_executable())
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
    helper_root = _security_root(security_root) / "uninstall-requests"
    helper_root.mkdir(parents=True, exist_ok=True)
    request_path = helper_root / f"{uuid.uuid4().hex}.json"
    value = _signed_value(
        {
            "schema_version": "1.0",
            "kind": "ARTIFEX_DEFERRED_UNINSTALL",
            "install_root": str(root),
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "parent_pid": parent_pid,
            "service_readiness_timeout_seconds": service_readiness_timeout_seconds,
            "expires_at": (
                datetime.now(UTC) + timedelta(seconds=_DEFERRED_REQUEST_TTL_SECONDS)
            ).isoformat(),
        },
        key,
    )
    _write_manifest(request_path, value)
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
    operation_root = _security_root(security_root)
    request_root = operation_root / "uninstall-requests"
    staging_root = operation_root / "staged-artifacts"
    request_root.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)
    staged_bundle = staging_root / uuid.uuid4().hex
    staged = staged_bundle / str(verified.manifest["artifact"])
    request_path = request_root / f"{uuid.uuid4().hex}.json"
    try:
        staged_bundle.mkdir(parents=False, exist_ok=False)
        _copy_verified_bundle(verified, staged_bundle)
        _write_manifest(staged_bundle / "artifex-artifact.json", verified.manifest)
        value = _signed_value(
            {
                "schema_version": "1.0",
                "kind": "ARTIFEX_DEFERRED_UPGRADE",
                "install_root": str(root),
                "manifest_fingerprint": _manifest_fingerprint(manifest),
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
        if staged_bundle.exists():
            shutil.rmtree(staged_bundle)
        request_path.unlink(missing_ok=True)
        raise
    return request_path


def _launch_deferred_helper(
    running_executable: Path, request_file: Path, parent_pid: int
) -> None:
    helper_dir = request_file.parent / f"helper-{uuid.uuid4().hex}"
    helper_dir.mkdir(parents=True, exist_ok=False)
    helper = helper_dir / _native_executable_name()
    _copy_atomic(running_executable, helper)
    runtime_root_value = getattr(sys, "_MEIPASS", None)
    if isinstance(runtime_root_value, str):
        runtime_root = Path(runtime_root_value).resolve()
        running_root = running_executable.parent.resolve()
        if running_root in runtime_root.parents:
            relative_runtime = runtime_root.relative_to(running_root)
            shutil.copytree(runtime_root, helper_dir / relative_runtime, symlinks=True)
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
            str(request_file),
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
    canonical_root = root.resolve()
    target = canonical_root.joinpath(*relative.parts)
    cursor = canonical_root
    for part in relative.parts[:-1]:
        cursor /= part
        if _path_lexists(cursor) and cursor.is_symlink():
            raise ValueError("manifest path traverses a symlink")
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
            and not path.is_symlink()
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


def _remove_staged_bundle(bundle: Path, staging_root: Path) -> None:
    resolved = bundle.resolve()
    if (
        resolved.parent != staging_root.resolve()
        or len(resolved.name) != 32
        or any(character not in "0123456789abcdef" for character in resolved.name)
        or resolved.is_symlink()
    ):
        raise ValueError("refusing unsafe staged bundle cleanup")
    if resolved.exists():
        shutil.rmtree(resolved)


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


def _schedule_helper_cleanup(helper: Path) -> None:
    if os.name != "nt":
        helper.unlink(missing_ok=True)
        return
    try:
        import ctypes

        windows_dlls = getattr(ctypes, "windll", None)
        if windows_dlls is not None:
            windows_dlls.kernel32.MoveFileExW(str(helper), None, 0x00000004)
    except (AttributeError, OSError):
        pass
