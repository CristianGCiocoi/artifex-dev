"""Authenticated, reversible install, upgrade, and self-uninstall lifecycle."""

from __future__ import annotations

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
from pathlib import Path
from typing import Any

from artifex import __version__
from artifex.distribution.approvals import ApprovalStore, user_state_root
from artifex.distribution.presentation import explain_decision, require_approval

MANIFEST_NAME = "artifex-install-manifest.json"
MANIFEST_SCHEMA_VERSION = "2.0"
_AUTH_ALGORITHM = "HMAC-SHA256"
_DEFERRED_REQUEST_TTL_SECONDS = 120

DeferredLauncher = Callable[[Path, Path, int], None]
ParentChecker = Callable[[int], bool]


@dataclass(frozen=True, slots=True)
class InstallResult:
    operation: str
    install_root: str
    executable: str
    manifest: str
    backup: str | None = None
    status: str = "COMPLETE"
    deferred_request: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "operation": self.operation,
            "install_root": self.install_root,
            "executable": self.executable,
            "manifest": self.manifest,
            "backup": self.backup,
            "status": self.status,
            "deferred_request": self.deferred_request,
        }


def install_plan(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
) -> Any:
    source = Path(source_executable).resolve()
    root = Path(install_root).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"frozen ARTIFEX executable not found: {source}")
    return explain_decision(
        "install ARTIFEX",
        "REVERSIBLE",
        effects=(f"copy {source.name} into {root}", f"write authenticated {MANIFEST_NAME}"),
        rollback=f"remove only newly created files under {root}",
        binding={
            "operation": "install",
            "install_root": str(root),
            "source_sha256": _sha256(source),
            "destination": _native_executable_name(),
            "manifest_schema": MANIFEST_SCHEMA_VERSION,
            "artifex_version": __version__,
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
) -> InstallResult:
    source = Path(source_executable).resolve()
    root = Path(install_root).resolve()
    if root == Path(root.anchor) or len(root.parts) < 2:
        raise ValueError("refusing broad install root")
    decision = install_plan(source, root, approval_store=approval_store, issue_token=False)
    destination = root / _native_executable_name()
    manifest_path = root / MANIFEST_NAME
    if manifest_path.exists() or destination.exists():
        raise FileExistsError("ARTIFEX is already installed; use upgrade")
    require_approval(decision, confirmation_token, approval_store=approval_store)
    root_created = not root.exists()
    root.mkdir(parents=True, exist_ok=True)
    key_path = _key_path(root, security_root)
    key: bytes | None = None
    try:
        key = _create_install_key(key_path)
        _copy_atomic(source, destination)
        manifest = _signed_manifest(
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "artifex_version": __version__,
                "install_root": str(root),
                "files": [{"path": destination.name, "sha256": _sha256(destination)}],
                "backups": [],
            },
            key,
        )
        _write_manifest(manifest_path, manifest)
    except Exception:
        manifest_path.unlink(missing_ok=True)
        destination.unlink(missing_ok=True)
        if key is not None:
            key_path.unlink(missing_ok=True)
        if root_created:
            with suppress(OSError):
                root.rmdir()
        raise
    return InstallResult("install", str(root), str(destination), str(manifest_path))


def upgrade_plan(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    issue_token: bool = True,
) -> Any:
    source = Path(source_executable).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"frozen ARTIFEX executable not found: {source}")
    root, _, manifest, _ = _load_manifest(install_root, security_root=security_root)
    destination = _single_managed_file(root, manifest)
    return explain_decision(
        "upgrade ARTIFEX",
        "REVERSIBLE",
        effects=(f"replace manifest-owned file {destination.name}",),
        rollback="restore the authenticated pre-upgrade artifact and manifest",
        binding={
            "operation": "upgrade",
            "install_root": str(root),
            "source_sha256": _sha256(source),
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "destination": destination.name,
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
) -> InstallResult:
    source = Path(source_executable).resolve()
    root, manifest_path, manifest, key = _load_manifest(
        install_root, security_root=security_root
    )
    _verify_managed_checksums(root, manifest)
    decision = upgrade_plan(
        source,
        root,
        approval_store=approval_store,
        security_root=security_root,
        issue_token=False,
    )
    require_approval(decision, confirmation_token, approval_store=approval_store)
    destination = _single_managed_file(root, manifest)
    old_manifest = manifest_path.read_bytes()
    backup = root / f"{destination.name}.pre-upgrade-{_sha256(destination)[:12]}.bak"
    if backup.exists():
        raise FileExistsError(f"upgrade backup already exists: {backup}")
    _copy_atomic(destination, backup)
    try:
        _copy_atomic(source, destination)
        previous_backups = list(_manifest_entries(manifest, "backups", required=False))
        previous_backups.append({"path": backup.name, "sha256": _sha256(backup)})
        updated = _signed_manifest(
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "artifex_version": __version__,
                "install_root": str(root),
                "files": [{"path": destination.name, "sha256": _sha256(destination)}],
                "backups": previous_backups,
            },
            key,
        )
        _write_manifest(manifest_path, updated)
    except Exception:
        _copy_atomic(backup, destination)
        backup.unlink(missing_ok=True)
        _write_bytes_atomic(manifest_path, old_manifest)
        raise
    return InstallResult(
        "upgrade", str(root), str(destination), str(manifest_path), str(backup)
    )


def uninstall_plan(
    install_root: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    security_root: str | Path | None = None,
    issue_token: bool = True,
) -> Any:
    root, _, manifest, _ = _load_manifest(install_root, security_root=security_root)
    managed = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    return explain_decision(
        "uninstall ARTIFEX",
        "REVERSIBLE",
        effects=tuple(f"remove authenticated manifest-owned file {path.name}" for path in managed),
        rollback="reinstall the frozen artifact; unrelated files remain untouched",
        binding={
            "operation": "uninstall",
            "install_root": str(root),
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "managed_files": [path.name for path in managed],
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
) -> dict[str, Any]:
    root, manifest_path, manifest, key = _load_manifest(
        install_root, security_root=security_root
    )
    _verify_managed_checksums(root, manifest)
    decision = uninstall_plan(
        root,
        approval_store=approval_store,
        security_root=security_root,
        issue_token=False,
    )
    require_approval(decision, confirmation_token, approval_store=approval_store)
    targets = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    current = Path(running_executable or sys.executable).resolve()
    self_managed = any(_same_file(current, target) for target in targets)
    defer = (os.name == "nt" and self_managed) if force_deferred is None else force_deferred
    if defer:
        request_file = _prepare_deferred_uninstall(
            root,
            manifest,
            key,
            security_root=security_root,
            parent_pid=os.getpid(),
        )
        launcher = deferred_launcher or _launch_deferred_helper
        launcher(current, request_file, os.getpid())
        return {
            "operation": "uninstall",
            "install_root": str(root),
            "status": "DEFERRED",
            "removed": [],
            "deferred_request": str(request_file),
        }
    removed = _perform_uninstall(
        root, manifest_path, manifest, security_root=security_root
    )
    return {
        "operation": "uninstall",
        "install_root": str(root),
        "status": "COMPLETE",
        "removed": removed,
    }


def complete_deferred_uninstall(
    request_file: str | Path,
    *,
    security_root: str | Path | None = None,
    wait_timeout_seconds: float = 30.0,
    parent_checker: ParentChecker | None = None,
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
    if request.get("kind") != "ARTIFEX_DEFERRED_UNINSTALL":
        raise ValueError("unexpected deferred uninstall request kind")
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
            raise TimeoutError("parent process did not exit before uninstall timeout")
        time.sleep(0.1)
    _verify_managed_checksums(root, manifest)
    removed = _perform_uninstall(
        root, manifest_path, manifest, security_root=security_root
    )
    request_path.unlink(missing_ok=True)
    if getattr(sys, "frozen", False):
        _schedule_helper_cleanup(Path(sys.executable).resolve())
    return {
        "operation": "uninstall",
        "install_root": str(root),
        "status": "COMPLETE",
        "removed": removed,
    }


def _perform_uninstall(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    security_root: str | Path | None,
) -> list[str]:
    _verify_managed_checksums(root, manifest)
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
    return [str(target) for target, _ in quarantined]


def _prepare_deferred_uninstall(
    root: Path,
    manifest: dict[str, Any],
    key: bytes,
    *,
    security_root: str | Path | None,
    parent_pid: int,
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
            "expires_at": (
                datetime.now(UTC) + timedelta(seconds=_DEFERRED_REQUEST_TTL_SECONDS)
            ).isoformat(),
        },
        key,
    )
    _write_manifest(request_path, value)
    return request_path


def _launch_deferred_helper(
    running_executable: Path, request_file: Path, parent_pid: int
) -> None:
    helper_dir = request_file.parent / f"helper-{uuid.uuid4().hex}"
    helper_dir.mkdir(parents=True, exist_ok=False)
    helper = helper_dir / _native_executable_name()
    _copy_atomic(running_executable, helper)
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
            "_complete-uninstall",
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
    return root, path, value, key


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
        digest = item.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ValueError("invalid install manifest file entry")
        entries.append({"path": path, "sha256": digest})
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
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
            raise ValueError("unsafe install manifest path")
        target = (root / relative).resolve()
        if root not in target.parents or target.name in seen:
            raise ValueError("manifest path escapes install root or is duplicated")
        seen.add(target.name)
        targets.append(target)
    return tuple(targets)


def _single_managed_file(root: Path, manifest: Mapping[str, Any]) -> Path:
    files = _manifest_files(root, manifest)
    if len(files) != 1:
        raise ValueError("V1 lifecycle requires exactly one managed executable")
    return files[0]


def _verify_managed_checksums(root: Path, manifest: Mapping[str, Any]) -> None:
    all_paths: set[Path] = set()
    for field, required in (("files", True), ("backups", False)):
        entries = _manifest_entries(manifest, field, required=required)
        targets = _manifest_files(root, manifest, field=field, required=required)
        for item, target in zip(entries, targets, strict=True):
            if target in all_paths:
                raise ValueError("managed path is duplicated across manifest sections")
            all_paths.add(target)
            expected = item["sha256"]
            if (
                len(expected) != 64
                or not hmac.compare_digest(_sha256(target) if target.is_file() else "", expected)
            ):
                raise ValueError(
                    f"managed file is missing or modified; refusing mutation: {target}"
                )


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
    descriptor, name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
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
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
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
