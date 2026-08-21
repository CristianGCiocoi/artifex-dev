"""Manifest-scoped, reversible install, upgrade, and uninstall operations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex.distribution.presentation import explain_decision, require_approval

MANIFEST_NAME = "artifex-install-manifest.json"


@dataclass(frozen=True, slots=True)
class InstallResult:
    operation: str
    install_root: str
    executable: str
    manifest: str
    backup: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "operation": self.operation,
            "install_root": self.install_root,
            "executable": self.executable,
            "manifest": self.manifest,
            "backup": self.backup,
        }


def install_plan(source_executable: str | Path, install_root: str | Path) -> Any:
    source = Path(source_executable).resolve()
    root = Path(install_root).resolve()
    return explain_decision(
        "install ARTIFEX",
        "REVERSIBLE",
        effects=(f"copy {source.name} into {root}", f"write {MANIFEST_NAME}"),
        rollback=f"uninstall using {root / MANIFEST_NAME}",
    )


def install(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    confirmation_token: str | None,
) -> InstallResult:
    source = Path(source_executable).resolve()
    root = Path(install_root).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"frozen ARTIFEX executable not found: {source}")
    if root == Path(root.anchor) or len(root.parts) < 2:
        raise ValueError("refusing broad install root")
    decision = install_plan(source, root)
    require_approval(decision, confirmation_token)
    root.mkdir(parents=True, exist_ok=True)
    destination = root / _native_executable_name()
    manifest_path = root / MANIFEST_NAME
    if manifest_path.exists() or destination.exists():
        raise FileExistsError("ARTIFEX is already installed; use upgrade")
    _copy_atomic(source, destination)
    _write_manifest(
        manifest_path,
        {
            "schema_version": "1.0",
            "install_root": str(root),
            "files": [{"path": destination.name, "sha256": _sha256(destination)}],
        },
    )
    return InstallResult("install", str(root), str(destination), str(manifest_path))


def upgrade(
    source_executable: str | Path,
    install_root: str | Path,
    *,
    confirmation_token: str | None,
) -> InstallResult:
    source = Path(source_executable).resolve()
    root, manifest_path, manifest = _load_manifest(install_root)
    destination = _single_managed_file(root, manifest)
    decision = upgrade_plan(root)
    require_approval(decision, confirmation_token)
    if not source.is_file():
        raise FileNotFoundError(f"frozen ARTIFEX executable not found: {source}")
    _verify_managed_checksums(root, manifest)
    backup = root / f"{destination.name}.pre-upgrade.bak"
    if destination.is_file():
        _copy_atomic(destination, backup)
    try:
        _copy_atomic(source, destination)
        _write_manifest(
            manifest_path,
            {
                "schema_version": "1.0",
                "install_root": str(root),
                "files": [{"path": destination.name, "sha256": _sha256(destination)}],
                "backups": (
                    [{"path": backup.name, "sha256": _sha256(backup)}]
                    if backup.exists()
                    else []
                ),
            },
        )
    except Exception:
        if backup.exists():
            _copy_atomic(backup, destination)
        raise
    return InstallResult(
        "upgrade", str(root), str(destination), str(manifest_path), str(backup)
    )


def upgrade_plan(install_root: str | Path) -> Any:
    root, _, manifest = _load_manifest(install_root)
    destination = _single_managed_file(root, manifest)
    return explain_decision(
        "upgrade ARTIFEX",
        "REVERSIBLE",
        effects=(f"replace manifest-owned file {destination.name}",),
        rollback="restore the verified pre-upgrade backup",
    )


def uninstall_plan(install_root: str | Path) -> Any:
    root, _, manifest = _load_manifest(install_root)
    managed = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    return explain_decision(
        "uninstall ARTIFEX",
        "REVERSIBLE",
        effects=tuple(f"remove manifest-owned file {path.name}" for path in managed),
        rollback="reinstall the frozen artifact; unrelated files remain untouched",
    )


def uninstall(install_root: str | Path, *, confirmation_token: str | None) -> dict[str, Any]:
    root, manifest_path, manifest = _load_manifest(install_root)
    require_approval(uninstall_plan(root), confirmation_token)
    _verify_managed_checksums(root, manifest)
    removed: list[str] = []
    targets = _manifest_files(root, manifest) + _manifest_files(
        root, manifest, field="backups", required=False
    )
    for target in targets:
        if target.is_file():
            target.unlink()
            removed.append(str(target))
    manifest_path.unlink()
    # Deliberately do not delete the install directory: it may contain user files.
    return {"operation": "uninstall", "install_root": str(root), "removed": removed}


def _native_executable_name() -> str:
    return "artifex.exe" if os.name == "nt" else "artifex"


def _load_manifest(install_root: str | Path) -> tuple[Path, Path, dict[str, Any]]:
    root = Path(install_root).resolve()
    path = root / MANIFEST_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"valid ARTIFEX install manifest required: {path}") from exc
    if not isinstance(value, dict) or value.get("install_root") != str(root):
        raise ValueError("install manifest root does not match target")
    return root, path, value


def _manifest_files(
    root: Path,
    manifest: dict[str, Any],
    *,
    field: str = "files",
    required: bool = True,
) -> tuple[Path, ...]:
    values = manifest.get(field, [])
    if not isinstance(values, list) or (required and not values):
        raise ValueError(f"install manifest contains no managed {field}")
    targets: list[Path] = []
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("invalid install manifest file entry")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
            raise ValueError("unsafe install manifest path")
        target = (root / relative).resolve()
        if root not in target.parents:
            raise ValueError("manifest path escapes install root")
        targets.append(target)
    return tuple(targets)


def _single_managed_file(root: Path, manifest: dict[str, Any]) -> Path:
    files = _manifest_files(root, manifest)
    if len(files) != 1:
        raise ValueError("V1 upgrade requires exactly one managed executable")
    return files[0]


def _verify_managed_checksums(root: Path, manifest: dict[str, Any]) -> None:
    for field, required in (("files", True), ("backups", False)):
        values = manifest.get(field, [])
        targets = _manifest_files(root, manifest, field=field, required=required)
        assert isinstance(values, list)
        for item, target in zip(values, targets, strict=True):
            expected = item.get("sha256")
            if (
                not isinstance(expected, str)
                or not target.is_file()
                or _sha256(target) != expected
            ):
                raise ValueError(
                    f"managed file is missing or modified; refusing mutation: {target}"
                )


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


def _write_manifest(path: Path, value: dict[str, Any]) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".manifest.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
