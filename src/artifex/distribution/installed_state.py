"""Canonical installed-state discovery and compatibility migration.

The installer owns only the location record.  Runtime data below ``state_root``
continues to be owned by the managed service and its authoritative stores.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INSTALLATION_RECORD_SCHEMA = "artifex.installed-state/v1"
INSTALLATION_RECORD_NAME = "installation.json"
CANONICAL_STATE_DIRECTORY = "state"
LEGACY_STATE_DIRECTORY = "runtime"


@dataclass(frozen=True, slots=True)
class InstalledStateRecord:
    install_root: Path
    state_root: Path
    product_version: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.install_root, "install_root"),
            (self.state_root, "state_root"),
        ):
            if not value.is_absolute() or value == Path(value.anchor):
                raise ValueError(f"{label} must be a non-root absolute path")
        if not self.product_version.strip():
            raise ValueError("product_version must be non-empty")

    def _payload(self) -> dict[str, str]:
        return {
            "schema": INSTALLATION_RECORD_SCHEMA,
            "authority": "ARTIFEX_INSTALLER_LOCATION_RECORD",
            "install_root": str(self.install_root.resolve()),
            "state_root": str(self.state_root.resolve()),
            "product_version": self.product_version,
        }

    def to_dict(self) -> dict[str, str]:
        payload = self._payload()
        payload["record_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> InstalledStateRecord:
        required = {
            "schema",
            "authority",
            "install_root",
            "state_root",
            "product_version",
            "record_sha256",
        }
        if set(value) != required:
            raise ValueError("installed-state record fields are invalid")
        if value["schema"] != INSTALLATION_RECORD_SCHEMA:
            raise ValueError("installed-state record schema is unsupported")
        if value["authority"] != "ARTIFEX_INSTALLER_LOCATION_RECORD":
            raise ValueError("installed-state record authority is invalid")
        text_fields = ("install_root", "state_root", "product_version", "record_sha256")
        if any(not isinstance(value[field], str) for field in text_fields):
            raise ValueError("installed-state record values are invalid")
        payload = {key: value[key] for key in required - {"record_sha256"}}
        expected = hashlib.sha256(_canonical(payload)).hexdigest()
        if value["record_sha256"] != expected:
            raise ValueError("installed-state record digest is invalid")
        return cls(
            install_root=Path(value["install_root"]),
            state_root=Path(value["state_root"]),
            product_version=value["product_version"],
        )


@dataclass(frozen=True, slots=True)
class StateMigrationResult:
    status: str
    source: Path
    target: Path
    legacy_retained: bool
    workspace_source: Path
    workspace_target: Path

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "source": str(self.source),
            "target": str(self.target),
            "legacy_retained": self.legacy_retained,
            "workspace_source": str(self.workspace_source),
            "workspace_target": str(self.workspace_target),
        }


def installed_data_root(*, local_app_data: str | Path | None = None) -> Path:
    if local_app_data is not None:
        base = Path(local_app_data).expanduser()
    elif os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    elif os.environ.get("XDG_STATE_HOME"):
        base = Path(os.environ["XDG_STATE_HOME"]).expanduser()
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path.home() / ".local" / "state"
    return (
        base / ("ARTIFEX" if os.name == "nt" or sys.platform == "darwin" else "artifex")
    ).resolve()


def installation_record_path(*, local_app_data: str | Path | None = None) -> Path:
    return installed_data_root(local_app_data=local_app_data) / INSTALLATION_RECORD_NAME


def canonical_state_root(*, local_app_data: str | Path | None = None) -> Path:
    root = installed_data_root(local_app_data=local_app_data)
    if os.name == "nt" or sys.platform == "darwin":
        return root / CANONICAL_STATE_DIRECTORY
    # Preserve the established XDG state location for unpackaged Unix clients.
    return root


def legacy_state_root(*, local_app_data: str | Path | None = None) -> Path:
    return installed_data_root(local_app_data=local_app_data) / LEGACY_STATE_DIRECTORY


def read_installed_state_record(
    path: str | Path | None = None,
    *,
    local_app_data: str | Path | None = None,
) -> InstalledStateRecord | None:
    target = (
        Path(path).resolve()
        if path is not None
        else installation_record_path(local_app_data=local_app_data)
    )
    if not target.is_file():
        return None
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("installed-state record is unreadable") from exc
    if not isinstance(value, Mapping):
        raise ValueError("installed-state record must be an object")
    return InstalledStateRecord.from_dict(value)


def discover_canonical_state_root(
    explicit: str | Path | None = None,
    *,
    record_path: str | Path | None = None,
    local_app_data: str | Path | None = None,
) -> Path:
    if explicit is not None:
        selected = Path(explicit).expanduser().resolve()
    elif os.environ.get("ARTIFEX_STATE_ROOT"):
        selected = Path(os.environ["ARTIFEX_STATE_ROOT"]).expanduser().resolve()
    else:
        record = read_installed_state_record(record_path, local_app_data=local_app_data)
        selected = (
            record.state_root.resolve()
            if record is not None
            else canonical_state_root(local_app_data=local_app_data)
        )
    if selected == Path(selected.anchor):
        raise ValueError("canonical state root cannot be a filesystem root")
    return selected


def write_installed_state_record(
    record: InstalledStateRecord,
    path: str | Path | None = None,
    *,
    local_app_data: str | Path | None = None,
) -> Path:
    target = (
        Path(path).resolve()
        if path is not None
        else installation_record_path(local_app_data=local_app_data)
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(record.to_dict()) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def remove_installed_state_record(
    install_root: str | Path,
    path: str | Path | None = None,
    *,
    local_app_data: str | Path | None = None,
) -> bool:
    target = (
        Path(path).resolve()
        if path is not None
        else installation_record_path(local_app_data=local_app_data)
    )
    record = read_installed_state_record(target)
    if record is None:
        return False
    if record.install_root.resolve() != Path(install_root).resolve():
        raise ValueError("installed-state record belongs to a different installation")
    target.unlink()
    return True


def migrate_legacy_state(
    *,
    source: str | Path | None = None,
    target: str | Path | None = None,
    local_app_data: str | Path | None = None,
) -> StateMigrationResult:
    """Copy legacy state to the canonical root without deleting user data.

    Keeping the legacy source makes an installer rollback able to restart the
    previous service registration.  A later retry is accepted only when the
    already-copied target still has the exact same file inventory and digests.
    """

    old = (
        Path(source).resolve()
        if source is not None
        else legacy_state_root(local_app_data=local_app_data)
    )
    new = (
        Path(target).resolve()
        if target is not None
        else canonical_state_root(local_app_data=local_app_data)
    )
    _validate_migration_pair(old, new)
    old_workspaces = old.with_name(f"{old.name}-workspaces")
    new_workspaces = new.with_name(f"{new.name}-workspaces")
    if not old.exists():
        return StateMigrationResult("NOT_REQUIRED", old, new, False, old_workspaces, new_workspaces)
    if not old.is_dir() or old.is_symlink():
        raise ValueError("legacy state root is not a safe directory")
    status = "COPIED_LEGACY_STATE"
    if new.exists():
        if not new.is_dir() or new.is_symlink() or _tree_digest(old) != _tree_digest(new):
            raise ValueError("canonical and legacy state roots contain ambiguous data")
        status = "LEGACY_COPY_ALREADY_PRESENT"
    else:
        _copy_tree_atomic(old, new)
    if old_workspaces.exists():
        if not old_workspaces.is_dir() or old_workspaces.is_symlink():
            raise ValueError("legacy workspace root is not a safe directory")
        if new_workspaces.exists():
            if (
                not new_workspaces.is_dir()
                or new_workspaces.is_symlink()
                or _tree_digest(old_workspaces) != _tree_digest(new_workspaces)
            ):
                raise ValueError("canonical and legacy workspace roots contain ambiguous data")
        else:
            _copy_tree_atomic(old_workspaces, new_workspaces)
    return StateMigrationResult(status, old, new, True, old_workspaces, new_workspaces)


def _validate_migration_pair(source: Path, target: Path) -> None:
    if source == target:
        return
    if source.parent != target.parent:
        raise ValueError("state migration roots must be siblings")
    if source == Path(source.anchor) or target == Path(target.anchor):
        raise ValueError("state migration cannot use a filesystem root")


def _copy_tree_atomic(source: Path, target: Path) -> None:
    temporary = target.with_name(f".{target.name}.migration-{os.getpid()}")
    if temporary.exists():
        raise FileExistsError("state migration staging directory already exists")
    try:
        shutil.copytree(source, temporary, symlinks=True)
        if _tree_digest(source) != _tree_digest(temporary):
            raise OSError("state migration copy verification failed")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind = "L"
            payload = os.readlink(path).encode("utf-8")
        elif path.is_dir():
            kind = "D"
            payload = b""
        elif path.is_file():
            kind = "F"
            payload = hashlib.sha256(path.read_bytes()).digest()
        else:
            raise ValueError("state migration encountered an unsupported filesystem entry")
        digest.update(kind.encode("ascii") + b"\0" + relative.encode("utf-8") + b"\0" + payload)
    return digest.hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
