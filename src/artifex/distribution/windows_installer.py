"""Bridge explicit NSIS consent into the authenticated distribution lifecycle."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from artifex import __version__
from artifex.distribution.artifact import runtime_release_identity
from artifex.distribution.installed_state import (
    INSTALLATION_RECORD_NAME,
    InstalledStateRecord,
    migrate_legacy_state,
    read_installed_state_record,
    remove_installed_state_record,
    write_installed_state_record,
)
from artifex.distribution.lifecycle import (
    MANIFEST_NAME,
    install,
    install_plan,
    uninstall,
    uninstall_plan,
    upgrade,
    upgrade_plan,
)


def _running_artifact_identity(
    source_executable: Path, timeout_seconds: float
) -> Mapping[str, Any]:
    """Return identity from the already-running frozen artifact.

    NSIS invokes the extracted artifact itself to apply the lifecycle. Re-spawning
    that same executable for each plan/apply verification can trigger multiple
    cold antivirus scans and exceed the outer installer deadline. The path bind
    keeps this fail-closed: only the exact currently executing artifact may use
    its in-process runtime identity, which verify_artifact still checks against
    the adjacent manifest and full bundle inventory.
    """

    del timeout_seconds
    source = source_executable.absolute().resolve()
    running = Path(sys.argv[0]).absolute().resolve()
    if source != running:
        raise ValueError("installer lifecycle source is not the running artifact")
    identity = runtime_release_identity()
    if identity.get("format") == "python-source" or identity.get("sha256") is None:
        raise ValueError("installer lifecycle requires a frozen runtime identity")
    return identity


def apply_installer(
    source_executable: str | Path,
    install_root: str | Path,
    service_state_root: str | Path,
) -> dict[str, Any]:
    """Install or upgrade after the user approves the enclosing NSIS UI."""

    source = Path(source_executable).resolve()
    root = Path(install_root).resolve()
    service_state = Path(service_state_root).resolve()
    record_path = service_state.parent / INSTALLATION_RECORD_NAME
    prior_record = record_path.read_bytes() if record_path.is_file() else None
    installing = not (root / MANIFEST_NAME).is_file()
    migration: dict[str, object] | None = None
    try:
        if installing:
            migration = migrate_legacy_state(
                source=service_state.with_name("runtime"), target=service_state
            ).to_dict()
        write_installed_state_record(
            InstalledStateRecord(root, service_state, __version__), record_path
        )
        if not installing:
            decision = upgrade_plan(
                source,
                root,
                identity_probe=_running_artifact_identity,
                managed_service=True,
                service_state_root=service_state,
                service_id="artifex-managed-service",
                service_readiness_timeout_seconds=60,
                allow_service_state_root_transition=True,
            )
            result = upgrade(
                source,
                root,
                confirmation_token=decision.confirmation_token,
                identity_probe=_running_artifact_identity,
                managed_service=True,
                service_state_root=service_state,
                service_id="artifex-managed-service",
                service_readiness_timeout_seconds=60,
                allow_service_state_root_transition=True,
            )
            result_migration = getattr(result, "state_migration", None)
            migration = dict(result_migration) if result_migration is not None else migration
        else:
            decision = install_plan(
                source,
                root,
                identity_probe=_running_artifact_identity,
                managed_service=True,
                service_state_root=service_state,
                service_id="artifex-managed-service",
                service_readiness_timeout_seconds=60,
            )
            result = install(
                source,
                root,
                confirmation_token=decision.confirmation_token,
                identity_probe=_running_artifact_identity,
                managed_service=True,
                service_state_root=service_state,
                service_id="artifex-managed-service",
                service_readiness_timeout_seconds=60,
            )
    except Exception:
        if prior_record is None:
            record_path.unlink(missing_ok=True)
        else:
            record_path.write_bytes(prior_record)
        raise
    value = result.to_dict()
    value.update(
        {
            "canonical_state_root": str(service_state),
            "installation_record": str(record_path),
            "state_migration": migration,
            "readiness": "PASS",
        }
    )
    return value


def remove_installer(install_root: str | Path) -> dict[str, Any]:
    """Unregister the service and remove manifest-owned files for NSIS."""

    root = Path(install_root).resolve()
    decision = uninstall_plan(
        root,
        managed_service=True,
        service_id="artifex-managed-service",
        service_readiness_timeout_seconds=60,
    )
    value = uninstall(
        root,
        confirmation_token=decision.confirmation_token,
        managed_service=True,
        service_id="artifex-managed-service",
        service_readiness_timeout_seconds=60,
    )
    try:
        record = read_installed_state_record()
    except ValueError:
        record = None
        value["installation_record_status"] = "INVALID_RETAINED_FOR_DIAGNOSTICS"
    retained_state = str(record.state_root) if record is not None else None
    if record is not None:
        with suppress(FileNotFoundError):
            remove_installed_state_record(root)
    value["retained_state_root"] = retained_state
    value["retained_data_removed"] = False
    return value
