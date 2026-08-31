"""Bridge explicit NSIS consent into the authenticated distribution lifecycle."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from artifex.distribution.artifact import runtime_release_identity
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
    if (root / MANIFEST_NAME).is_file():
        decision = upgrade_plan(
            source,
            root,
            identity_probe=_running_artifact_identity,
            managed_service=True,
            service_state_root=service_state,
            service_id="artifex-managed-service",
            service_readiness_timeout_seconds=60,
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
        )
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
    return result.to_dict()


def remove_installer(install_root: str | Path) -> dict[str, Any]:
    """Unregister the service and remove manifest-owned files for NSIS."""

    root = Path(install_root).resolve()
    decision = uninstall_plan(
        root,
        managed_service=True,
        service_id="artifex-managed-service",
        service_readiness_timeout_seconds=60,
    )
    return uninstall(
        root,
        confirmation_token=decision.confirmation_token,
        managed_service=True,
        service_id="artifex-managed-service",
        service_readiness_timeout_seconds=60,
    )
