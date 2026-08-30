"""Bridge explicit NSIS consent into the authenticated distribution lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from artifex.distribution.lifecycle import (
    MANIFEST_NAME,
    install,
    install_plan,
    uninstall,
    uninstall_plan,
    upgrade,
    upgrade_plan,
)


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
            managed_service=True,
            service_state_root=service_state,
            service_id="artifex-managed-service",
            service_readiness_timeout_seconds=60,
        )
        result = upgrade(
            source,
            root,
            confirmation_token=decision.confirmation_token,
            managed_service=True,
            service_state_root=service_state,
            service_id="artifex-managed-service",
            service_readiness_timeout_seconds=60,
        )
    else:
        decision = install_plan(
            source,
            root,
            managed_service=True,
            service_state_root=service_state,
            service_id="artifex-managed-service",
            service_readiness_timeout_seconds=60,
        )
        result = install(
            source,
            root,
            confirmation_token=decision.confirmation_token,
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
