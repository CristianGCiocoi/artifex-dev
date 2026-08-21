"""Non-mutating environment diagnostics with safe remediation guidance."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from artifex.integrations.contracts import HealthStatus
from artifex.integrations.registry import IntegrationRegistry


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    check_id: str
    status: HealthStatus
    summary: str
    remediation: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "id": self.check_id,
            "status": self.status.value,
            "summary": self.summary,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    status: HealthStatus
    checks: tuple[DoctorCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "checks": [check.to_dict() for check in self.checks],
        }


def run_doctor(
    registry: IntegrationRegistry,
    *,
    project_root: str | Path | None = None,
) -> DoctorReport:
    checks = [
        DoctorCheck(
            "python",
            HealthStatus.PASS if sys.version_info >= (3, 12) else HealthStatus.FAIL,
            f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            None if sys.version_info >= (3, 12) else "Install the packaged ARTIFEX release.",
        ),
        DoctorCheck(
            "git",
            HealthStatus.PASS if shutil.which("git") else HealthStatus.FAIL,
            "Git executable is available" if shutil.which("git") else "Git executable is missing",
            None if shutil.which("git") else "Install Git and ensure it is on PATH.",
        ),
    ]
    if project_root is not None:
        root = Path(project_root).resolve()
        present = root.is_dir() and (root / ".artifex").is_dir()
        checks.append(
            DoctorCheck(
                "project",
                HealthStatus.PASS if present else HealthStatus.DEGRADED,
                f"ARTIFEX project metadata {'found' if present else 'not found'} at {root}",
                (
                    None
                    if present
                    else "Run project initialization or select an ARTIFEX project root."
                ),
            )
        )
    for integration in registry.all():
        health = integration.health()
        checks.append(
            DoctorCheck(
                f"integration:{integration.metadata.integration_id}",
                health.status,
                health.summary,
            )
        )
    statuses = {check.status for check in checks}
    if HealthStatus.FAIL in statuses:
        overall = HealthStatus.FAIL
    elif HealthStatus.DEGRADED in statuses or HealthStatus.UNKNOWN in statuses:
        overall = HealthStatus.DEGRADED
    else:
        overall = HealthStatus.PASS
    return DoctorReport(overall, tuple(checks))
