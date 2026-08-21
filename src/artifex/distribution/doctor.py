"""Distribution diagnostics with an allowlisted, dry-run-first repair path."""

from __future__ import annotations

from pathlib import Path

from artifex.distribution.discovery import discover_environment
from artifex.distribution.models import DistributionDoctorReport, DoctorFinding

_SAFE_REMEDIATIONS = frozenset({"create-artifex-state-directory"})


def run_distribution_doctor(
    project_root: str | Path | None = None,
    *,
    fix: bool = False,
    apply: bool = False,
) -> DistributionDoctorReport:
    if apply and not fix:
        raise ValueError("--apply requires --fix")
    discovery = discover_environment(resource_path=project_root or ".")
    findings: list[DoctorFinding] = []
    git = next(tool for tool in discovery.tools if tool.tool == "git")
    findings.append(
        DoctorFinding(
            "git",
            git.status,
            git.detail,
            None,
        )
    )
    state: Path | None = None
    if project_root is not None:
        root = Path(project_root).resolve()
        state = root / ".artifex"
        exists = state.is_dir()
        findings.append(
            DoctorFinding(
                "project-state",
                "PASS" if exists else "DEGRADED",
                f"ARTIFEX state {'exists' if exists else 'is missing'} at {state}",
                None if exists else "create-artifex-state-directory",
            )
        )
    fixes: list[dict[str, object]] = []
    if fix:
        for finding in findings:
            remediation = finding.remediation_id
            if remediation is None:
                continue
            if remediation not in _SAFE_REMEDIATIONS:
                fixes.append({"id": remediation, "status": "BLOCKED_NOT_ALLOWLISTED"})
                continue
            status = "PLANNED"
            if apply:
                assert state is not None
                state.mkdir(parents=True, exist_ok=True)
                status = "APPLIED"
            fixes.append({"id": remediation, "status": status, "target": str(state)})
    if apply and state is not None and state.is_dir():
        findings = [
            (
                DoctorFinding("project-state", "PASS", f"ARTIFEX state exists at {state}")
                if finding.finding_id == "project-state"
                else finding
            )
            for finding in findings
        ]
    statuses = {finding.status for finding in findings}
    overall = "FAIL" if "FAIL" in statuses else "DEGRADED" if "DEGRADED" in statuses else "PASS"
    return DistributionDoctorReport(overall, tuple(findings), tuple(fixes), dry_run=not apply)
