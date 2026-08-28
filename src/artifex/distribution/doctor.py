"""Distribution diagnostics with an allowlisted, dry-run-first repair path."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from artifex.distribution.discovery import discover_environment
from artifex.distribution.models import DistributionDoctorReport, DoctorFinding

_SAFE_REMEDIATIONS = frozenset({"create-artifex-state-directory"})


def run_distribution_doctor(
    project_root: str | Path | None = None,
    *,
    fix: bool = False,
    apply: bool = False,
    capability_graph: object | None = None,
    provider_error: str | None = None,
    runstore_path: str | Path | None = None,
    service_state_path: str | Path | None = None,
    clock: Callable[[], float] = time.time,
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
        findings.extend(_provider_findings(capability_graph, provider_error))
    if service_state_path is not None:
        findings.append(_service_finding(Path(service_state_path)))
    if runstore_path is not None:
        runstore, fencing = _runstore_findings(Path(runstore_path), now=int(clock()))
        findings.extend((runstore, fencing))
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


def _provider_findings(graph: object | None, provider_error: str | None) -> list[DoctorFinding]:
    if provider_error is not None:
        return [
            DoctorFinding(
                "provider-composition",
                "FAIL",
                "Persisted provider setup could not be consumed safely by this process.",
                "review-provider-setup",
                {"error_type": provider_error, "credential_material_present": False},
            ),
            _manual_fallback_finding(),
        ]
    providers = tuple(getattr(graph, "providers", ())) if graph is not None else ()
    findings: list[DoctorFinding] = []
    automated_ready = False
    for provider in providers:
        provider_id = str(getattr(provider, "provider_id", "unknown"))
        readiness = getattr(provider, "readiness", None)
        state_value = getattr(getattr(readiness, "state", None), "value", "UNKNOWN")
        certified_roles = tuple(
            sorted(getattr(role, "value", str(role)) for role in provider.certified_roles)
        )
        candidate = state_value == "AVAILABLE" and bool(certified_roles)
        automated_ready = automated_ready or candidate
        findings.append(
            DoctorFinding(
                f"provider:{provider_id}",
                "PASS" if candidate else "DEGRADED",
                (
                    f"{provider_id} is available with a certified role."
                    if candidate
                    else f"{provider_id} is not an eligible automated bootstrap candidate."
                ),
                None if candidate else "review-provider-readiness-and-certification",
                {
                    "provider_id": provider_id,
                    "readiness": state_value,
                    "certified_roles": list(certified_roles),
                    "automated_candidate": candidate,
                    "credential_material_present": False,
                },
            )
        )
    if not automated_ready:
        findings.append(_manual_fallback_finding())
    return findings


def _manual_fallback_finding() -> DoctorFinding:
    return DoctorFinding(
        "manual-fallback",
        "DEGRADED",
        (
            "No certified automated provider is ready. ManualIntegration is available: "
            "create a packet with manual.packet.create and submit the completed result "
            "with manual.result.submit."
        ),
        "use-manual-integration",
        {
            "integration_id": "manual",
            "packet_operation": "manual.packet.create",
            "result_operation": "manual.result.submit",
            "self_acceptance": False,
            "credential_material_present": False,
        },
    )


def _service_finding(path: Path) -> DoctorFinding:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        return DoctorFinding(
            "managed-service",
            "DEGRADED",
            f"Managed-service state is absent at {resolved}.",
            "start-managed-service",
            {"state": "ABSENT", "state_file_present": False},
        )
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DoctorFinding(
            "managed-service",
            "FAIL",
            f"Managed-service state at {resolved} is unreadable.",
            "repair-managed-service-state",
            {"state": "UNKNOWN", "state_file_present": True},
        )
    if not isinstance(value, dict):
        state = "UNKNOWN"
    else:
        observed = next(
            (
                value[key]
                for key in ("lifecycle_state", "status", "state", "lifecycle")
                if key in value
            ),
            "UNKNOWN",
        )
        state = _safe_service_state(observed)
    healthy = state in {"RUNNING", "ACTIVE", "READY"}
    details: dict[str, object] = {"state": state, "state_file_present": True}
    if isinstance(value, dict):
        details.update(
            {
                "schema_version": _safe_identifier(value.get("schema_version")),
                "frontend_independent": (
                    value.get("frontend_independent")
                    if isinstance(value.get("frontend_independent"), bool)
                    else None
                ),
                "process_id_present": isinstance(value.get("process_id"), int),
                "coordinator_generation": (
                    value.get("coordinator_generation")
                    if isinstance(value.get("coordinator_generation"), int)
                    else None
                ),
                "transport": _safe_transport_summary(value.get("transport")),
            }
        )
    return DoctorFinding(
        "managed-service",
        "PASS" if healthy else "DEGRADED",
        f"Managed-service state is {state}.",
        None if healthy else "start-managed-service",
        details,
    )


def _safe_service_state(value: object) -> str:
    if not isinstance(value, str):
        return "UNKNOWN"
    normalized = value.strip().upper()
    allowed = {
        "STARTING",
        "RUNNING",
        "STOPPING",
        "STOPPED",
        "FAILED",
        "ACTIVE",
        "INACTIVE",
        "READY",
        "UNKNOWN",
    }
    return normalized if normalized in allowed else "UNKNOWN"


def _safe_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 64:
        return None
    return (
        candidate
        if all(character.isalnum() or character in "._-" for character in candidate)
        else None
    )


def _safe_transport_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"configured": False, "kind": None, "protocol": None}
    return {
        "configured": True,
        "kind": _safe_identifier(value.get("kind")),
        "protocol": _safe_identifier(value.get("protocol")),
    }


def _runstore_findings(path: Path, *, now: int) -> tuple[DoctorFinding, DoctorFinding]:
    resolved = path.expanduser().resolve()
    absent = DoctorFinding(
        "runstore",
        "FAIL",
        f"RunStore is absent at {resolved}.",
        "start-managed-service",
        {"state": "ABSENT", "database_present": False},
    )
    no_fence = DoctorFinding(
        "coordinator-fence",
        "DEGRADED",
        "No coordinator lease can be inspected because RunStore is absent.",
        "start-managed-service",
        {"state": "UNKNOWN"},
    )
    if not resolved.is_file():
        return absent, no_fence
    try:
        uri = resolved.as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            required = {"coordinator_lease", "runs", "project_jobs", "attempts"}
            missing = sorted(required - tables)
            lease: tuple[Any, ...] | None = None
            if "coordinator_lease" in tables:
                lease = connection.execute(
                    "SELECT generation, expires_at FROM coordinator_lease WHERE id = 1"
                ).fetchone()
    except (OSError, sqlite3.Error):
        return (
            DoctorFinding(
                "runstore",
                "FAIL",
                f"RunStore at {resolved} is unreadable or not valid SQLite.",
                "repair-runstore",
                {"state": "UNREADABLE", "database_present": True},
            ),
            DoctorFinding(
                "coordinator-fence",
                "DEGRADED",
                "Coordinator fencing state is unavailable.",
                "repair-runstore",
                {"state": "UNKNOWN"},
            ),
        )
    integrity = bool(quick_check and quick_check[0] == "ok")
    runstore_ok = integrity and not missing
    runstore = DoctorFinding(
        "runstore",
        "PASS" if runstore_ok else "FAIL",
        (
            "RunStore is readable and has the required durable runtime schema."
            if runstore_ok
            else "RunStore integrity or durable runtime schema validation failed."
        ),
        None if runstore_ok else "repair-runstore",
        {
            "state": "READY" if runstore_ok else "INVALID",
            "database_present": True,
            "integrity": "PASS" if integrity else "FAIL",
            "missing_required_tables": missing,
        },
    )
    if lease is None:
        fencing = DoctorFinding(
            "coordinator-fence",
            "DEGRADED",
            "RunStore has no active coordinator lease.",
            "start-managed-service",
            {"state": "ABSENT"},
        )
    else:
        generation, expires_at = int(lease[0]), int(lease[1])
        active = expires_at > now
        fencing = DoctorFinding(
            "coordinator-fence",
            "PASS" if active else "DEGRADED",
            f"Coordinator lease generation {generation} is {'active' if active else 'expired'}.",
            None if active else "restart-managed-service",
            {
                "state": "ACTIVE" if active else "EXPIRED",
                "generation": generation,
                "expires_at": expires_at,
            },
        )
    return runstore, fencing
