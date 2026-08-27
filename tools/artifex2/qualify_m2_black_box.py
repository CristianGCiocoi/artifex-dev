"""Qualify M2 mandatory journeys through an installed wheel's public CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _call(
    python: Path,
    operation: str,
    arguments: dict[str, Any],
    *,
    expect_ok: bool = True,
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(python),
            "-m",
            "artifex.cli",
            "call",
            operation,
            "--arguments",
            json.dumps(arguments, separators=(",", ":")),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if not completed.stdout.strip():
        raise AssertionError(
            f"{operation} returned no JSON: exit={completed.returncode} stderr={completed.stderr}"
        )
    result = json.loads(completed.stdout)
    if bool(result["ok"]) is not expect_ok:
        raise AssertionError(
            f"{operation} expected ok={expect_ok}: exit={completed.returncode} result={result}"
        )
    if expect_ok and completed.returncode != 0:
        raise AssertionError(f"{operation} succeeded but exited {completed.returncode}")
    if not expect_ok and completed.returncode == 0:
        raise AssertionError(f"{operation} failed semantically but exited zero")
    return result


def _envelope(identifier: str, project_id: str) -> dict[str, Any]:
    return {
        "envelope_id": identifier,
        "version": 1,
        "project_id": project_id,
        "objective": "M2 public black-box qualification",
        "baseline_revision": 1,
        "actor_id": "architect",
        "allowed_paths": [".artifex/project-model.json"],
        "allowed_capabilities": ["filesystem:workspace"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 2,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
    }


def _bootstrap(
    python: Path,
    store: Path,
    service_id: str,
    *,
    prefix: str,
    project_id: str,
) -> dict[str, Any]:
    return _call(
        python,
        "runtime.bootstrap",
        {
            "store_path": str(store),
            "service_id": service_id,
            "envelope": _envelope(f"{prefix}-envelope", project_id),
            "workstream_id": f"{prefix}-workstream",
            "run_id": f"{prefix}-run",
            "project_job_id": f"{prefix}-job",
            "attempt_id": f"{prefix}-attempt",
            "purpose": f"{prefix} public journey",
        },
    )


def _j05(python: Path, root: Path) -> dict[str, Any]:
    store = root / "j05" / "runstore.sqlite3"
    service_id = "managed-j05"
    _bootstrap(python, store, service_id, prefix="j05", project_id="project-j05")
    common = {"store_path": str(store), "service_id": service_id}
    recovered = _call(
        python, "runtime.status", {**common, "run_id": "j05-run"}
    )["value"]
    _call(
        python,
        "runtime.attempt.finish",
        {**common, "attempt_id": "j05-attempt", "result_claim": "validation passed"},
    )
    finished = _call(
        python, "runtime.status", {**common, "run_id": "j05-run"}
    )["value"]
    _call(
        python,
        "runtime.accept",
        {
            **common,
            "project_job_id": "j05-job",
            "evidence_valid": True,
            "reason": "clean installed-wheel evidence",
        },
    )
    accepted = _call(
        python, "runtime.status", {**common, "run_id": "j05-run"}
    )["value"]
    foreign = _call(
        python,
        "runtime.status",
        {"store_path": str(store), "service_id": "foreign", "run_id": "j05-run"},
        expect_ok=False,
    )

    assert recovered["attempts"][0]["state"] == "RUNNING"
    assert finished["project_jobs"][0]["state"] == "FINISHED"
    assert finished["acceptance_decisions"] == []
    assert accepted["project_jobs"][0]["state"] == "ACCEPTED"
    assert accepted["run"]["state"] == "COMPLETED"
    assert accepted["workstream"]["state"] == "COMPLETE"
    assert accepted["automated_codex_execution"] is False
    assert accepted["provider_dispatch"] is False
    generations = [
        event["payload"]["generation"]
        for event in accepted["audit"]
        if event["event_type"] == "COORDINATOR_ACQUIRED"
    ]
    assert generations == sorted(set(generations))
    assert len(generations) >= 6
    assert foreign["error"]["details"]["type"] == "CoordinatorFencedError"
    return {
        "status": "PASS",
        "frontend_processes": 6,
        "coordinator_generations": generations,
        "final_run_state": accepted["run"]["state"],
        "final_job_state": accepted["project_jobs"][0]["state"],
        "foreign_coordinator_fenced": True,
        "audit_events": len(accepted["audit"]),
    }


def _j18(python: Path, root: Path) -> dict[str, Any]:
    store = root / "j18" / "runstore.sqlite3"
    service_id = "managed-j18"
    _bootstrap(python, store, service_id, prefix="j18", project_id="project-j18")
    common = {"store_path": str(store), "service_id": service_id}
    _call(
        python,
        "runtime.attempt.unknown",
        {**common, "attempt_id": "j18-attempt"},
    )
    blind_retry = _call(
        python,
        "runtime.attempt.retry",
        {
            **common,
            "previous_attempt_id": "j18-attempt",
            "new_attempt_id": "j18-attempt-2",
        },
        expect_ok=False,
    )
    unknown = _call(
        python, "runtime.status", {**common, "run_id": "j18-run"}
    )["value"]
    _call(
        python,
        "runtime.attempt.reconcile",
        {
            **common,
            "attempt_id": "j18-attempt",
            "outcome": "RECOVERED_FINISHED",
            "recovered_claim": "external result recovered",
        },
    )
    recovered = _call(
        python, "runtime.status", {**common, "run_id": "j18-run"}
    )["value"]
    assert unknown["attempts"][0]["state"] == "UNKNOWN"
    assert unknown["run"]["state"] == "WAITING_RECONCILIATION"
    assert blind_retry["error"]["details"]["type"] == "RuntimeTransitionError"
    assert recovered["attempts"][0]["state"] == "FINISHED"
    assert recovered["project_jobs"][0]["state"] == "FINISHED"
    assert recovered["acceptance_decisions"] == []
    assert recovered["automated_codex_execution"] is False
    return {
        "status": "PASS",
        "blind_retry_rejected": True,
        "unknown_run_state": unknown["run"]["state"],
        "recovered_attempt_state": recovered["attempts"][0]["state"],
        "accepted_after_recovery": False,
        "audit_events": len(recovered["audit"]),
    }


def _j15(python: Path, root: Path) -> dict[str, Any]:
    journey_root = root / "j15"
    project_root = journey_root / "project"
    catalog = journey_root / "catalog.sqlite3"
    store = journey_root / "runstore.sqlite3"
    service_id = "managed-j15"
    _call(
        python,
        "project.create",
        {
            "project_root": str(project_root),
            "catalog_path": str(catalog),
            "name": "J15",
            "project_id": "project-j15",
        },
    )
    _bootstrap(python, store, service_id, prefix="j15-a", project_id="project-j15")
    _bootstrap(python, store, service_id, prefix="j15-b", project_id="project-j15")
    common = {
        "store_path": str(store),
        "service_id": service_id,
        "workspace_root": str(journey_root / "workspaces"),
    }
    for suffix in ("a", "b"):
        _call(
            python,
            "runtime.workspace.create",
            {
                **common,
                "workspace_id": f"j15-{suffix}-workspace",
                "attempt_id": f"j15-{suffix}-attempt",
                "project_root": str(project_root),
                "baseline_revision": 1,
            },
        )
    model_path = project_root / ".artifex" / "project-model.json"
    baseline = json.loads(model_path.read_text(encoding="utf-8"))
    model_a = json.loads(json.dumps(baseline))
    model_b = json.loads(json.dumps(baseline))
    model_a["project"]["description"] = "workspace A accepted"
    model_b["project"]["description"] = "workspace B stale"

    def finish_accept(suffix: str) -> None:
        _call(
            python,
            "runtime.attempt.finish",
            {
                **common,
                "attempt_id": f"j15-{suffix}-attempt",
                "result_claim": f"workspace {suffix} validation passed",
            },
        )
        _call(
            python,
            "runtime.accept",
            {
                **common,
                "project_job_id": f"j15-{suffix}-job",
                "evidence_valid": True,
                "reason": f"workspace {suffix} evidence valid",
            },
        )

    finish_accept("a")
    promoted_a = _call(
        python,
        "runtime.workspace.promote",
        {
            **common,
            "workspace_id": "j15-a-workspace",
            "project_job_id": "j15-a-job",
            "model": model_a,
        },
    )
    finish_accept("b")
    conflict_b = _call(
        python,
        "runtime.workspace.promote",
        {
            **common,
            "workspace_id": "j15-b-workspace",
            "project_job_id": "j15-b-job",
            "model": model_b,
        },
        expect_ok=False,
    )
    status_b = _call(
        python, "runtime.status", {**common, "run_id": "j15-b-run"}
    )["value"]
    current = json.loads(model_path.read_text(encoding="utf-8"))
    assert promoted_a["value"]["semantic_revision"] == 2
    assert conflict_b["error"]["details"]["type"] == "PromotionConflictError"
    assert status_b["workspaces"][0]["state"] == "PROMOTION_CONFLICT"
    assert status_b["project_jobs"][0]["state"] == "PROMOTION_CONFLICT"
    assert current["project"]["description"] == "workspace A accepted"
    return {
        "status": "PASS",
        "workspace_a_revision": 2,
        "workspace_b_state": status_b["workspaces"][0]["state"],
        "project_description": current["project"]["description"],
        "silent_overwrite": False,
    }


def qualify(python: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="artifex-m2-black-box-") as directory:
        root = Path(directory)
        return {
            "schema_version": "1.0",
            "status": "PASS",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS",
            "provider_dispatch": False,
            "automated_codex_execution": False,
            "journeys": {
                "J05": _j05(python, root),
                "J15": _j15(python, root),
                "J18": _j18(python, root),
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.python.resolve())
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()

