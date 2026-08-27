"""Qualify M4 journeys through an installed wheel and public CLI processes."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from copy import deepcopy
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
            "-I",
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
        errors="replace",
        check=False,
        timeout=120,
    )
    if not completed.stdout.strip():
        raise AssertionError(
            f"{operation} returned no JSON: exit={completed.returncode} "
            f"stderr={completed.stderr[:500]}"
        )
    result = json.loads(completed.stdout)
    if bool(result["ok"]) is not expect_ok:
        raise AssertionError(f"{operation} expected ok={expect_ok}: {result}")
    if expect_ok != (completed.returncode == 0):
        raise AssertionError(f"{operation} process exit disagrees with semantic result")
    return result


def _principal(actor_id: str, actor_type: str, *permissions: str) -> dict[str, Any]:
    return {
        "actor_id": actor_id,
        "actor_type": actor_type,
        "authenticated": True,
        "authentication_method": "m4-black-box",
        "direct_permissions": list(permissions),
    }


def _envelope(
    project_id: str,
    workstream_id: str,
    envelope_id: str,
    *,
    approved: bool = True,
) -> dict[str, Any]:
    return {
        "envelope_id": envelope_id,
        "version": 1,
        "project_id": project_id,
        "objective": "Execute one approved bounded M4 workstream",
        "baseline_revision": 1,
        "actor_id": "m4-user",
        "allowed_paths": ["."],
        "allowed_capabilities": ["manual:execution"],
        "required_gates": ["validation", "acceptance-authority"],
        "max_attempts": 2,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "approved": approved,
        "supervision_level": "L2",
        "materiality": "TACTICAL",
        "allowed_workstreams": [workstream_id],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": [],
        "tool_permissions": ["manual.integration"],
        "data_classification": "INTERNAL",
        "resource_budget": {"attempts": 2, "wall_seconds": 3600},
        "deadline_at": 4102444800,
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME", "MATERIAL_DECISION"],
    }


def _create_project(python: Path, root: Path, suffix: str) -> dict[str, Path]:
    project = root / suffix / "project"
    catalog = root / suffix / "catalog.sqlite3"
    store = root / suffix / "runstore.sqlite3"
    _call(
        python,
        "project.create",
        {
            "project_root": str(project),
            "catalog_path": str(catalog),
            "project_id": f"project-{suffix}",
            "name": f"M4 {suffix}",
            "description": "I have an idea to build a governed collaborative system.",
        },
    )
    return {"project": project, "catalog": catalog, "store": store}


def _bootstrap(
    python: Path,
    store: Path,
    project_id: str,
    suffix: str,
) -> None:
    _call(
        python,
        "runtime.bootstrap",
        {
            "store_path": str(store),
            "service_id": "m4-public-runtime",
            "envelope": _envelope(
                project_id, f"workstream-{suffix}", f"envelope-{suffix}"
            ),
            "workstream_id": f"workstream-{suffix}",
            "run_id": f"run-{suffix}",
            "project_job_id": f"job-{suffix}",
            "attempt_id": f"attempt-{suffix}",
            "purpose": f"M4 {suffix}",
        },
    )


def _j04(python: Path, root: Path) -> dict[str, Any]:
    paths = _create_project(python, root, "j04")
    project = paths["project"]
    common = {
        "store_path": str(paths["store"]),
        "service_id": "m4-j04",
        "project_root": str(project),
    }
    permissions = ("interaction:connect", "interaction:write")
    actor_a = _principal("client-a", "INTERACTION_CLIENT", *permissions)
    actor_b = _principal("client-b", "INTERACTION_CLIENT", *permissions)
    opened_a = _call(python, "interaction.open", {**common, "actor": actor_a})["value"]
    opened_b = _call(python, "interaction.open", {**common, "actor": actor_b})["value"]
    session_a = opened_a["session"]["session_id"]
    session_b = opened_b["session"]["session_id"]
    model_path = project / ".artifex" / "project-model.json"
    baseline = json.loads(model_path.read_text(encoding="utf-8"))
    model_a = deepcopy(baseline)
    model_a["project"]["description"] = "session A accepted"
    _call(
        python,
        "interaction.semantic.submit",
        {
            **common,
            "catalog_path": str(paths["catalog"]),
            "name": "M4 j04",
            "session_id": session_a,
            "actor": actor_a,
            "expected_revision": 1,
            "model": model_a,
            "accept": True,
        },
    )
    model_b = deepcopy(baseline)
    model_b["project"]["description"] = "session B stale"
    conflict = _call(
        python,
        "interaction.semantic.submit",
        {
            **common,
            "catalog_path": str(paths["catalog"]),
            "name": "M4 j04",
            "session_id": session_b,
            "actor": actor_b,
            "expected_revision": 1,
            "model": model_b,
            "accept": True,
        },
        expect_ok=False,
    )
    _call(
        python,
        "interaction.disconnect",
        {**common, "session_id": session_b, "actor": actor_b},
    )
    _call(
        python,
        "interaction.reconnect",
        {
            **common,
            "session_id": session_b,
            "reconnect_token": opened_b["reconnect_token"],
            "actor": actor_b,
        },
    )
    current = json.loads(model_path.read_text(encoding="utf-8"))
    assert current["project"]["description"] == "session A accepted"
    return {
        "status": "PASS",
        "revision_conflict": conflict["error"]["details"]["type"],
        "silent_overwrite": False,
        "reconnect": True,
    }


def _j06(python: Path, root: Path) -> dict[str, Any]:
    store = root / "j06" / "runstore.sqlite3"
    for suffix in ("a", "b"):
        _bootstrap(python, store, "project-j06", suffix)
    service = _principal("m4-service", "ARTIFEX_SERVICE", "*")
    user = _principal("m4-user", "USER", "governance:resolve-decision")
    common = {"store_path": str(store), "service_id": "m4-public-runtime"}
    request = _call(
        python,
        "governance.decision.request",
        {
            **common,
            "project_id": "project-j06",
            "run_id": "run-a",
            "question": "May branch A change the strategic architecture?",
            "affected_workstreams": ["workstream-a"],
            "actor": service,
        },
    )["value"]["decision_request"]
    status_a = _call(python, "runtime.status", {**common, "run_id": "run-a"})["value"]
    status_b = _call(python, "runtime.status", {**common, "run_id": "run-b"})["value"]
    assert status_a["workstream"]["state"] == "BLOCKED"
    assert status_b["workstream"]["state"] == "ACTIVE"
    _call(
        python,
        "runtime.attempt.finish",
        {**common, "attempt_id": "attempt-b", "result_claim": "B progressed"},
    )
    _call(
        python,
        "governance.decision.resolve",
        {
            **common,
            "decision_request_id": request["decision_request_id"],
            "outcome": "APPROVE",
            "resolution": "User approved bounded branch A",
            "actor": user,
        },
    )
    resumed = _call(python, "runtime.status", {**common, "run_id": "run-a"})["value"]
    assert resumed["workstream"]["state"] == "ACTIVE"
    return {
        "status": "PASS",
        "affected_branch_blocked": True,
        "unrelated_branch_progressed": True,
        "user_resolution_resumed_branch": True,
    }


def _j07(python: Path, root: Path) -> dict[str, Any]:
    store = root / "j07" / "runstore.sqlite3"
    _bootstrap(python, store, "project-j07", "active")
    actor = _principal("m4-service", "ARTIFEX_SERVICE", "*")
    common = {"store_path": str(store), "service_id": "m4-public-runtime"}
    for state in ("DRAINING", "PAUSED"):
        _call(
            python,
            "control.set",
            {
                **common,
                "scope": "PLATFORM",
                "scope_id": "global",
                "state": state,
                "reason": f"exercise {state}",
                "actor": actor,
            },
        )
    blocked = _call(
        python,
        "runtime.bootstrap",
        {
            **common,
            "envelope": _envelope(
                "project-j07", "workstream-paused", "envelope-paused"
            ),
            "workstream_id": "workstream-paused",
            "run_id": "run-paused",
            "project_job_id": "job-paused",
            "attempt_id": "attempt-paused",
            "purpose": "must not dispatch during pause",
        },
        expect_ok=False,
    )
    _call(
        python,
        "control.set",
        {
            **common,
            "scope": "PLATFORM",
            "scope_id": "global",
            "state": "EMERGENCY_STOP",
            "reason": "unconfirmed provider termination",
            "actor": actor,
            "attempts": [
                {"attempt_id": "attempt-active", "termination_confirmed": False}
            ],
        },
    )
    status = _call(python, "runtime.status", {**common, "run_id": "run-active"})["value"]
    assert status["attempts"][0]["state"] == "NEEDS_RECONCILIATION"
    return {
        "status": "PASS",
        "new_dispatch_blocked": blocked["error"]["details"]["type"],
        "false_stop_claim": False,
        "uncertain_state": "NEEDS_RECONCILIATION",
    }


def _j19(python: Path, root: Path) -> dict[str, Any]:
    paths = _create_project(python, root, "j19")
    common = {
        "store_path": str(paths["store"]),
        "service_id": "m4-j19",
        "project_root": str(paths["project"]),
    }
    client = _principal(
        "m4-collaboration-client",
        "INTERACTION_CLIENT",
        "interaction:connect",
        "interaction:write",
        "envelope:propose",
    )
    opened = _call(python, "interaction.open", {**common, "actor": client})["value"]
    session_id = opened["session"]["session_id"]
    revision = 1
    stages = (
        "EXPLORATION",
        "RESEARCH",
        "DEFINITION",
        "ARCHITECTURE",
        "REQUIREMENTS_ADRS",
        "PLAN",
    )
    for stage in stages:
        advanced = _call(
            python,
            "interaction.lifecycle.advance",
            {
                **common,
                "catalog_path": str(paths["catalog"]),
                "name": "M4 j19",
                "session_id": session_id,
                "actor": client,
                "expected_revision": revision,
                "stage": stage,
                "summary": f"Accepted collaborative {stage.lower()} outcome",
                "evidence_refs": ["research://j19"] if stage == "RESEARCH" else [],
            },
        )["value"]
        revision = int(advanced["semantic_revision"])
    workstream = "workstream-approved-plan"
    envelope = _envelope(
        "project-j19", workstream, "envelope-approved-plan", approved=False
    )
    _call(
        python,
        "governance.envelope.propose",
        {**common, "actor": client, "envelope": envelope},
    )
    for stage in ("ENVELOPE_PROPOSED",):
        advanced = _call(
            python,
            "interaction.lifecycle.advance",
            {
                **common,
                "catalog_path": str(paths["catalog"]),
                "name": "M4 j19",
                "session_id": session_id,
                "actor": client,
                "expected_revision": revision,
                "stage": stage,
                "summary": "Proposed a full bounded Envelope",
            },
        )["value"]
        revision = int(advanced["semantic_revision"])
    user = _principal("m4-user", "USER", "envelope:approve", "run:authorize")
    _call(
        python,
        "governance.envelope.approve",
        {
            **common,
            "envelope_id": envelope["envelope_id"],
            "version": 1,
            "actor": user,
        },
    )
    approved_plan = _call(
        python,
        "interaction.lifecycle.advance",
        {
            **common,
            "catalog_path": str(paths["catalog"]),
            "name": "M4 j19",
            "session_id": session_id,
            "actor": client,
            "expected_revision": revision,
            "stage": "APPROVED_PLAN",
            "summary": "User approved Plan and Envelope",
            "decision_refs": ["envelope://envelope-approved-plan/1"],
        },
    )["value"]
    authorized = _call(
        python,
        "runtime.run.authorize",
        {
            **common,
            "envelope_id": envelope["envelope_id"],
            "envelope_version": 1,
            "workstream_id": workstream,
            "run_id": "run-approved-plan",
            "project_job_id": "job-approved-plan",
            "attempt_id": "attempt-approved-plan",
            "purpose": "Execute approved plan",
            "actor": user,
        },
    )["value"]
    assert approved_plan["project_dashboard"]["lifecycle_stage"] == "APPROVED_PLAN"
    assert authorized["attempts"][0]["state"] == "PENDING"
    return {
        "status": "PASS",
        "manual_specialist_session_shuttle": False,
        "semantic_revision": approved_plan["semantic_revision"],
        "lifecycle_stage": "APPROVED_PLAN",
        "run_authorized": True,
        "provider_dispatch": False,
    }


def qualify(python: Path) -> dict[str, Any]:
    if not python.resolve().is_file():
        raise FileNotFoundError(f"installed Python does not exist: {python}")
    with tempfile.TemporaryDirectory(prefix="artifex-m4-public-") as directory:
        root = Path(directory)
        return {
            "schema_version": "1.0",
            "status": "PASS",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS",
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "journeys": {
                "J04": _j04(python, root),
                "J06": _j06(python, root),
                "J07": _j07(python, root),
                "J19": _j19(python, root),
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.python)
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


if __name__ == "__main__":
    main()
