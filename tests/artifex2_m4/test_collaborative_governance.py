from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.project import ProjectAuthority
from artifex.runtime import (
    ActorPrincipal,
    ActorType,
    ControlScope,
    DecisionOutcome,
    ExecutionEnvelope,
    ManagedRuntimeService,
    Materiality,
    OperationalControlState,
    ReconciliationOutcome,
    RuntimeAuthorizationError,
    SupervisionLevel,
)


def _principal(
    actor_id: str,
    actor_type: ActorType,
    *permissions: str,
) -> ActorPrincipal:
    return ActorPrincipal(
        actor_id,
        actor_type,
        True,
        "test-identity",
        direct_permissions=tuple(permissions),
    )


def _actor_value(
    actor_id: str,
    actor_type: ActorType,
    *permissions: str,
) -> dict[str, object]:
    return {
        "actor_id": actor_id,
        "actor_type": actor_type.value,
        "authenticated": True,
        "authentication_method": "test-identity",
        "direct_permissions": list(permissions),
    }


def _call(
    operation: str,
    arguments: dict[str, object],
    *,
    project_root: Path | None = None,
) -> dict[str, object]:
    result = Application().dispatch(
        OperationRequest(
            operation,
            arguments,
            OperationContext(
                project_root=str(project_root) if project_root is not None else None,
                actor="test-transport",
            ),
        )
    )
    assert result.ok, result.to_dict()
    return dict(result.value)


def _create_project(tmp_path: Path, name: str = "M4 Project") -> tuple[Path, Path, Path]:
    project_root = tmp_path / "project"
    catalog = tmp_path / "catalog.sqlite3"
    store = tmp_path / "runstore.sqlite3"
    _call(
        "project.create",
        {
            "name": name,
            "project_id": "project-m4",
            "description": "I have an idea to build a conflict-safe system.",
            "catalog_path": str(catalog),
        },
        project_root=project_root,
    )
    return project_root, catalog, store


def _envelope(
    project_id: str,
    workstream_id: str,
    envelope_id: str,
    *,
    approved: bool = True,
) -> ExecutionEnvelope:
    return ExecutionEnvelope(
        envelope_id=envelope_id,
        version=1,
        project_id=project_id,
        objective="Execute an approved bounded M4 workstream",
        baseline_revision=1,
        actor_id="user-owner",
        allowed_paths=(".",),
        allowed_capabilities=("manual:execution",),
        required_gates=("validation", "acceptance-authority"),
        max_attempts=2,
        recovery_policy="RECONCILE_BEFORE_RETRY",
        approved=approved,
        supervision_level=SupervisionLevel.L2,
        materiality=Materiality.TACTICAL,
        allowed_workstreams=(workstream_id,),
        filesystem_permissions=("READ", "WRITE"),
        network_permissions=(),
        tool_permissions=("manual.integration",),
        data_classification="INTERNAL",
        resource_budget=(("attempts", 2), ("wall_seconds", 3600)),
        deadline_at=4_102_444_800,
        stop_conditions=("MAX_ATTEMPTS", "UNKNOWN_OUTCOME", "MATERIAL_DECISION"),
    )


def _bootstrap(
    service: ManagedRuntimeService,
    project_id: str,
    suffix: str,
    actor: ActorPrincipal,
) -> tuple[str, str, str, str]:
    workstream_id = f"workstream-{suffix}"
    run_id = f"run-{suffix}"
    job_id = f"job-{suffix}"
    attempt_id = f"attempt-{suffix}"
    service.bootstrap_run(
        _envelope(project_id, workstream_id, f"envelope-{suffix}"),
        workstream_id=workstream_id,
        run_id=run_id,
        project_job_id=job_id,
        attempt_id=attempt_id,
        purpose=f"M4 {suffix}",
        actor_id=actor,
        approval_actor=actor,
    )
    return workstream_id, run_id, job_id, attempt_id


def test_j04_two_sessions_detect_stale_semantic_revision_without_overwrite(
    tmp_path: Path,
) -> None:
    project_root, catalog, store = _create_project(tmp_path)
    session_permissions = ("interaction:connect", "interaction:read", "interaction:write")
    actor_a = _actor_value("client-a", ActorType.INTERACTION_CLIENT, *session_permissions)
    actor_b = _actor_value("client-b", ActorType.INTERACTION_CLIENT, *session_permissions)
    common = {"store_path": str(store), "project_root": str(project_root)}
    opened_a = _call("interaction.open", {**common, "actor": actor_a})
    opened_b = _call("interaction.open", {**common, "actor": actor_b})
    session_a = str(opened_a["session"]["session_id"])  # type: ignore[index]
    session_b = str(opened_b["session"]["session_id"])  # type: ignore[index]

    original = ProjectAuthority(project_root).current().model.to_dict()
    model_a = deepcopy(original)
    model_a["project"]["description"] = "Accepted contribution from session A"
    accepted = _call(
        "interaction.semantic.submit",
        {
            **common,
            "catalog_path": str(catalog),
            "name": "M4 Project",
            "session_id": session_a,
            "actor": actor_a,
            "expected_revision": 1,
            "model": model_a,
            "accept": True,
        },
    )
    assert accepted["semantic_revision"] == 2

    model_b = deepcopy(original)
    model_b["project"]["description"] = "Stale contribution from session B"
    conflict = Application().dispatch(
        OperationRequest(
            "interaction.semantic.submit",
            {
                **common,
                "catalog_path": str(catalog),
                "name": "M4 Project",
                "session_id": session_b,
                "actor": actor_b,
                "expected_revision": 1,
                "model": model_b,
                "accept": True,
            },
        )
    )
    assert conflict.ok is False
    assert conflict.error is not None
    assert "semantic revision conflict" in conflict.error.message
    current = ProjectAuthority(project_root).current()
    assert current.number == 2
    assert current.model.project.description == "Accepted contribution from session A"
    sessions = _call(
        "interaction.list",
        {"store_path": str(store), "project_id": "project-m4", "actor": actor_a},
    )["sessions"]
    assert {item["last_seen_revision"] for item in sessions} == {1, 2}  # type: ignore[union-attr]
    disconnected = _call(
        "interaction.disconnect",
        {**common, "session_id": session_b, "actor": actor_b},
    )
    assert disconnected["session"]["state"] == "DISCONNECTED"  # type: ignore[index]
    invalid = Application().dispatch(
        OperationRequest(
            "interaction.reconnect",
            {
                **common,
                "session_id": session_b,
                "reconnect_token": "not-the-issued-token",
                "actor": actor_b,
            },
        )
    )
    assert invalid.ok is False
    reconnected = _call(
        "interaction.reconnect",
        {
            **common,
            "session_id": session_b,
            "reconnect_token": opened_b["reconnect_token"],
            "actor": actor_b,
        },
    )
    assert reconnected["session"]["state"] == "ACTIVE"  # type: ignore[index]


def test_j19_public_lifecycle_persists_approved_plan_then_authorizes_run(
    tmp_path: Path,
) -> None:
    project_root, catalog, store = _create_project(tmp_path, "Lifecycle Project")
    interaction_actor = _actor_value(
        "collaboration-client",
        ActorType.INTERACTION_CLIENT,
        "interaction:connect",
        "interaction:write",
        "envelope:propose",
    )
    common = {"store_path": str(store), "project_root": str(project_root)}
    opened = _call("interaction.open", {**common, "actor": interaction_actor})
    session_id = str(opened["session"]["session_id"])  # type: ignore[index]
    revision = 1
    for stage, summary, evidence in (
        ("EXPLORATION", "Explored users, constraints, and alternatives", ()),
        ("RESEARCH", "Delegated research and retained sourced evidence", ("research://r1",)),
        ("DEFINITION", "Defined objectives, scope, and success criteria", ()),
        ("ARCHITECTURE", "Selected bounded standalone architecture", ()),
        ("REQUIREMENTS_ADRS", "Recorded requirements and material ADRs", ()),
        ("PLAN", "Created dependency-aware implementation plan", ()),
    ):
        value = _call(
            "interaction.lifecycle.advance",
            {
                **common,
                "catalog_path": str(catalog),
                "name": "Lifecycle Project",
                "session_id": session_id,
                "actor": interaction_actor,
                "expected_revision": revision,
                "stage": stage,
                "summary": summary,
                "evidence_refs": list(evidence),
            },
        )
        revision = int(value["semantic_revision"])

    workstream_id = "workstream-approved-plan"
    envelope = _envelope("project-m4", workstream_id, "envelope-approved-plan", approved=False)
    proposed = _call(
        "governance.envelope.propose",
        {**common, "actor": interaction_actor, "envelope": envelope.to_dict()},
    )
    assert proposed["envelope_proposal"]["approved"] is False  # type: ignore[index]
    value = _call(
        "interaction.lifecycle.advance",
        {
            **common,
            "catalog_path": str(catalog),
            "name": "Lifecycle Project",
            "session_id": session_id,
            "actor": interaction_actor,
            "expected_revision": revision,
            "stage": "ENVELOPE_PROPOSED",
            "summary": "Proposed a full bounded Execution Envelope",
        },
    )
    revision = int(value["semantic_revision"])

    user_actor = _actor_value(
        "user-owner",
        ActorType.USER,
        "envelope:approve",
        "run:authorize",
        "control:operate",
    )
    approved = _call(
        "governance.envelope.approve",
        {
            "store_path": str(store),
            "envelope_id": envelope.envelope_id,
            "version": 1,
            "actor": user_actor,
        },
    )
    assert approved["envelope"]["approved"] is True  # type: ignore[index]
    value = _call(
        "interaction.lifecycle.advance",
        {
            **common,
            "catalog_path": str(catalog),
            "name": "Lifecycle Project",
            "session_id": session_id,
            "actor": interaction_actor,
            "expected_revision": revision,
            "stage": "APPROVED_PLAN",
            "summary": "User approved the plan and Envelope",
            "decision_refs": [f"envelope://{envelope.envelope_id}/1"],
        },
    )
    assert value["project_dashboard"]["lifecycle_stage"] == "APPROVED_PLAN"  # type: ignore[index]
    forbidden = Application().dispatch(
        OperationRequest(
            "runtime.run.authorize",
            {
                "store_path": str(store),
                "envelope_id": envelope.envelope_id,
                "envelope_version": 1,
                "workstream_id": workstream_id,
                "run_id": "run-approved-plan",
                "project_job_id": "job-approved-plan",
                "attempt_id": "attempt-approved-plan",
                "purpose": "Provider must not authorize this Run",
                "actor": _actor_value(
                    "provider-forgery", ActorType.PROVIDER, "run:authorize"
                ),
            },
        )
    )
    assert forbidden.ok is False
    assert forbidden.error is not None
    assert "cannot authorize a Run" in forbidden.error.message
    authorized = _call(
        "runtime.run.authorize",
        {
            "store_path": str(store),
            "envelope_id": envelope.envelope_id,
            "envelope_version": 1,
            "workstream_id": workstream_id,
            "run_id": "run-approved-plan",
            "project_job_id": "job-approved-plan",
            "attempt_id": "attempt-approved-plan",
            "purpose": "Execute approved plan",
            "actor": user_actor,
        },
    )
    assert authorized["run_authorized"] is True
    assert authorized["attempts"][0]["state"] == "PENDING"  # type: ignore[index]
    assert ProjectAuthority(project_root).current().model.governance.stage.value == "APPROVED_PLAN"


def test_j06_material_decision_blocks_only_affected_branch_and_requires_user(
    tmp_path: Path,
) -> None:
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3", service_id="m4-j06")
    authority = _principal(
        "artifex-service",
        ActorType.ARTIFEX_SERVICE,
        "*",
    )
    workstream_a, _, job_a, attempt_a = _bootstrap(service, "project-m4", "a", authority)
    workstream_b, _, _, attempt_b = _bootstrap(service, "project-m4", "b", authority)

    request = service.decisions.create(
        project_id="project-m4",
        question="May branch A change the strategic architecture?",
        affected_workstreams=(workstream_a,),
        actor=authority,
        run_id="run-a",
    )
    assert service.store.get("workstreams", "workstream_id", workstream_a)["state"] == "BLOCKED"  # type: ignore[index]
    assert service.store.get("workstreams", "workstream_id", workstream_b)["state"] == "ACTIVE"  # type: ignore[index]
    service.finish(attempt_b, "Tactical branch B completed", actor_id=authority)
    service.finish(attempt_a, "Material branch result pending approval", actor_id=authority)
    with pytest.raises(RuntimeAuthorizationError, match="material DecisionRequest"):
        service.accept(
            job_a,
            evidence_valid=True,
            actor_id=authority,
            reason="must not accept before material approval",
        )

    non_user = _principal(
        "automated-governor",
        ActorType.ARTIFEX_SERVICE,
        "governance:resolve-decision",
    )
    with pytest.raises(RuntimeAuthorizationError, match="USER resolution"):
        service.decisions.resolve(
            str(request["decision_request_id"]),
            outcome=DecisionOutcome.APPROVE,
            resolution="automation may not decide",
            actor=non_user,
        )
    user = _principal(
        "user-owner", ActorType.USER, "governance:resolve-decision"
    )
    service.decisions.resolve(
        str(request["decision_request_id"]),
        outcome=DecisionOutcome.APPROVE,
        resolution="Approved the bounded architecture change",
        actor=user,
    )
    assert service.store.get("workstreams", "workstream_id", workstream_a)["state"] == "ACTIVE"  # type: ignore[index]
    decision = service.accept(
        job_a,
        evidence_valid=True,
        actor_id=authority,
        reason="independent evidence valid after user approval",
    )
    assert decision.outcome.value == "ACCEPT"


def test_j07_controls_block_new_dispatch_and_uncertain_stop_reconciles(
    tmp_path: Path,
) -> None:
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3", service_id="m4-j07")
    actor = _principal("artifex-service", ActorType.ARTIFEX_SERVICE, "*")
    _, _, _, attempt = _bootstrap(service, "project-m4", "active", actor)

    service.controls.set(
        scope=ControlScope.PLATFORM,
        scope_id="global",
        project_id=None,
        state=OperationalControlState.DRAINING,
        reason="drain for maintenance",
        actor=actor,
    )
    assert service.store.get("attempts", "attempt_id", attempt)["state"] == "RUNNING"  # type: ignore[index]
    with pytest.raises(RuntimeAuthorizationError, match="DRAINING"):
        _bootstrap(service, "project-m4", "blocked-by-drain", actor)
    blocked = service.store.get("attempts", "attempt_id", "attempt-blocked-by-drain")
    assert blocked is not None and blocked["state"] == "PENDING"

    service.controls.set(
        scope=ControlScope.PLATFORM,
        scope_id="global",
        project_id=None,
        state=OperationalControlState.PAUSED,
        reason="global safe pause",
        actor=actor,
    )
    effective, _ = service.controls.effective_for_attempt(attempt)
    assert effective is OperationalControlState.PAUSED
    service.controls.set(
        scope=ControlScope.PLATFORM,
        scope_id="global",
        project_id=None,
        state=OperationalControlState.EMERGENCY_STOP,
        reason="unconfirmed provider termination",
        actor=actor,
    )
    outcome = service.controls.emergency_attempt(
        attempt, termination_confirmed=False, actor=actor
    )
    assert outcome == {
        "attempt_id": attempt,
        "state": "NEEDS_RECONCILIATION",
        "termination_confirmed": False,
        "stop_claimed": False,
    }
    service.reconcile(
        attempt,
        ReconciliationOutcome.SAFE_TO_RETRY,
        actor_id=actor,
    )
    with pytest.raises(Exception, match="explicit reconciliation"):
        service.controls.set(
            scope=ControlScope.PLATFORM,
            scope_id="global",
            project_id=None,
            state=OperationalControlState.RUNNING,
            reason="unsafe clear",
            actor=actor,
        )
    cleared = service.controls.set(
        scope=ControlScope.PLATFORM,
        scope_id="global",
        project_id=None,
        state=OperationalControlState.RUNNING,
        reason="reconciliation completed",
        actor=actor,
        reconciled=True,
    )
    assert cleared["state"] == "RUNNING"
