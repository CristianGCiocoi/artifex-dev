from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from artifex.runtime.governance import (
    ControlScope,
    DecisionOutcome,
    InteractionSessionManager,
    MaterialDecisionManager,
    OperationalControlManager,
    OperationalControlState,
)
from artifex.runtime.models import (
    ActorPrincipal,
    ActorType,
    Materiality,
    RuntimeAuthorizationError,
    RuntimeTransitionError,
)


class FakeStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, Any]] = {
            ("workstreams", "workstream-1"): {
                "workstream_id": "workstream-1",
                "project_id": "project-1",
                "state": "ACTIVE",
            },
            ("runs", "run-1"): {
                "run_id": "run-1",
                "workstream_id": "workstream-1",
                "project_id": "project-1",
            },
            ("project_jobs", "job-1"): {
                "project_job_id": "job-1",
                "run_id": "run-1",
            },
            ("attempts", "attempt-1"): {
                "attempt_id": "attempt-1",
                "project_job_id": "job-1",
                "state": "RUNNING",
            },
        }
        self.decisions: dict[str, dict[str, Any]] = {}
        self.controls: dict[tuple[str, str], dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}

    def get(self, table: str, key: str, value: str) -> dict[str, Any] | None:
        del key
        return self.rows.get((table, value))

    def create_decision_request(
        self, value: dict[str, Any], token: object, **kwargs: object
    ) -> None:
        del token, kwargs
        self.decisions[str(value["decision_request_id"])] = value

    def decision_request(self, identifier: str) -> dict[str, Any] | None:
        return self.decisions.get(identifier)

    def resolve_decision_request(
        self,
        identifier: str,
        *,
        outcome: str,
        resolution: str,
        restore_workstreams: bool,
        **kwargs: object,
    ) -> None:
        del kwargs
        self.decisions[identifier].update(
            state="RESOLVED",
            outcome=outcome,
            resolution=resolution,
            restore_workstreams=restore_workstreams,
        )

    def operational_control(self, scope: str, identifier: str) -> dict[str, Any] | None:
        return self.controls.get((scope, identifier))

    def set_operational_control(self, **value: Any) -> None:
        value.pop("token")
        value.pop("now")
        value.pop("actor")
        self.controls[(str(value["scope_type"]), str(value["scope_id"]))] = value

    def interaction_session(self, identifier: str) -> dict[str, Any] | None:
        return self.sessions.get(identifier)

    def interaction_sessions(self, project_id: str) -> tuple[dict[str, Any], ...]:
        return tuple(
            value for value in self.sessions.values() if value["project_id"] == project_id
        )

    def update_interaction_session(
        self,
        identifier: str,
        *,
        expected_state: str,
        state: str,
        last_seen_revision: int,
        **kwargs: object,
    ) -> None:
        del kwargs
        current = self.sessions[identifier]
        if current["state"] != expected_state:
            raise RuntimeTransitionError("stale session transition")
        current.update(state=state, last_seen_revision=last_seen_revision)


class FakeCoordinator(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__(token=object())
        self.actions: list[tuple[str, str]] = []

    def cancel_attempt(self, attempt_id: str, *, actor_id: ActorPrincipal) -> None:
        self.actions.append(("cancel", attempt_id))

    def mark_unknown(self, attempt_id: str, *, actor_id: ActorPrincipal) -> None:
        self.actions.append(("unknown", attempt_id))

    def begin_reconciliation(self, attempt_id: str, *, actor_id: ActorPrincipal) -> None:
        self.actions.append(("reconcile", attempt_id))


def _actor(actor_type: ActorType = ActorType.USER) -> ActorPrincipal:
    return ActorPrincipal("operator", actor_type, True, "test", direct_permissions=("*",))


def _session_row() -> dict[str, Any]:
    return {
        "session_id": "session-1",
        "project_id": "project-1",
        "actor_id": "client-1",
        "actor_type": "INTERACTION_CLIENT",
        "delegated_actions": ["interaction:connect", "interaction:write"],
        "opened_revision": 1,
        "last_seen_revision": 1,
        "state": "ACTIVE",
        "workstream_id": None,
        "run_id": None,
        "delegation_id": None,
        "reconnect_token_hash": "invalid-until-replaced",
    }


@pytest.mark.unit
def test_interaction_sessions_require_identity_and_explicit_reconnect() -> None:
    from artifex.runtime.governance import _token_hash

    store = FakeStore()
    store.sessions["session-1"] = _session_row()
    manager = InteractionSessionManager(store, FakeCoordinator(), clock=lambda: 10)  # type: ignore[arg-type]
    actor = ActorPrincipal(
        "client-1",
        ActorType.INTERACTION_CLIENT,
        True,
        "test",
        direct_permissions=("interaction:connect", "interaction:write"),
    )
    with pytest.raises(KeyError, match="unknown"):
        manager.require("missing")
    session = manager.require("session-1")
    assert session.to_dict()["actor_type"] == "INTERACTION_CLIENT"
    assert manager.list("project-1") == (session,)
    with pytest.raises(RuntimeAuthorizationError, match="actor does not match"):
        manager.require_active("session-1", replace(actor, actor_id="other"))

    assert manager.record_revision("session-1", 2, actor=actor).last_seen_revision == 2
    disconnected = manager.disconnect("session-1", actor=actor)
    assert disconnected.state.value == "DISCONNECTED"
    with pytest.raises(RuntimeTransitionError, match="not ACTIVE"):
        manager.require_active("session-1", actor)
    with pytest.raises(RuntimeAuthorizationError, match="actor does not match"):
        manager.reconnect("session-1", "token", actor=replace(actor, actor_id="other"))
    with pytest.raises(RuntimeAuthorizationError, match="invalid reconnect"):
        manager.reconnect("session-1", "wrong", actor=actor)
    store.sessions["session-1"]["reconnect_token_hash"] = _token_hash("correct")
    assert manager.reconnect("session-1", "correct", actor=actor).state.value == "ACTIVE"
    with pytest.raises(RuntimeTransitionError, match="only a DISCONNECTED"):
        manager.reconnect("session-1", "correct", actor=actor)
    with pytest.raises(RuntimeAuthorizationError, match="actor does not match"):
        manager.close("session-1", actor=replace(actor, actor_id="other"))
    closed = manager.close("session-1", actor=actor)
    assert manager.close("session-1", actor=actor) == closed


@pytest.mark.unit
def test_material_decisions_validate_scope_materiality_and_resolution() -> None:
    store = FakeStore()
    manager = MaterialDecisionManager(store, FakeCoordinator(), clock=lambda: 10)  # type: ignore[arg-type]
    actor = _actor()
    base = {
        "project_id": "project-1",
        "question": "Which durable option is accepted?",
        "affected_workstreams": ("workstream-1",),
        "actor": actor,
        "run_id": "run-1",
        "decision_request_id": "decision-1",
    }
    with pytest.raises(ValueError, match="reserved"):
        manager.create(**base, materiality=Materiality.TACTICAL)
    with pytest.raises(ValueError, match="question"):
        manager.create(**{**base, "question": ""})
    with pytest.raises(ValueError, match="unique"):
        manager.create(**{**base, "affected_workstreams": ("workstream-1",) * 2})
    with pytest.raises(ValueError, match="Run is outside"):
        manager.create(**{**base, "run_id": "missing"})
    with pytest.raises(ValueError, match="Workstream is outside"):
        manager.create(**{**base, "affected_workstreams": ("missing",)})
    store.rows[("workstreams", "workstream-1")]["state"] = "COMPLETE"
    with pytest.raises(RuntimeTransitionError, match="cannot block"):
        manager.create(**base)
    store.rows[("workstreams", "workstream-1")]["state"] = "ACTIVE"
    created = manager.create(**base)
    assert created["state"] == "OPEN"

    with pytest.raises(KeyError, match="unknown"):
        manager.resolve("missing", outcome=DecisionOutcome.APPROVE, resolution="yes", actor=actor)
    with pytest.raises(RuntimeAuthorizationError, match="USER"):
        manager.resolve(
            "decision-1",
            outcome=DecisionOutcome.APPROVE,
            resolution="yes",
            actor=_actor(ActorType.ARTIFEX_SERVICE),
        )
    with pytest.raises(ValueError, match="resolution"):
        manager.resolve(
            "decision-1", outcome=DecisionOutcome.APPROVE, resolution="", actor=actor
        )
    resolved = manager.resolve(
        "decision-1", outcome=DecisionOutcome.APPROVE, resolution="accepted", actor=actor
    )
    assert resolved["restore_workstreams"] is True
    with pytest.raises(KeyError, match="unknown ProjectJob"):
        manager.assert_project_job_unblocked("missing")
    manager.assert_project_job_unblocked("job-1")
    store.rows[("workstreams", "workstream-1")]["state"] = "BLOCKED"
    with pytest.raises(RuntimeAuthorizationError, match="blocked"):
        manager.assert_project_job_unblocked("job-1")


@pytest.mark.unit
def test_operational_controls_fail_closed_across_every_scope() -> None:
    store = FakeStore()
    coordinator = FakeCoordinator()
    manager = OperationalControlManager(store, coordinator, clock=lambda: 10)  # type: ignore[arg-type]
    actor = _actor()
    with pytest.raises(ValueError, match="identity"):
        manager.set(
            scope=ControlScope.PLATFORM,
            scope_id="",
            project_id=None,
            state=OperationalControlState.PAUSED,
            reason="pause",
            actor=actor,
        )
    with pytest.raises(RuntimeAuthorizationError, match="USER or"):
        manager.set(
            scope=ControlScope.PLATFORM,
            scope_id="global",
            project_id=None,
            state=OperationalControlState.PAUSED,
            reason="pause",
            actor=_actor(ActorType.AGENT),
        )
    invalid_scopes = (
        (ControlScope.PLATFORM, "not-global", None),
        (ControlScope.PROVIDER, "codex", "project-1"),
        (ControlScope.PROJECT, "other", "project-1"),
        (ControlScope.WORKSTREAM, "missing", "project-1"),
        (ControlScope.RUN, "missing", "project-1"),
        (ControlScope.PROJECT_JOB, "missing", "project-1"),
    )
    for scope, scope_id, project_id in invalid_scopes:
        with pytest.raises(ValueError):
            manager.set(
                scope=scope,
                scope_id=scope_id,
                project_id=project_id,
                state=OperationalControlState.PAUSED,
                reason="bounded pause",
                actor=actor,
            )

    control = manager.set(
        scope=ControlScope.PROJECT,
        scope_id="project-1",
        project_id="project-1",
        state=OperationalControlState.EMERGENCY_STOP,
        reason="incident",
        actor=actor,
    )
    assert control["generation"] == 1
    with pytest.raises(RuntimeTransitionError, match="reconciliation"):
        manager.set(
            scope=ControlScope.PROJECT,
            scope_id="project-1",
            project_id="project-1",
            state=OperationalControlState.RUNNING,
            reason="resume",
            actor=actor,
        )
    resumed = manager.set(
        scope=ControlScope.PROJECT,
        scope_id="project-1",
        project_id="project-1",
        state=OperationalControlState.RUNNING,
        reason="reconciled",
        actor=actor,
        reconciled=True,
    )
    assert resumed["generation"] == 2

    with pytest.raises(KeyError, match="unknown Attempt"):
        manager.effective_for_attempt("missing")
    assert manager.effective_for_attempt("attempt-1")[0] is OperationalControlState.RUNNING
    manager.set(
        scope=ControlScope.PROVIDER,
        scope_id="codex",
        project_id=None,
        state=OperationalControlState.PAUSED,
        reason="provider maintenance",
        actor=actor,
    )
    effective, _ = manager.effective_for_attempt("attempt-1", provider_id="codex")
    assert effective is OperationalControlState.PAUSED
    with pytest.raises(RuntimeAuthorizationError, match="PAUSED"):
        manager.assert_dispatch_allowed("attempt-1", provider_id="codex")
    store.rows[("workstreams", "workstream-1")]["state"] = "BLOCKED"
    with pytest.raises(RuntimeAuthorizationError, match="dependency-local"):
        manager.effective_for_attempt("attempt-1")


@pytest.mark.unit
def test_emergency_attempt_reports_only_confirmed_termination() -> None:
    store = FakeStore()
    coordinator = FakeCoordinator()
    manager = OperationalControlManager(store, coordinator, clock=lambda: 10)  # type: ignore[arg-type]
    actor = _actor()
    with pytest.raises(KeyError, match="unknown Attempt"):
        manager.emergency_attempt("missing", termination_confirmed=True, actor=actor)
    store.rows[("attempts", "attempt-1")]["state"] = "FINISHED"
    with pytest.raises(RuntimeTransitionError, match="RUNNING"):
        manager.emergency_attempt("attempt-1", termination_confirmed=True, actor=actor)
    store.rows[("attempts", "attempt-1")]["state"] = "RUNNING"
    assert manager.emergency_attempt(
        "attempt-1", termination_confirmed=True, actor=actor
    )["state"] == "CANCELLED"
    pending = manager.emergency_attempt(
        "attempt-1", termination_confirmed=False, actor=actor
    )
    assert pending == {
        "attempt_id": "attempt-1",
        "state": "NEEDS_RECONCILIATION",
        "termination_confirmed": False,
        "stop_claimed": False,
    }
    assert coordinator.actions == [
        ("cancel", "attempt-1"),
        ("unknown", "attempt-1"),
        ("reconcile", "attempt-1"),
    ]
