"""Collaborative sessions, material decisions, and scope-aware operational control."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from time import time
from typing import Any, ClassVar

from artifex.project import ProjectAuthority
from artifex.runtime.coordinator import ExecutionCoordinator
from artifex.runtime.models import (
    ActorPrincipal,
    ActorType,
    AttemptState,
    Materiality,
    RuntimeAuthorizationError,
    RuntimeTransitionError,
    WorkstreamState,
)
from artifex.runtime.store import SQLiteRunStore


def _clock() -> int:
    return int(time())


class InteractionState(StrEnum):
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"
    CLOSED = "CLOSED"


class DecisionOutcome(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REWORK = "REWORK"


class OperationalControlState(StrEnum):
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    PAUSED = "PAUSED"
    EMERGENCY_STOP = "EMERGENCY_STOP"


class ControlScope(StrEnum):
    PLATFORM = "PLATFORM"
    PROJECT = "PROJECT"
    WORKSTREAM = "WORKSTREAM"
    RUN = "RUN"
    PROJECT_JOB = "PROJECT_JOB"
    PROVIDER = "PROVIDER"


@dataclass(frozen=True, slots=True)
class InteractionSession:
    session_id: str
    project_id: str
    actor_id: str
    actor_type: ActorType
    delegated_actions: tuple[str, ...]
    opened_revision: int
    last_seen_revision: int
    state: InteractionState
    workstream_id: str | None = None
    run_id: str | None = None
    delegation_id: str | None = None

    @classmethod
    def from_row(cls, value: Mapping[str, Any]) -> InteractionSession:
        return cls(
            session_id=str(value["session_id"]),
            project_id=str(value["project_id"]),
            actor_id=str(value["actor_id"]),
            actor_type=ActorType(str(value["actor_type"])),
            delegated_actions=tuple(str(item) for item in value["delegated_actions"]),
            opened_revision=int(value["opened_revision"]),
            last_seen_revision=int(value["last_seen_revision"]),
            state=InteractionState(str(value["state"])),
            workstream_id=_optional_row_string(value.get("workstream_id")),
            run_id=_optional_row_string(value.get("run_id")),
            delegation_id=_optional_row_string(value.get("delegation_id")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "project_id": self.project_id,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type.value,
            "delegated_actions": list(self.delegated_actions),
            "opened_revision": self.opened_revision,
            "last_seen_revision": self.last_seen_revision,
            "state": self.state.value,
            "workstream_id": self.workstream_id,
            "run_id": self.run_id,
            "delegation_id": self.delegation_id,
        }


class InteractionSessionManager:
    """RunStore authority for frontend-neutral reconnectable sessions."""

    def __init__(
        self,
        store: SQLiteRunStore,
        coordinator: ExecutionCoordinator,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.coordinator = coordinator
        self.clock = clock

    def open(
        self,
        project_root: str,
        *,
        actor: ActorPrincipal,
        workstream_id: str | None = None,
        run_id: str | None = None,
        session_id: str | None = None,
    ) -> tuple[InteractionSession, str]:
        revision = ProjectAuthority(project_root).current()
        actor.require("interaction:connect", revision.project_id, now=self.clock())
        if actor.actor_type is not ActorType.INTERACTION_CLIENT:
            raise RuntimeAuthorizationError("InteractionSession requires INTERACTION_CLIENT actor")
        if run_id is not None:
            run = self.store.get("runs", "run_id", run_id)
            if run is None or str(run["project_id"]) != revision.project_id:
                raise ValueError("InteractionSession Run is outside the Project")
            if workstream_id is not None and str(run["workstream_id"]) != workstream_id:
                raise ValueError("InteractionSession Run and Workstream do not match")
        if workstream_id is not None:
            workstream = self.store.get("workstreams", "workstream_id", workstream_id)
            if workstream is None or str(workstream["project_id"]) != revision.project_id:
                raise ValueError("InteractionSession Workstream is outside the Project")
        identifier = session_id or f"session-{uuid.uuid4()}"
        reconnect_token = secrets.token_urlsafe(32)
        now = self.clock()
        actions = actor.direct_permissions
        if actor.delegation is not None:
            actions = actor.delegation.allowed_actions
        self.store.create_interaction_session(
            {
                "session_id": identifier,
                "project_id": revision.project_id,
                "workstream_id": workstream_id,
                "run_id": run_id,
                "actor_id": actor.actor_id,
                "actor_type": actor.actor_type.value,
                "delegation_id": (
                    actor.delegation.grant_id if actor.delegation is not None else None
                ),
                "delegated_actions": json.dumps(actions, sort_keys=True),
                "opened_revision": revision.number,
                "last_seen_revision": revision.number,
                "state": InteractionState.ACTIVE.value,
                "reconnect_token_hash": _token_hash(reconnect_token),
                "created_at": now,
                "updated_at": now,
            },
            self.coordinator.token,
            now=now,
            actor=actor,
        )
        return self.require(identifier), reconnect_token

    def require(self, session_id: str) -> InteractionSession:
        value = self.store.interaction_session(session_id)
        if value is None:
            raise KeyError(f"unknown InteractionSession: {session_id}")
        return InteractionSession.from_row(value)

    def require_active(self, session_id: str, actor: ActorPrincipal) -> InteractionSession:
        session = self.require(session_id)
        if session.state is not InteractionState.ACTIVE:
            raise RuntimeTransitionError("InteractionSession is not ACTIVE; reconnect is required")
        if actor.actor_id != session.actor_id or actor.actor_type is not session.actor_type:
            raise RuntimeAuthorizationError("InteractionSession actor does not match")
        actor.require("interaction:write", session.project_id, now=self.clock())
        return session

    def disconnect(self, session_id: str, *, actor: ActorPrincipal) -> InteractionSession:
        session = self.require_active(session_id, actor)
        self._transition(session, InteractionState.DISCONNECTED, actor, "INTERACTION_DISCONNECTED")
        return self.require(session_id)

    def reconnect(
        self, session_id: str, reconnect_token: str, *, actor: ActorPrincipal
    ) -> InteractionSession:
        session = self.require(session_id)
        if session.state is not InteractionState.DISCONNECTED:
            raise RuntimeTransitionError("only a DISCONNECTED InteractionSession may reconnect")
        if actor.actor_id != session.actor_id or actor.actor_type is not session.actor_type:
            raise RuntimeAuthorizationError("InteractionSession actor does not match")
        value = self.store.interaction_session(session_id)
        assert value is not None
        if not hmac.compare_digest(
            str(value["reconnect_token_hash"]), _token_hash(reconnect_token)
        ):
            raise RuntimeAuthorizationError("invalid reconnect credential")
        actor.require("interaction:connect", session.project_id, now=self.clock())
        self._transition(session, InteractionState.ACTIVE, actor, "INTERACTION_RECONNECTED")
        return self.require(session_id)

    def close(self, session_id: str, *, actor: ActorPrincipal) -> InteractionSession:
        session = self.require(session_id)
        if session.state is InteractionState.CLOSED:
            return session
        if actor.actor_id != session.actor_id:
            raise RuntimeAuthorizationError("InteractionSession actor does not match")
        actor.require("interaction:connect", session.project_id, now=self.clock())
        self._transition(session, InteractionState.CLOSED, actor, "INTERACTION_CLOSED")
        return self.require(session_id)

    def record_revision(
        self, session_id: str, revision: int, *, actor: ActorPrincipal
    ) -> InteractionSession:
        self.require_active(session_id, actor)
        self.store.update_interaction_session(
            session_id,
            expected_state=InteractionState.ACTIVE.value,
            state=InteractionState.ACTIVE.value,
            last_seen_revision=revision,
            token=self.coordinator.token,
            now=self.clock(),
            actor=actor,
            event_type="INTERACTION_REVISION_OBSERVED",
        )
        return self.require(session_id)

    def list(self, project_id: str) -> tuple[InteractionSession, ...]:
        return tuple(
            InteractionSession.from_row(value)
            for value in self.store.interaction_sessions(project_id)
        )

    def _transition(
        self,
        session: InteractionSession,
        target: InteractionState,
        actor: ActorPrincipal,
        event_type: str,
    ) -> None:
        self.store.update_interaction_session(
            session.session_id,
            expected_state=session.state.value,
            state=target.value,
            last_seen_revision=session.last_seen_revision,
            token=self.coordinator.token,
            now=self.clock(),
            actor=actor,
            event_type=event_type,
        )


class MaterialDecisionManager:
    """Durable DecisionRequests with transactionally local Workstream blocking."""

    def __init__(
        self,
        store: SQLiteRunStore,
        coordinator: ExecutionCoordinator,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.coordinator = coordinator
        self.clock = clock

    def create(
        self,
        *,
        project_id: str,
        question: str,
        affected_workstreams: tuple[str, ...],
        actor: ActorPrincipal,
        run_id: str | None = None,
        decision_request_id: str | None = None,
        materiality: Materiality = Materiality.STRATEGIC_MATERIAL,
    ) -> dict[str, Any]:
        actor.require("governance:request-decision", project_id, now=self.clock())
        if materiality is not Materiality.STRATEGIC_MATERIAL:
            raise ValueError("DecisionRequest blocking is reserved for STRATEGIC_MATERIAL work")
        if not question.strip() or not affected_workstreams:
            raise ValueError("DecisionRequest question and affected Workstreams are required")
        if len(set(affected_workstreams)) != len(affected_workstreams):
            raise ValueError("DecisionRequest affected Workstreams must be unique")
        if run_id is not None:
            run = self.store.get("runs", "run_id", run_id)
            if run is None or str(run["project_id"]) != project_id:
                raise ValueError("DecisionRequest Run is outside Project")
        states: dict[str, str] = {}
        for workstream_id in affected_workstreams:
            value = self.store.get("workstreams", "workstream_id", workstream_id)
            if value is None or str(value["project_id"]) != project_id:
                raise ValueError(f"DecisionRequest Workstream is outside Project: {workstream_id}")
            state = WorkstreamState(str(value["state"]))
            if state not in {WorkstreamState.READY, WorkstreamState.ACTIVE}:
                raise RuntimeTransitionError(
                    f"DecisionRequest cannot block Workstream in {state.value}: {workstream_id}"
                )
            states[workstream_id] = state.value
        identifier = decision_request_id or f"decision-{uuid.uuid4()}"
        now = self.clock()
        self.store.create_decision_request(
            {
                "decision_request_id": identifier,
                "project_id": project_id,
                "run_id": run_id,
                "requested_by": actor.actor_id,
                "materiality": materiality.value,
                "question": question,
                "affected_workstreams": json.dumps(sorted(states)),
                "blocked_from_states": json.dumps(states, sort_keys=True),
                "state": "OPEN",
                "outcome": None,
                "resolution": None,
                "resolved_by": None,
                "created_at": now,
                "resolved_at": None,
            },
            self.coordinator.token,
            now=now,
            actor=actor,
        )
        value = self.store.decision_request(identifier)
        assert value is not None
        return value

    def resolve(
        self,
        decision_request_id: str,
        *,
        outcome: DecisionOutcome,
        resolution: str,
        actor: ActorPrincipal,
    ) -> dict[str, Any]:
        value = self.store.decision_request(decision_request_id)
        if value is None:
            raise KeyError(f"unknown DecisionRequest: {decision_request_id}")
        project_id = str(value["project_id"])
        actor.require("governance:resolve-decision", project_id, now=self.clock())
        if actor.actor_type is not ActorType.USER:
            raise RuntimeAuthorizationError("material DecisionRequest requires USER resolution")
        if not resolution.strip():
            raise ValueError("DecisionRequest resolution is required")
        self.store.resolve_decision_request(
            decision_request_id,
            outcome=outcome.value,
            resolution=resolution,
            restore_workstreams=outcome is DecisionOutcome.APPROVE,
            token=self.coordinator.token,
            now=self.clock(),
            actor=actor,
        )
        updated = self.store.decision_request(decision_request_id)
        assert updated is not None
        return updated

    def assert_project_job_unblocked(self, project_job_id: str) -> None:
        job = self.store.get("project_jobs", "project_job_id", project_job_id)
        if job is None:
            raise KeyError(f"unknown ProjectJob: {project_job_id}")
        run = self.store.get("runs", "run_id", str(job["run_id"]))
        assert run is not None
        workstream = self.store.get(
            "workstreams", "workstream_id", str(run["workstream_id"])
        )
        assert workstream is not None
        if str(workstream["state"]) == WorkstreamState.BLOCKED.value:
            raise RuntimeAuthorizationError(
                "ProjectJob acceptance/promotion blocked by material DecisionRequest"
            )


class OperationalControlManager:
    """Scope-aware dispatch gate preserving honest pause and recovery semantics."""

    _RANK: ClassVar[Mapping[OperationalControlState, int]] = {
        OperationalControlState.RUNNING: 0,
        OperationalControlState.DRAINING: 1,
        OperationalControlState.PAUSED: 2,
        OperationalControlState.EMERGENCY_STOP: 3,
    }

    def __init__(
        self,
        store: SQLiteRunStore,
        coordinator: ExecutionCoordinator,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.coordinator = coordinator
        self.clock = clock

    def set(
        self,
        *,
        scope: ControlScope,
        scope_id: str,
        project_id: str | None,
        state: OperationalControlState,
        reason: str,
        actor: ActorPrincipal,
        reconciled: bool = False,
    ) -> dict[str, Any]:
        if not scope_id.strip() or not reason.strip():
            raise ValueError("control scope identity and reason are required")
        authority_project = project_id or "*"
        actor.require("control:operate", authority_project, now=self.clock())
        if actor.actor_type not in {ActorType.USER, ActorType.ARTIFEX_SERVICE}:
            raise RuntimeAuthorizationError("operational control requires USER or ARTIFEX_SERVICE")
        if scope is ControlScope.PLATFORM:
            if scope_id != "global" or project_id is not None:
                raise ValueError("Platform control uses scope_id=global and no Project")
        elif scope is ControlScope.PROVIDER:
            if project_id is not None:
                raise ValueError("provider control is Platform-wide and has no Project")
        elif project_id is None:
            raise ValueError("non-Platform control requires Project identity")
        else:
            self._validate_project_scope(scope, scope_id, project_id)
        current = self.store.operational_control(scope.value, scope_id)
        previous = (
            OperationalControlState(str(current["state"]))
            if current is not None
            else OperationalControlState.RUNNING
        )
        if (
            previous is OperationalControlState.EMERGENCY_STOP
            and state is not previous
            and not reconciled
        ):
            raise RuntimeTransitionError(
                "EMERGENCY_STOP may clear only after explicit reconciliation"
            )
        generation = int(current["generation"]) + 1 if current is not None else 1
        self.store.set_operational_control(
            scope_type=scope.value,
            scope_id=scope_id,
            project_id=project_id,
            state=state.value,
            reason=reason,
            generation=generation,
            token=self.coordinator.token,
            now=self.clock(),
            actor=actor,
        )
        value = self.store.operational_control(scope.value, scope_id)
        assert value is not None
        return value

    def _validate_project_scope(
        self, scope: ControlScope, scope_id: str, project_id: str
    ) -> None:
        if scope is ControlScope.PROJECT:
            if scope_id != project_id:
                raise ValueError("Project control scope identity does not match Project")
            return
        if scope is ControlScope.WORKSTREAM:
            value = self.store.get("workstreams", "workstream_id", scope_id)
            if value is None or str(value["project_id"]) != project_id:
                raise ValueError("Workstream control is outside Project")
            return
        if scope is ControlScope.RUN:
            value = self.store.get("runs", "run_id", scope_id)
            if value is None or str(value["project_id"]) != project_id:
                raise ValueError("Run control is outside Project")
            return
        if scope is ControlScope.PROJECT_JOB:
            job = self.store.get("project_jobs", "project_job_id", scope_id)
            if job is None:
                raise ValueError("unknown ProjectJob control scope")
            run = self.store.get("runs", "run_id", str(job["run_id"]))
            if run is None or str(run["project_id"]) != project_id:
                raise ValueError("ProjectJob control is outside Project")
            return
        raise ValueError(f"unsupported Project control scope: {scope.value}")

    def effective_for_attempt(
        self, attempt_id: str, *, provider_id: str | None = None
    ) -> tuple[OperationalControlState, tuple[dict[str, Any], ...]]:
        attempt = self.store.get("attempts", "attempt_id", attempt_id)
        if attempt is None:
            raise KeyError(f"unknown Attempt: {attempt_id}")
        job = self.store.get("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        assert job is not None
        run = self.store.get("runs", "run_id", str(job["run_id"]))
        assert run is not None
        workstream_id = str(run["workstream_id"])
        workstream = self.store.get("workstreams", "workstream_id", workstream_id)
        assert workstream is not None
        if str(workstream["state"]) == WorkstreamState.BLOCKED.value:
            raise RuntimeAuthorizationError(
                f"dispatch blocked by dependency-local DecisionRequest: {workstream_id}"
            )
        keys = [
            (ControlScope.PLATFORM.value, "global"),
            (ControlScope.PROJECT.value, str(run["project_id"])),
            (ControlScope.WORKSTREAM.value, workstream_id),
            (ControlScope.RUN.value, str(run["run_id"])),
            (ControlScope.PROJECT_JOB.value, str(job["project_job_id"])),
        ]
        if provider_id is not None:
            keys.append((ControlScope.PROVIDER.value, provider_id))
        controls = tuple(
            value
            for scope, identifier in keys
            if (value := self.store.operational_control(scope, identifier)) is not None
        )
        effective = max(
            (OperationalControlState(str(value["state"])) for value in controls),
            key=self._RANK.__getitem__,
            default=OperationalControlState.RUNNING,
        )
        return effective, controls

    def assert_dispatch_allowed(self, attempt_id: str, *, provider_id: str | None = None) -> None:
        state, _ = self.effective_for_attempt(attempt_id, provider_id=provider_id)
        if state is not OperationalControlState.RUNNING:
            raise RuntimeAuthorizationError(f"new dispatch blocked by {state.value} control")

    def emergency_attempt(
        self,
        attempt_id: str,
        *,
        termination_confirmed: bool,
        actor: ActorPrincipal,
    ) -> dict[str, Any]:
        attempt = self.store.get("attempts", "attempt_id", attempt_id)
        if attempt is None:
            raise KeyError(f"unknown Attempt: {attempt_id}")
        if AttemptState(str(attempt["state"])) is not AttemptState.RUNNING:
            raise RuntimeTransitionError("emergency action requires a RUNNING Attempt")
        if termination_confirmed:
            self.coordinator.cancel_attempt(attempt_id, actor_id=actor)
            return {
                "attempt_id": attempt_id,
                "state": AttemptState.CANCELLED.value,
                "termination_confirmed": True,
            }
        self.coordinator.mark_unknown(attempt_id, actor_id=actor)
        self.coordinator.begin_reconciliation(attempt_id, actor_id=actor)
        return {
            "attempt_id": attempt_id,
            "state": AttemptState.NEEDS_RECONCILIATION.value,
            "termination_confirmed": False,
            "stop_claimed": False,
        }


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _optional_row_string(value: object) -> str | None:
    return str(value) if value is not None else None


__all__ = [
    "ControlScope",
    "DecisionOutcome",
    "InteractionSession",
    "InteractionSessionManager",
    "InteractionState",
    "MaterialDecisionManager",
    "OperationalControlManager",
    "OperationalControlState",
]
