from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Event

import pytest

from artifex.runtime import (
    CoordinatorFencedError,
    EnvelopeError,
    ExecutionCoordinator,
    ExecutionEnvelope,
    ManagedRuntimeService,
    ReconciliationOutcome,
    RuntimeTransitionError,
    SQLiteRunStore,
)


class Clock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _envelope(*, max_attempts: int = 2) -> ExecutionEnvelope:
    return ExecutionEnvelope(
        envelope_id="envelope-1",
        version=1,
        project_id="project-1",
        objective="Prove durable runtime authority",
        baseline_revision=1,
        actor_id="architect",
        allowed_paths=("src", "tests"),
        allowed_capabilities=("filesystem:workspace",),
        required_gates=("validation", "acceptance"),
        max_attempts=max_attempts,
        recovery_policy="RECONCILE_BEFORE_RETRY",
    )


def _bootstrap(service: ManagedRuntimeService) -> None:
    service.bootstrap_run(
        _envelope(),
        workstream_id="workstream-1",
        run_id="run-1",
        project_job_id="job-1",
        attempt_id="attempt-1",
        purpose="durability",
        actor_id="operator",
    )


@pytest.mark.architecture
def test_runstore_contains_coordination_not_project_semantic_truth(tmp_path: Path) -> None:
    path = tmp_path / "runstore.sqlite3"
    SQLiteRunStore(path)

    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert {
        "coordinator_lease",
        "envelopes",
        "workstreams",
        "runs",
        "project_jobs",
        "attempts",
        "workspaces",
        "acceptance_decisions",
        "runtime_audit",
    } <= tables
    assert not {"project_model", "semantic_revisions", "semantic_proposals"} & tables


@pytest.mark.adversarial
def test_restart_advances_generation_and_fences_prior_coordinator(tmp_path: Path) -> None:
    clock = Clock()
    store = SQLiteRunStore(tmp_path / "runstore.sqlite3")
    first = ExecutionCoordinator(store, "managed-service", clock=clock)

    with pytest.raises(CoordinatorFencedError, match="held by"):
        ExecutionCoordinator(store, "foreign-service", clock=clock)

    restarted = ExecutionCoordinator(store, "managed-service", clock=clock)
    assert restarted.token.generation == first.token.generation + 1
    with pytest.raises(CoordinatorFencedError, match="stale"):
        first.create_workstream("stale", "project-1", actor_id="old-process")

    restarted.create_workstream("current", "project-1", actor_id="new-process")
    clock.value += 31
    recovered = ExecutionCoordinator(store, "recovered-service", clock=clock)
    assert recovered.token.generation == restarted.token.generation + 1


@pytest.mark.adversarial
def test_related_runtime_transitions_roll_back_as_one_transaction(tmp_path: Path) -> None:
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3")
    _bootstrap(service)

    with pytest.raises(CoordinatorFencedError, match="state mismatch"):
        service.store.transition_batch(
            (
                {
                    "table": "attempts",
                    "id_column": "attempt_id",
                    "identifier": "attempt-1",
                    "expected_state": "RUNNING",
                    "target_state": "FINISHED",
                },
                {
                    "table": "project_jobs",
                    "id_column": "project_job_id",
                    "identifier": "job-1",
                    "expected_state": "PENDING",
                    "target_state": "FINISHED",
                },
            ),
            service.coordinator.token,
            now=100,
            actor_id="runtime",
        )

    snapshot = service.status("run-1")
    assert snapshot["attempts"][0]["state"] == "RUNNING"
    assert snapshot["project_jobs"][0]["state"] == "RUNNING"


@pytest.mark.unit
def test_execution_envelope_is_mandatory_and_codex_provider_is_outside_m2(
    tmp_path: Path,
) -> None:
    store = SQLiteRunStore(tmp_path / "runstore.sqlite3")
    coordinator = ExecutionCoordinator(store, "service")
    coordinator.create_workstream("workstream-1", "project-1", actor_id="operator")

    with pytest.raises(RuntimeTransitionError, match="approved Execution Envelope"):
        coordinator.create_run(
            "run-1",
            "workstream-1",
            "project-1",
            "missing",
            1,
            actor_id="operator",
        )
    with pytest.raises(EnvelopeError, match="outside M2"):
        ExecutionEnvelope(
            envelope_id="unsafe",
            version=1,
            project_id="project-1",
            objective="dispatch Codex",
            baseline_revision=1,
            actor_id="operator",
            allowed_paths=("src",),
            allowed_capabilities=("provider:codex",),
            required_gates=("validation",),
            max_attempts=1,
            recovery_policy="RECONCILE_BEFORE_RETRY",
        )


def test_managed_service_renews_fence_while_provider_call_is_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ManagedRuntimeService(tmp_path / "heartbeat.sqlite3")
    renewed = Event()
    original_renew = service.coordinator.renew

    def renew() -> object:
        token = original_renew()
        renewed.set()
        return token

    monkeypatch.setattr(service.coordinator, "renew", renew)
    with service.coordinator_heartbeat(interval_seconds=0.01):
        assert renewed.wait(1)


@pytest.mark.integration
def test_j05_committed_hierarchy_survives_service_and_frontend_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runstore.sqlite3"
    clock = Clock()
    first = ManagedRuntimeService(path, service_id="runtime-service", clock=clock)
    _bootstrap(first)
    first.finish("attempt-1", "validation passed", actor_id="worker")

    restarted = ManagedRuntimeService(path, service_id="runtime-service", clock=clock)
    status = restarted.status("run-1")

    assert status["workstream"]["state"] == "ACTIVE"
    assert status["run"]["state"] == "RUNNING"
    assert status["project_jobs"][0]["state"] == "FINISHED"
    assert status["attempts"][0]["state"] == "FINISHED"
    assert status["acceptance_decisions"] == []
    assert status["projection"] == {
        "scope": "RUNTIME",
        "authoritative": False,
        "derived_from": "SQLiteRunStore",
    }
    assert status["provider_dispatch"] is False
    assert status["automated_codex_execution"] is False

    decision = restarted.accept(
        "job-1", evidence_valid=True, actor_id="acceptance-authority", reason="evidence valid"
    )
    assert decision.outcome.value == "ACCEPT"
    accepted = restarted.status("run-1")
    assert accepted["project_jobs"][0]["state"] == "ACCEPTED"
    assert accepted["run"]["state"] == "COMPLETED"
    assert accepted["workstream"]["state"] == "COMPLETE"
    assert {event["actor_id"] for event in restarted.store.audit()} >= {
        "operator",
        "worker",
        "acceptance-authority",
    }


@pytest.mark.adversarial
def test_j18_unknown_requires_reconciliation_before_retry_or_acceptance(
    tmp_path: Path,
) -> None:
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3")
    _bootstrap(service)
    service.mark_unknown("attempt-1", actor_id="runtime")

    with pytest.raises(RuntimeTransitionError, match="safe reconciliation"):
        service.coordinator.retry_attempt("attempt-1", "attempt-2", actor_id="runtime")
    with pytest.raises(RuntimeTransitionError, match="FINISHED"):
        service.accept(
            "job-1", evidence_valid=True, actor_id="acceptance-authority", reason="premature"
        )

    service.begin_reconciliation("attempt-1", actor_id="reconciler")
    service.reconcile(
        "attempt-1",
        ReconciliationOutcome.RECOVERED_FINISHED,
        actor_id="reconciler",
        recovered_claim="external result recovered",
    )
    snapshot = service.status("run-1")
    assert snapshot["attempts"][0]["state"] == "FINISHED"
    assert snapshot["attempts"][0]["reconciliation_outcome"] == "RECOVERED_FINISHED"
    assert snapshot["project_jobs"][0]["state"] == "FINISHED"
    assert snapshot["acceptance_decisions"] == []


@pytest.mark.integration
def test_safe_retry_is_created_only_after_explicit_reconciliation(tmp_path: Path) -> None:
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3")
    _bootstrap(service)
    service.mark_unknown("attempt-1", actor_id="runtime")
    service.begin_reconciliation("attempt-1", actor_id="reconciler")
    service.reconcile("attempt-1", ReconciliationOutcome.SAFE_TO_RETRY, actor_id="reconciler")
    service.coordinator.retry_attempt("attempt-1", "attempt-2", actor_id="runtime")

    attempts = service.status("run-1")["attempts"]
    assert [attempt["state"] for attempt in attempts] == [
        "RECONCILED_RETRYABLE",
        "PENDING",
    ]
    assert [attempt["ordinal"] for attempt in attempts] == [1, 2]


@pytest.mark.integration
def test_cancel_is_durable_but_cannot_hide_an_unknown_external_outcome(tmp_path: Path) -> None:
    service = ManagedRuntimeService(tmp_path / "cancel.sqlite3")
    _bootstrap(service)
    service.cancel("attempt-1", actor_id="operator")
    cancelled = service.status("run-1")
    assert cancelled["attempts"][0]["state"] == "CANCELLED"
    assert cancelled["project_jobs"][0]["state"] == "CANCELLED"
    assert cancelled["run"]["state"] == "COMPLETED"

    unknown = ManagedRuntimeService(tmp_path / "unknown.sqlite3")
    _bootstrap(unknown)
    unknown.mark_unknown("attempt-1", actor_id="runtime")
    with pytest.raises(RuntimeTransitionError, match="without reconciliation"):
        unknown.cancel("attempt-1", actor_id="operator")
