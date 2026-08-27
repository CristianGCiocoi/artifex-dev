"""Restartable managed-service composition over the standalone RunStore."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from time import time

from artifex.project import ProjectModel
from artifex.runtime.acceptance import RuntimeAcceptanceAuthority
from artifex.runtime.coordinator import ExecutionCoordinator
from artifex.runtime.models import (
    AcceptanceDecision,
    AcceptanceOutcome,
    ExecutionEnvelope,
    ReconciliationOutcome,
)
from artifex.runtime.store import SQLiteRunStore
from artifex.runtime.workspace import WorkspaceManager


def _clock() -> int:
    return int(time())


class ManagedRuntimeService:
    """Service-owned durable runtime; safe to reconstruct after frontend exit."""

    def __init__(
        self,
        store_path: str | Path,
        *,
        service_id: str = "artifex-managed-service",
        workspace_root: str | Path | None = None,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = SQLiteRunStore(store_path)
        self.coordinator = ExecutionCoordinator(
            self.store, service_id, clock=clock, lease_seconds=30
        )
        self.acceptance = RuntimeAcceptanceAuthority(
            self.store, self.coordinator.token, clock=clock
        )
        root = (
            Path(workspace_root)
            if workspace_root is not None
            else Path(store_path).expanduser().resolve().parent / "workspaces"
        )
        self.workspaces = WorkspaceManager(self.store, self.coordinator.token, root, clock=clock)

    def bootstrap_run(
        self,
        envelope: ExecutionEnvelope,
        *,
        workstream_id: str,
        run_id: str,
        project_job_id: str,
        attempt_id: str,
        purpose: str,
        actor_id: str,
    ) -> dict[str, object]:
        self.coordinator.approve_envelope(envelope)
        self.coordinator.create_workstream(workstream_id, envelope.project_id, actor_id=actor_id)
        self.coordinator.create_run(
            run_id,
            workstream_id,
            envelope.project_id,
            envelope.envelope_id,
            envelope.version,
            actor_id=actor_id,
        )
        self.coordinator.create_project_job(project_job_id, run_id, purpose, actor_id=actor_id)
        self.coordinator.create_attempt(attempt_id, project_job_id, actor_id=actor_id)
        self.coordinator.start_attempt(attempt_id, actor_id=actor_id)
        return {
            **self.coordinator.snapshot(run_id),
            "provider_dispatch": False,
            "automated_codex_execution": False,
        }

    def finish(self, attempt_id: str, result_claim: str, *, actor_id: str) -> None:
        self.coordinator.finish_attempt(attempt_id, result_claim, actor_id=actor_id)

    def cancel(self, attempt_id: str, *, actor_id: str) -> None:
        self.coordinator.cancel_attempt(attempt_id, actor_id=actor_id)

    def accept(
        self,
        project_job_id: str,
        *,
        evidence_valid: bool,
        actor_id: str,
        reason: str,
    ) -> AcceptanceDecision:
        decision = self.acceptance.decide(
            project_job_id,
            AcceptanceOutcome.ACCEPT,
            evidence_valid=evidence_valid,
            actor_id=actor_id,
            reason=reason,
        )
        self.coordinator.settle_run_for_job(project_job_id, actor_id=actor_id)
        return decision

    def mark_unknown(self, attempt_id: str, *, actor_id: str) -> None:
        self.coordinator.mark_unknown(attempt_id, actor_id=actor_id)

    def begin_reconciliation(self, attempt_id: str, *, actor_id: str) -> None:
        self.coordinator.begin_reconciliation(attempt_id, actor_id=actor_id)

    def reconcile(
        self,
        attempt_id: str,
        outcome: ReconciliationOutcome,
        *,
        actor_id: str,
        recovered_claim: str | None = None,
    ) -> None:
        self.coordinator.reconcile_attempt(
            attempt_id,
            outcome,
            actor_id=actor_id,
            recovered_claim=recovered_claim,
        )

    def create_workspace(
        self,
        workspace_id: str,
        attempt_id: str,
        project_root: str | Path,
        baseline_revision: int,
        *,
        actor_id: str,
    ) -> Path:
        return self.workspaces.create(
            workspace_id, attempt_id, project_root, baseline_revision, actor_id=actor_id
        )

    def promote_workspace(
        self,
        workspace_id: str,
        model: ProjectModel,
        decision: AcceptanceDecision,
        *,
        actor_id: str,
    ) -> int:
        return self.workspaces.promote(workspace_id, model, decision, actor_id=actor_id)

    def promote_accepted_workspace(
        self,
        workspace_id: str,
        model: ProjectModel,
        project_job_id: str,
        *,
        actor_id: str,
    ) -> int:
        value = self.store.acceptance(project_job_id)
        if value is None:
            raise ValueError("ProjectJob has no Acceptance Authority decision")
        decision = AcceptanceDecision(
            decision_id=str(value["decision_id"]),
            project_job_id=str(value["project_job_id"]),
            outcome=AcceptanceOutcome(str(value["outcome"])),
            evidence_valid=bool(value["evidence_valid"]),
            actor_id=str(value["actor_id"]),
            reason=str(value["reason"]),
            decided_at=int(value["decided_at"]),
        )
        return self.promote_workspace(workspace_id, model, decision, actor_id=actor_id)

    def status(self, run_id: str) -> dict[str, object]:
        return {
            **self.coordinator.snapshot(run_id),
            "projection": {
                "scope": "RUNTIME",
                "authoritative": False,
                "derived_from": "SQLiteRunStore",
            },
            "provider_dispatch": False,
            "automated_codex_execution": False,
        }


__all__ = ["ManagedRuntimeService"]
