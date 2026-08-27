"""Persistent isolated Execution Workspaces and guarded semantic promotion."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path
from time import time

from artifex.project import ProjectAuthority, ProjectModel
from artifex.runtime.models import (
    AcceptanceDecision,
    AcceptanceOutcome,
    FenceToken,
    ProjectJobState,
    PromotionConflictError,
    RuntimeTransitionError,
)
from artifex.runtime.store import SQLiteRunStore


def _clock() -> int:
    return int(time())


class WorkspaceManager:
    def __init__(
        self,
        store: SQLiteRunStore,
        token: FenceToken,
        workspace_root: str | Path,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.token = token
        self.root = Path(workspace_root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.clock = clock

    def create(
        self,
        workspace_id: str,
        attempt_id: str,
        project_root: str | Path,
        baseline_revision: int,
        *,
        actor_id: str,
    ) -> Path:
        source = Path(project_root).expanduser().resolve()
        target = self.root / workspace_id
        if target.exists():
            raise FileExistsError(f"Execution Workspace already exists: {workspace_id}")
        shutil.copytree(source, target, ignore=shutil.ignore_patterns(".git"))
        now = self.clock()
        self.store.insert(
            "workspaces",
            {
                "workspace_id": workspace_id,
                "attempt_id": attempt_id,
                "project_root": str(source),
                "workspace_root": str(target),
                "baseline_revision": baseline_revision,
                "state": "ACTIVE",
                "created_at": now,
            },
            self.token,
            now=now,
            actor_id=actor_id,
            event_type="WORKSPACE_CREATED",
        )
        return target

    def promote(
        self,
        workspace_id: str,
        model: ProjectModel,
        decision: AcceptanceDecision,
        *,
        actor_id: str,
    ) -> int:
        workspace = self.store.get("workspaces", "workspace_id", workspace_id)
        if workspace is None or workspace["state"] != "ACTIVE":
            raise RuntimeTransitionError("Execution Workspace is not active")
        attempt = self.store.get("attempts", "attempt_id", str(workspace["attempt_id"]))
        if attempt is None:
            raise RuntimeTransitionError("Execution Workspace Attempt is missing")
        job_id = str(attempt["project_job_id"])
        if decision.project_job_id != job_id or decision.outcome is not AcceptanceOutcome.ACCEPT:
            raise RuntimeTransitionError("promotion requires matching Acceptance Authority ACCEPT")
        job = self.store.get("project_jobs", "project_job_id", job_id)
        if job is None or job["state"] != ProjectJobState.ACCEPTED.value:
            raise RuntimeTransitionError("ProjectJob has not been accepted")

        authority = ProjectAuthority(str(workspace["project_root"]))
        current = authority.current()
        now = self.clock()
        baseline = int(workspace["baseline_revision"])
        if current.number != baseline:
            self.store.set_workspace_state(
                workspace_id, "ACTIVE", "PROMOTION_CONFLICT", self.token, now=now, actor_id=actor_id
            )
            self.store.transition(
                "project_jobs",
                "project_job_id",
                job_id,
                expected_state=ProjectJobState.ACCEPTED.value,
                target_state=ProjectJobState.PROMOTION_CONFLICT.value,
                token=self.token,
                now=now,
                actor_id=actor_id,
            )
            raise PromotionConflictError(
                f"workspace baseline {baseline} is stale; current revision is {current.number}"
            )
        proposal = authority.propose(
            model,
            expected_revision=baseline,
            actor=actor_id,
            source="EXECUTION_WORKSPACE_PROMOTION",
        )
        revision = authority.accept(
            proposal.id,
            expected_revision=baseline,
            actor=actor_id,
        )
        self.store.set_workspace_state(
            workspace_id, "ACTIVE", "PROMOTED", self.token, now=now, actor_id=actor_id
        )
        return revision.number


__all__ = ["WorkspaceManager"]
