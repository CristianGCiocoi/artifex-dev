"""Acceptance Authority separated from runtime completion."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from time import time

from artifex.runtime.models import (
    AcceptanceDecision,
    AcceptanceOutcome,
    FenceToken,
    ProjectJobState,
    RuntimeTransitionError,
)
from artifex.runtime.store import SQLiteRunStore


def _clock() -> int:
    return int(time())


class RuntimeAcceptanceAuthority:
    """Interpret evidence and decide; never execute Attempts or promote semantics."""

    def __init__(
        self,
        store: SQLiteRunStore,
        token: FenceToken,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.token = token
        self.clock = clock

    def decide(
        self,
        project_job_id: str,
        outcome: AcceptanceOutcome,
        *,
        evidence_valid: bool,
        actor_id: str,
        reason: str,
    ) -> AcceptanceDecision:
        if not actor_id.strip() or not reason.strip():
            raise ValueError("Acceptance Authority actor and reason are required")
        job = self.store.get("project_jobs", "project_job_id", project_job_id)
        if job is None or job["state"] != ProjectJobState.FINISHED.value:
            raise RuntimeTransitionError("only a FINISHED ProjectJob may enter acceptance")
        if outcome is AcceptanceOutcome.ACCEPT and not evidence_valid:
            raise RuntimeTransitionError("ACCEPT requires valid evidence")
        now = self.clock()
        decision = AcceptanceDecision(
            decision_id=f"decision-{uuid.uuid4()}",
            project_job_id=project_job_id,
            outcome=outcome,
            evidence_valid=evidence_valid,
            actor_id=actor_id,
            reason=reason,
            decided_at=now,
        )
        target = {
            AcceptanceOutcome.ACCEPT: ProjectJobState.ACCEPTED,
            AcceptanceOutcome.REJECT: ProjectJobState.REJECTED,
            AcceptanceOutcome.REWORK: ProjectJobState.REWORK,
            AcceptanceOutcome.REQUIRE_APPROVAL: ProjectJobState.REQUIRE_APPROVAL,
        }[outcome]
        self.store.record_acceptance(
            decision.to_dict(), self.token, now=now, target_state=target.value
        )
        return decision


__all__ = ["RuntimeAcceptanceAuthority"]
