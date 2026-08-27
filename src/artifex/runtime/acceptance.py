"""Acceptance Authority separated from runtime completion."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from time import time
from typing import Any

from artifex.policy import scrub_secrets
from artifex.runtime.models import (
    AcceptanceDecision,
    AcceptanceOutcome,
    ActorLike,
    ActorPrincipal,
    ActorType,
    EvidenceBindingError,
    FenceToken,
    ProjectJobState,
    RuntimeAuthorizationError,
    RuntimeTransitionError,
    actor_principal,
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
        actor_id: ActorLike,
        reason: str,
        evidence_ids: tuple[str, ...] = (),
        correlation_id: str | None = None,
    ) -> AcceptanceDecision:
        principal = actor_principal(actor_id)
        if not reason.strip():
            raise ValueError("Acceptance Authority actor and reason are required")
        safe_reason = scrub_secrets(reason)
        job = self.store.get("project_jobs", "project_job_id", project_job_id)
        if job is None or job["state"] != ProjectJobState.FINISHED.value:
            raise RuntimeTransitionError("only a FINISHED ProjectJob may enter acceptance")
        now = self.clock()
        run = self.store.get("runs", "run_id", str(job["run_id"]))
        if run is None:
            raise RuntimeTransitionError("ProjectJob Run is missing")
        if isinstance(actor_id, ActorPrincipal) and principal.actor_type in {
            ActorType.PROVIDER,
            ActorType.AUTOMATION_SYSTEM_ACTOR,
            ActorType.INTERACTION_CLIENT,
        }:
            raise RuntimeAuthorizationError(
                "provider, automation and interaction actors cannot decide Project acceptance"
            )
        principal.require("acceptance:decide", str(run["project_id"]), now=now)
        envelope = self.store.envelope(
            str(run["envelope_id"]), int(str(run["envelope_version"]))
        )
        if envelope is None:
            raise RuntimeTransitionError("ProjectJob Execution Envelope is missing")
        snapshot = self.store.snapshot_run(str(run["run_id"]))
        attempts = [
            value
            for value in snapshot["attempts"]
            if value["project_job_id"] == project_job_id
            and value["state"] == "FINISHED"
        ]
        if not attempts:
            raise RuntimeTransitionError("ProjectJob has no FINISHED Attempt")
        attempt = max(attempts, key=lambda value: int(value["ordinal"]))
        dispatch = self.store.dispatch_authorization(str(attempt["attempt_id"]))
        if dispatch is not None and str(dispatch["actor_id"]) == principal.actor_id:
            raise RuntimeAuthorizationError(
                "dispatch authority cannot decide acceptance for its own execution"
            )
        records = self.store.evidence(evidence_ids)
        durable_valid = self._validate_evidence(
            records,
            evidence_ids,
            project_job_id=project_job_id,
            attempt_id=str(attempt["attempt_id"]),
            envelope=envelope,
        )
        if outcome is AcceptanceOutcome.ACCEPT:
            if bool(envelope.get("require_durable_evidence", False)) and not durable_valid:
                raise EvidenceBindingError(
                    "ACCEPT requires complete durable evidence bound to Attempt and baseline"
                )
            if not evidence_valid or (evidence_ids and not durable_valid):
                raise RuntimeTransitionError("ACCEPT requires valid evidence")
        decision = AcceptanceDecision(
            decision_id=f"decision-{uuid.uuid4()}",
            project_job_id=project_job_id,
            outcome=outcome,
            evidence_valid=evidence_valid,
            actor_id=principal.actor_id,
            reason=safe_reason,
            decided_at=now,
            evidence_ids=evidence_ids,
            envelope_fingerprint=str(envelope["fingerprint"]),
        )
        target = {
            AcceptanceOutcome.ACCEPT: ProjectJobState.ACCEPTED,
            AcceptanceOutcome.REJECT: ProjectJobState.REJECTED,
            AcceptanceOutcome.REWORK: ProjectJobState.REWORK,
            AcceptanceOutcome.REQUIRE_APPROVAL: ProjectJobState.REQUIRE_APPROVAL,
        }[outcome]
        self.store.record_acceptance(
            decision.to_dict(),
            self.token,
            now=now,
            target_state=target.value,
            actor=principal,
            correlation_id=correlation_id,
        )
        return decision

    @staticmethod
    def _validate_evidence(
        records: tuple[dict[str, object], ...],
        requested_ids: tuple[str, ...],
        *,
        project_job_id: str,
        attempt_id: str,
        envelope: Mapping[str, Any],
    ) -> bool:
        if len(records) != len(requested_ids) or len(set(requested_ids)) != len(requested_ids):
            return False
        authority_gates = {"acceptance", "acceptance-authority", "project-authority"}
        required = {
            str(gate)
            for gate in envelope["required_gates"]
            if str(gate).casefold() not in authority_gates
        }
        passed: set[str] = set()
        for record in records:
            if (
                str(record["project_job_id"]) != project_job_id
                or str(record["attempt_id"]) != attempt_id
                or str(record["envelope_fingerprint"]) != str(envelope["fingerprint"])
                or int(str(record["baseline_revision"]))
                != int(str(envelope["baseline_revision"]))
                or not bool(record["passed"])
            ):
                return False
            passed.add(str(record["gate"]))
        return required.issubset(passed)


__all__ = ["RuntimeAcceptanceAuthority"]
