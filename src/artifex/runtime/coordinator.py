"""Fenced durable execution coordination without provider dispatch."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from time import time

from artifex.policy import scrub_secrets
from artifex.runtime.models import (
    ActorLike,
    ActorPrincipal,
    ActorType,
    AttemptState,
    CredentialReference,
    DispatchAuthorization,
    EvidenceRecord,
    ExecutionEnvelope,
    FenceToken,
    ProjectJobState,
    ReconciliationOutcome,
    RunState,
    RuntimeAuthorizationError,
    RuntimeTransitionError,
    WorkstreamState,
    actor_principal,
)
from artifex.runtime.store import SQLiteRunStore


def _clock() -> int:
    return int(time())


class ExecutionCoordinator:
    """Own runtime transitions, but never evidence interpretation or acceptance."""

    def __init__(
        self,
        store: SQLiteRunStore,
        holder_id: str,
        *,
        clock: Callable[[], int] = _clock,
        lease_seconds: int = 30,
    ) -> None:
        self.store = store
        self.holder_id = holder_id
        self.clock = clock
        self.lease_seconds = lease_seconds
        self.token = store.acquire_coordinator(holder_id, now=clock(), ttl_seconds=lease_seconds)

    def renew(self) -> FenceToken:
        self.token = self.store.renew_coordinator(
            self.token, now=self.clock(), ttl_seconds=self.lease_seconds
        )
        return self.token

    def approve_envelope(
        self,
        envelope: ExecutionEnvelope,
        *,
        actor: ActorLike | None = None,
        correlation_id: str | None = None,
    ) -> None:
        approval_actor = actor if actor is not None else envelope.actor_id
        principal = actor_principal(approval_actor)
        if isinstance(approval_actor, ActorPrincipal) and principal.actor_type in {
            ActorType.PROVIDER,
            ActorType.AUTOMATION_SYSTEM_ACTOR,
            ActorType.INTERACTION_CLIENT,
        }:
            raise RuntimeAuthorizationError(
                "provider, automation and interaction actors cannot approve Execution Envelopes"
            )
        self.store.put_envelope(
            envelope,
            self.token,
            now=self.clock(),
            actor=approval_actor,
            correlation_id=correlation_id,
        )

    def create_workstream(
        self, workstream_id: str, project_id: str, *, actor_id: ActorLike
    ) -> None:
        now = self.clock()
        self.store.insert(
            "workstreams",
            {
                "workstream_id": workstream_id,
                "project_id": project_id,
                "state": WorkstreamState.READY.value,
                "created_at": now,
                "updated_at": now,
            },
            self.token,
            now=now,
            actor_id=actor_id,
            event_type="WORKSTREAM_CREATED",
        )

    def create_run(
        self,
        run_id: str,
        workstream_id: str,
        project_id: str,
        envelope_id: str,
        envelope_version: int,
        *,
        actor_id: ActorLike,
    ) -> None:
        envelope = self.store.envelope(envelope_id, envelope_version)
        if envelope is None or not envelope["approved"]:
            raise RuntimeTransitionError("Run requires an approved Execution Envelope")
        if envelope["project_id"] != project_id:
            raise RuntimeTransitionError("Envelope Project does not match Run Project")
        allowed_workstreams = tuple(str(item) for item in envelope.get("allowed_workstreams", ()))
        if allowed_workstreams and workstream_id not in allowed_workstreams:
            raise RuntimeAuthorizationError("Workstream is outside the Execution Envelope scope")
        deadline = envelope.get("deadline_at")
        if deadline is not None and self.clock() >= int(deadline):
            raise RuntimeAuthorizationError("Execution Envelope deadline has expired")
        workstream = self._require("workstreams", "workstream_id", workstream_id)
        if workstream["project_id"] != project_id:
            raise RuntimeTransitionError("Workstream Project does not match Run Project")
        now = self.clock()
        self.store.insert(
            "runs",
            {
                "run_id": run_id,
                "workstream_id": workstream_id,
                "project_id": project_id,
                "envelope_id": envelope_id,
                "envelope_version": envelope_version,
                "state": RunState.PENDING.value,
                "created_at": now,
                "updated_at": now,
            },
            self.token,
            now=now,
            actor_id=actor_id,
            event_type="RUN_CREATED",
        )

    def create_project_job(
        self, project_job_id: str, run_id: str, purpose: str, *, actor_id: ActorLike
    ) -> None:
        if not purpose.strip():
            raise ValueError("ProjectJob purpose is required")
        self._require("runs", "run_id", run_id)
        now = self.clock()
        self.store.insert(
            "project_jobs",
            {
                "project_job_id": project_job_id,
                "run_id": run_id,
                "state": ProjectJobState.PENDING.value,
                "purpose": purpose,
                "created_at": now,
                "updated_at": now,
            },
            self.token,
            now=now,
            actor_id=actor_id,
            event_type="PROJECT_JOB_CREATED",
        )

    def create_attempt(self, attempt_id: str, project_job_id: str, *, actor_id: ActorLike) -> None:
        job = self._require("project_jobs", "project_job_id", project_job_id)
        snapshot = self.store.snapshot_run(str(job["run_id"]))
        current_attempts = [
            item for item in snapshot["attempts"] if item["project_job_id"] == project_job_id
        ]
        envelope_row = snapshot["run"]
        envelope = self.store.envelope(
            str(envelope_row["envelope_id"]), int(envelope_row["envelope_version"])
        )
        assert envelope is not None
        ordinal = len(current_attempts) + 1
        if ordinal > int(envelope["max_attempts"]):
            raise RuntimeTransitionError("Execution Envelope attempt limit reached")
        now = self.clock()
        self.store.insert(
            "attempts",
            {
                "attempt_id": attempt_id,
                "project_job_id": project_job_id,
                "ordinal": ordinal,
                "state": AttemptState.PENDING.value,
                "result_claim": None,
                "reconciliation_outcome": None,
                "created_at": now,
                "updated_at": now,
            },
            self.token,
            now=now,
            actor_id=actor_id,
            event_type="ATTEMPT_CREATED",
        )

    def authorize_attempt_dispatch(
        self,
        attempt_id: str,
        *,
        provider_id: str,
        provider_role: str,
        requested_capabilities: tuple[str, ...],
        filesystem_permissions: tuple[str, ...],
        network_permissions: tuple[str, ...] = (),
        tool_permissions: tuple[str, ...] = (),
        credential_reference_ids: tuple[str, ...] = (),
        actor: ActorPrincipal,
        correlation_id: str | None = None,
    ) -> DispatchAuthorization:
        """Authorize one provider dispatch against the immutable Envelope.

        This seam deliberately does not select a provider. The M3 contextual
        resolver supplies a candidate; the coordinator enforces the resulting
        request before a process may be launched.
        """

        attempt = self._require("attempts", "attempt_id", attempt_id)
        if attempt["state"] != AttemptState.PENDING.value:
            raise RuntimeTransitionError("only a PENDING Attempt may be authorized for dispatch")
        job = self._require("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        run = self._require("runs", "run_id", str(job["run_id"]))
        now = self.clock()
        actor.require("runtime:dispatch", str(run["project_id"]), now=now)
        if actor.actor_type not in {
            ActorType.ARTIFEX_SERVICE,
            ActorType.AGENT,
            ActorType.AUTOMATION_SYSTEM_ACTOR,
        }:
            raise RuntimeAuthorizationError("actor type cannot dispatch autonomous execution")
        envelope = self.store.envelope(
            str(run["envelope_id"]), int(str(run["envelope_version"]))
        )
        if envelope is None:
            raise RuntimeTransitionError("Run Execution Envelope is missing")
        if provider_id not in tuple(envelope.get("allowed_providers", ())):
            raise RuntimeAuthorizationError("provider is not allowed by the Execution Envelope")
        if provider_role not in tuple(envelope.get("allowed_provider_roles", ())):
            raise RuntimeAuthorizationError(
                "provider role is not allowed by the Execution Envelope"
            )
        if not set(requested_capabilities).issubset(set(envelope["allowed_capabilities"])):
            raise RuntimeAuthorizationError("requested capability exceeds the Execution Envelope")
        _require_subset(
            filesystem_permissions,
            tuple(envelope.get("filesystem_permissions", ())),
            "filesystem permission",
        )
        _require_subset(
            network_permissions,
            tuple(envelope.get("network_permissions", ())),
            "network permission",
        )
        _require_subset(
            tool_permissions,
            tuple(envelope.get("tool_permissions", ())),
            "tool permission",
        )
        deadline = envelope.get("deadline_at")
        if deadline is not None and now >= int(deadline):
            raise RuntimeAuthorizationError("Execution Envelope deadline has expired")
        references = {
            str(value["reference_id"]): CredentialReference(
                reference_id=str(value["reference_id"]),
                provider_id=str(value["provider_id"]),
                role=str(value["role"]),
                project_id=str(value["project_id"]),
                expires_at=(
                    int(value["expires_at"]) if value.get("expires_at") is not None else None
                ),
                revoked=bool(value.get("revoked", False)),
            )
            for value in envelope.get("credential_references", ())
        }
        for reference_id in credential_reference_ids:
            reference = references.get(reference_id)
            if reference is None or not reference.permits(
                provider_id, provider_role, str(run["project_id"]), now=now
            ):
                raise RuntimeAuthorizationError(
                    "credential reference is absent, expired, revoked or out of scope: "
                    f"{reference_id}"
                )
        authorization = DispatchAuthorization(
            authorization_id=f"dispatch-{uuid.uuid4()}",
            attempt_id=attempt_id,
            provider_id=provider_id,
            provider_role=provider_role,
            requested_capabilities=requested_capabilities,
            filesystem_permissions=filesystem_permissions,
            network_permissions=network_permissions,
            tool_permissions=tool_permissions,
            credential_reference_ids=credential_reference_ids,
            envelope_fingerprint=str(envelope["fingerprint"]),
            actor_id=actor.actor_id,
            authorized_at=now,
        )
        self.store.record_dispatch_authorization(
            authorization,
            self.token,
            now=now,
            actor=actor,
            correlation_id=correlation_id,
        )
        return authorization

    def record_evidence(
        self,
        evidence: EvidenceRecord,
        *,
        actor: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        attempt = self._require("attempts", "attempt_id", evidence.attempt_id)
        if str(attempt["project_job_id"]) != evidence.project_job_id:
            raise RuntimeTransitionError("evidence ProjectJob does not match Attempt")
        job = self._require("project_jobs", "project_job_id", evidence.project_job_id)
        run = self._require("runs", "run_id", str(job["run_id"]))
        envelope = self.store.envelope(
            str(run["envelope_id"]), int(str(run["envelope_version"]))
        )
        if envelope is None or evidence.envelope_fingerprint != envelope["fingerprint"]:
            raise RuntimeTransitionError("evidence does not match the Run Execution Envelope")
        if evidence.baseline_revision != int(envelope["baseline_revision"]):
            raise RuntimeTransitionError("evidence does not match the Run baseline")
        principal = actor_principal(actor)
        principal.require("evidence:record", str(run["project_id"]), now=self.clock())
        if principal.actor_id != evidence.actor_id:
            raise RuntimeAuthorizationError("evidence actor attribution does not match caller")
        self.store.record_evidence(
            evidence,
            self.token,
            now=self.clock(),
            actor=principal,
            correlation_id=correlation_id,
        )

    def start_attempt(self, attempt_id: str, *, actor_id: ActorLike) -> None:
        attempt = self._require("attempts", "attempt_id", attempt_id)
        job = self._require("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        run = self._require("runs", "run_id", str(job["run_id"]))
        workstream = self._require("workstreams", "workstream_id", str(run["workstream_id"]))
        envelope = self.store.envelope(
            str(run["envelope_id"]), int(str(run["envelope_version"]))
        )
        if envelope is None:
            raise RuntimeTransitionError("Run Execution Envelope is missing")
        if (
            envelope.get("allowed_providers")
            and self.store.dispatch_authorization(attempt_id) is None
        ):
            raise RuntimeAuthorizationError(
                "provider Attempt cannot start before dispatch authorization"
            )
        now = self.clock()
        if workstream["state"] == WorkstreamState.READY.value:
            self._transition(
                "workstreams",
                "workstream_id",
                str(workstream["workstream_id"]),
                WorkstreamState.READY.value,
                WorkstreamState.ACTIVE.value,
                actor_id,
                now,
            )
        if run["state"] == RunState.PENDING.value:
            self._transition(
                "runs",
                "run_id",
                str(run["run_id"]),
                RunState.PENDING.value,
                RunState.RUNNING.value,
                actor_id,
                now,
            )
        if job["state"] == ProjectJobState.PENDING.value:
            self._transition(
                "project_jobs",
                "project_job_id",
                str(job["project_job_id"]),
                ProjectJobState.PENDING.value,
                ProjectJobState.RUNNING.value,
                actor_id,
                now,
            )
        self._transition(
            "attempts",
            "attempt_id",
            attempt_id,
            AttemptState.PENDING.value,
            AttemptState.RUNNING.value,
            actor_id,
            now,
        )

    def finish_attempt(
        self,
        attempt_id: str,
        result_claim: str,
        *,
        actor_id: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        if not result_claim.strip():
            raise ValueError("Attempt result claim is required")
        safe_claim = scrub_secrets(result_claim)
        attempt = self._require("attempts", "attempt_id", attempt_id)
        now = self.clock()
        dispatch = self.store.dispatch_authorization(attempt_id)
        if dispatch is not None:
            job = self._require(
                "project_jobs", "project_job_id", str(attempt["project_job_id"])
            )
            run = self._require("runs", "run_id", str(job["run_id"]))
            principal = actor_principal(actor_id)
            principal.require("result:submit", str(run["project_id"]), now=now)
            if isinstance(actor_id, ActorPrincipal) and principal.actor_type not in {
                ActorType.PROVIDER,
                ActorType.ARTIFEX_SERVICE,
            }:
                raise RuntimeAuthorizationError(
                    "only provider or managed-service actors may submit provider results"
                )
            self.store.record_event(
                "PROVIDER_RESULT_RECORDED",
                "attempts",
                attempt_id,
                {
                    "result_claim": safe_claim,
                    "provider_id": dispatch["provider_id"],
                    "provider_role": dispatch["provider_role"],
                    "envelope_fingerprint": dispatch["envelope_fingerprint"],
                },
                self.token,
                now=now,
                actor=principal,
                correlation_id=correlation_id,
            )
        self._transition_batch(
            (
                self._change(
                    "attempts",
                    "attempt_id",
                    attempt_id,
                    AttemptState.RUNNING.value,
                    AttemptState.FINISHED.value,
                    {"result_claim": safe_claim},
                ),
                self._change(
                    "project_jobs",
                    "project_job_id",
                    str(attempt["project_job_id"]),
                    ProjectJobState.RUNNING.value,
                    ProjectJobState.FINISHED.value,
                ),
            ),
            actor_id,
            now,
        )

    def cancel_attempt(self, attempt_id: str, *, actor_id: ActorLike) -> None:
        attempt = self._require("attempts", "attempt_id", attempt_id)
        if attempt["state"] not in {AttemptState.PENDING.value, AttemptState.RUNNING.value}:
            raise RuntimeTransitionError(
                "only PENDING or RUNNING Attempts may be cancelled without reconciliation"
            )
        job = self._require("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        now = self.clock()
        self._transition_batch(
            (
                self._change(
                    "attempts",
                    "attempt_id",
                    attempt_id,
                    str(attempt["state"]),
                    AttemptState.CANCELLED.value,
                ),
                self._change(
                    "project_jobs",
                    "project_job_id",
                    str(job["project_job_id"]),
                    str(job["state"]),
                    ProjectJobState.CANCELLED.value,
                ),
            ),
            actor_id,
            now,
        )
        self.settle_run_for_job(str(job["project_job_id"]), actor_id=actor_id)

    def mark_unknown(self, attempt_id: str, *, actor_id: ActorLike) -> None:
        attempt = self._require("attempts", "attempt_id", attempt_id)
        job = self._require("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        now = self.clock()
        self._transition_batch(
            (
                self._change(
                    "attempts",
                    "attempt_id",
                    attempt_id,
                    AttemptState.RUNNING.value,
                    AttemptState.UNKNOWN.value,
                ),
                self._change(
                    "project_jobs",
                    "project_job_id",
                    str(job["project_job_id"]),
                    ProjectJobState.RUNNING.value,
                    ProjectJobState.UNKNOWN.value,
                ),
                self._change(
                    "runs",
                    "run_id",
                    str(job["run_id"]),
                    RunState.RUNNING.value,
                    RunState.WAITING_RECONCILIATION.value,
                ),
            ),
            actor_id,
            now,
        )

    def begin_reconciliation(self, attempt_id: str, *, actor_id: ActorLike) -> None:
        self._transition(
            "attempts",
            "attempt_id",
            attempt_id,
            AttemptState.UNKNOWN.value,
            AttemptState.NEEDS_RECONCILIATION.value,
            actor_id,
            self.clock(),
        )

    def reconcile_attempt(
        self,
        attempt_id: str,
        outcome: ReconciliationOutcome,
        *,
        actor_id: ActorLike,
        recovered_claim: str | None = None,
    ) -> None:
        attempt = self._require("attempts", "attempt_id", attempt_id)
        job = self._require("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        now = self.clock()
        if outcome is ReconciliationOutcome.STILL_UNKNOWN:
            raise RuntimeTransitionError("UNKNOWN remains blocked; no retry or success is inferred")
        if outcome is ReconciliationOutcome.RECOVERED_FINISHED:
            if not recovered_claim:
                raise RuntimeTransitionError("recovered FINISHED requires a result claim")
            self._transition_batch(
                (
                    self._change(
                        "attempts",
                        "attempt_id",
                        attempt_id,
                        AttemptState.NEEDS_RECONCILIATION.value,
                        AttemptState.FINISHED.value,
                        {
                            "result_claim": recovered_claim,
                            "reconciliation_outcome": outcome.value,
                        },
                    ),
                    self._change(
                        "project_jobs",
                        "project_job_id",
                        str(job["project_job_id"]),
                        ProjectJobState.UNKNOWN.value,
                        ProjectJobState.FINISHED.value,
                    ),
                    self._change(
                        "runs",
                        "run_id",
                        str(job["run_id"]),
                        RunState.WAITING_RECONCILIATION.value,
                        RunState.RUNNING.value,
                    ),
                ),
                actor_id,
                now,
            )
            return
        self._transition_batch(
            (
                self._change(
                    "attempts",
                    "attempt_id",
                    attempt_id,
                    AttemptState.NEEDS_RECONCILIATION.value,
                    AttemptState.RECONCILED_RETRYABLE.value,
                    {"reconciliation_outcome": outcome.value},
                ),
                self._change(
                    "project_jobs",
                    "project_job_id",
                    str(job["project_job_id"]),
                    ProjectJobState.UNKNOWN.value,
                    ProjectJobState.RUNNING.value,
                ),
                self._change(
                    "runs",
                    "run_id",
                    str(job["run_id"]),
                    RunState.WAITING_RECONCILIATION.value,
                    RunState.RUNNING.value,
                ),
            ),
            actor_id,
            now,
        )

    def retry_attempt(
        self, previous_attempt_id: str, new_attempt_id: str, *, actor_id: ActorLike
    ) -> None:
        previous = self._require("attempts", "attempt_id", previous_attempt_id)
        if (
            previous["state"] != AttemptState.RECONCILED_RETRYABLE.value
            or previous["reconciliation_outcome"] != ReconciliationOutcome.SAFE_TO_RETRY.value
        ):
            raise RuntimeTransitionError(
                "UNKNOWN Attempt cannot be retried before safe reconciliation"
            )
        self.create_attempt(new_attempt_id, str(previous["project_job_id"]), actor_id=actor_id)

    def snapshot(self, run_id: str) -> dict[str, object]:
        return self.store.snapshot_run(run_id)

    def settle_run_for_job(self, project_job_id: str, *, actor_id: ActorLike) -> None:
        job = self._require("project_jobs", "project_job_id", project_job_id)
        run = self._require("runs", "run_id", str(job["run_id"]))
        if run["state"] != RunState.RUNNING.value:
            return
        snapshot = self.store.snapshot_run(str(run["run_id"]))
        terminal = {
            ProjectJobState.ACCEPTED.value,
            ProjectJobState.REJECTED.value,
            ProjectJobState.REQUIRE_APPROVAL.value,
            ProjectJobState.PROMOTION_CONFLICT.value,
            ProjectJobState.CANCELLED.value,
        }
        if not snapshot["project_jobs"] or any(
            item["state"] not in terminal for item in snapshot["project_jobs"]
        ):
            return
        now = self.clock()
        workstream = self._require(
            "workstreams", "workstream_id", str(run["workstream_id"])
        )
        changes = [
            self._change(
                "runs",
                "run_id",
                str(run["run_id"]),
                RunState.RUNNING.value,
                RunState.COMPLETED.value,
            )
        ]
        if workstream["state"] == WorkstreamState.ACTIVE.value:
            changes.append(
                self._change(
                    "workstreams",
                    "workstream_id",
                    str(workstream["workstream_id"]),
                    WorkstreamState.ACTIVE.value,
                    WorkstreamState.COMPLETE.value,
                )
            )
        self._transition_batch(tuple(changes), actor_id, now)

    def _transition(
        self,
        table: str,
        id_column: str,
        identifier: str,
        expected: str,
        target: str,
        actor_id: ActorLike,
        now: int,
        updates: dict[str, object] | None = None,
    ) -> None:
        self.store.transition(
            table,
            id_column,
            identifier,
            expected_state=expected,
            target_state=target,
            token=self.token,
            now=now,
            actor_id=actor_id,
            updates=updates,
        )

    def _transition_batch(
        self,
        changes: tuple[dict[str, object], ...],
        actor_id: ActorLike,
        now: int,
    ) -> None:
        self.store.transition_batch(changes, self.token, now=now, actor_id=actor_id)

    @staticmethod
    def _change(
        table: str,
        id_column: str,
        identifier: str,
        expected_state: str,
        target_state: str,
        updates: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "table": table,
            "id_column": id_column,
            "identifier": identifier,
            "expected_state": expected_state,
            "target_state": target_state,
            "updates": updates or {},
        }

    def _require(self, table: str, id_column: str, identifier: str) -> dict[str, object]:
        value = self.store.get(table, id_column, identifier)
        if value is None:
            raise KeyError(f"unknown runtime entity: {table}:{identifier}")
        return value


def _require_subset(requested: tuple[str, ...], allowed: tuple[str, ...], label: str) -> None:
    if not set(requested).issubset(set(allowed)):
        raise RuntimeAuthorizationError(f"requested {label} exceeds the Execution Envelope")


__all__ = ["ExecutionCoordinator"]
