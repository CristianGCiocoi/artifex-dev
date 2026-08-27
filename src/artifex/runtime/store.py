"""Transactional SQLite RunStore and single-coordinator fencing authority."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from artifex.policy import scrub_secrets
from artifex.runtime.models import (
    ActorLike,
    CoordinatorFencedError,
    DispatchAuthorization,
    EvidenceRecord,
    ExecutionEnvelope,
    FenceToken,
    RuntimeAuthorizationError,
    actor_principal,
)


class SQLiteRunStore:
    """Standalone runtime authority. Project semantic content is intentionally absent."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def acquire_coordinator(self, holder_id: str, *, now: int, ttl_seconds: int = 30) -> FenceToken:
        if not holder_id.strip() or ttl_seconds < 1:
            raise ValueError("coordinator holder and positive TTL are required")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT holder_id, generation, expires_at FROM coordinator_lease WHERE id = 1"
            ).fetchone()
            if row is None:
                generation = 1
            elif int(row["expires_at"]) > now and str(row["holder_id"]) != holder_id:
                raise CoordinatorFencedError(
                    f"standalone coordinator is held by {row['holder_id']}"
                )
            else:
                # Every service incarnation receives a new generation, including a
                # restart under the same stable holder identity. The prior process is
                # thereby fenced immediately instead of sharing a live write token.
                generation = int(row["generation"]) + 1
            expires_at = now + ttl_seconds
            connection.execute(
                """
                INSERT INTO coordinator_lease (id, holder_id, generation, expires_at)
                VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET holder_id=excluded.holder_id,
                    generation=excluded.generation, expires_at=excluded.expires_at
                """,
                (holder_id, generation, expires_at),
            )
            self._audit(
                connection,
                "COORDINATOR_ACQUIRED",
                holder_id,
                "coordinator",
                holder_id,
                now,
                {
                    "generation": generation,
                    "expires_at": expires_at,
                },
            )
        return FenceToken(holder_id, generation, expires_at)

    def renew_coordinator(
        self, token: FenceToken, *, now: int, ttl_seconds: int = 30
    ) -> FenceToken:
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            expires_at = now + ttl_seconds
            connection.execute(
                "UPDATE coordinator_lease SET expires_at = ? WHERE id = 1", (expires_at,)
            )
        return FenceToken(token.holder_id, token.generation, expires_at)

    def put_envelope(
        self,
        envelope: ExecutionEnvelope,
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike | None = None,
        correlation_id: str | None = None,
    ) -> None:
        if not envelope.approved:
            raise RuntimeAuthorizationError("only approved Execution Envelopes may be persisted")
        payload = json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))
        principal = actor_principal(actor if actor is not None else envelope.actor_id)
        principal.require("envelope:approve", envelope.project_id, now=now)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            existing = connection.execute(
                "SELECT fingerprint FROM envelopes WHERE envelope_id = ? AND version = ?",
                (envelope.envelope_id, envelope.version),
            ).fetchone()
            if existing is not None:
                if str(existing["fingerprint"]) != envelope.fingerprint:
                    raise RuntimeAuthorizationError(
                        "approved Execution Envelope version is immutable"
                    )
                return
            connection.execute(
                """
                INSERT INTO envelopes (
                    envelope_id, version, project_id, approved, fingerprint, approved_by, payload
                ) VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    envelope.envelope_id,
                    envelope.version,
                    envelope.project_id,
                    envelope.fingerprint,
                    principal.actor_id,
                    payload,
                ),
            )
            self._audit(
                connection,
                "ENVELOPE_APPROVED",
                principal,
                "envelope",
                envelope.envelope_id,
                now,
                {
                    "version": envelope.version,
                    "fingerprint": envelope.fingerprint,
                    "project_id": envelope.project_id,
                    "supervision_level": envelope.supervision_level.value,
                },
                correlation_id=correlation_id,
            )

    def envelope(self, envelope_id: str, version: int) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM envelopes WHERE envelope_id = ? AND version = ?",
                (envelope_id, version),
            ).fetchone()
        return json.loads(str(row["payload"])) if row is not None else None

    def envelope_for_attempt(self, attempt_id: str) -> Mapping[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT e.payload FROM envelopes e
                   JOIN runs r ON r.envelope_id = e.envelope_id
                       AND r.envelope_version = e.version
                   JOIN project_jobs j ON j.run_id = r.run_id
                   JOIN attempts a ON a.project_job_id = j.project_job_id
                   WHERE a.attempt_id = ?""",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown Attempt or Execution Envelope: {attempt_id}")
        value = json.loads(str(row["payload"]))
        if not isinstance(value, Mapping):
            raise RuntimeAuthorizationError("stored Execution Envelope payload is invalid")
        return value

    def record_dispatch_authorization(
        self,
        authorization: DispatchAuthorization,
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        principal = actor_principal(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """INSERT INTO dispatch_authorizations (
                    authorization_id, attempt_id, provider_id, provider_role,
                    requested_capabilities, filesystem_permissions,
                    network_permissions, tool_permissions, credential_reference_ids,
                    envelope_fingerprint, actor_id, authorized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    authorization.authorization_id,
                    authorization.attempt_id,
                    authorization.provider_id,
                    authorization.provider_role,
                    json.dumps(authorization.requested_capabilities),
                    json.dumps(authorization.filesystem_permissions),
                    json.dumps(authorization.network_permissions),
                    json.dumps(authorization.tool_permissions),
                    json.dumps(authorization.credential_reference_ids),
                    authorization.envelope_fingerprint,
                    authorization.actor_id,
                    authorization.authorized_at,
                ),
            )
            self._audit(
                connection,
                "ATTEMPT_DISPATCH_AUTHORIZED",
                principal,
                "attempts",
                authorization.attempt_id,
                now,
                authorization.to_dict(),
                correlation_id=correlation_id,
            )

    def dispatch_authorization(self, attempt_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM dispatch_authorizations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["requested_capabilities"] = json.loads(str(value["requested_capabilities"]))
        value["filesystem_permissions"] = json.loads(str(value["filesystem_permissions"]))
        value["network_permissions"] = json.loads(str(value["network_permissions"]))
        value["tool_permissions"] = json.loads(str(value["tool_permissions"]))
        value["credential_reference_ids"] = json.loads(str(value["credential_reference_ids"]))
        return value

    def record_evidence(
        self,
        evidence: EvidenceRecord,
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        principal = actor_principal(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """INSERT INTO evidence_records (
                    evidence_id, project_job_id, attempt_id, gate, passed,
                    envelope_fingerprint, baseline_revision, artifact_ref,
                    artifact_digest, actor_id, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence.evidence_id,
                    evidence.project_job_id,
                    evidence.attempt_id,
                    evidence.gate,
                    int(evidence.passed),
                    evidence.envelope_fingerprint,
                    evidence.baseline_revision,
                    evidence.artifact_ref,
                    evidence.artifact_digest,
                    evidence.actor_id,
                    evidence.recorded_at,
                ),
            )
            self._audit(
                connection,
                "EVIDENCE_RECORDED",
                principal,
                "evidence",
                evidence.evidence_id,
                now,
                evidence.to_dict(),
                correlation_id=correlation_id,
            )

    def evidence(self, evidence_ids: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
        if not evidence_ids:
            return ()
        placeholders = ",".join("?" for _ in evidence_ids)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM evidence_records WHERE evidence_id IN ({placeholders})",
                evidence_ids,
            ).fetchall()
        by_id = {str(row["evidence_id"]): dict(row) for row in rows}
        return tuple(by_id[value] for value in evidence_ids if value in by_id)

    def insert(
        self,
        table: str,
        values: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        actor_id: ActorLike,
        event_type: str,
    ) -> None:
        self._validate_actor(actor_id)
        allowed = {"workstreams", "runs", "project_jobs", "attempts", "workspaces"}
        if table not in allowed:
            raise ValueError(f"unsupported runtime table: {table}")
        columns = tuple(values)
        placeholders = ", ".join("?" for _ in columns)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )
            identifier = str(values[columns[0]])
            self._audit(connection, event_type, actor_id, table, identifier, now, dict(values))

    def transition(
        self,
        table: str,
        id_column: str,
        identifier: str,
        *,
        expected_state: str,
        target_state: str,
        token: FenceToken,
        now: int,
        actor_id: ActorLike,
        updates: Mapping[str, Any] | None = None,
    ) -> None:
        self.transition_batch(
            (
                {
                    "table": table,
                    "id_column": id_column,
                    "identifier": identifier,
                    "expected_state": expected_state,
                    "target_state": target_state,
                    "updates": dict(updates or {}),
                },
            ),
            token,
            now=now,
            actor_id=actor_id,
        )

    def transition_batch(
        self,
        transitions: tuple[Mapping[str, Any], ...],
        token: FenceToken,
        *,
        now: int,
        actor_id: ActorLike,
    ) -> None:
        """Commit related runtime state changes under one fence and transaction."""

        self._validate_actor(actor_id)
        if not transitions:
            raise ValueError("runtime transition batch must not be empty")
        allowed = {
            ("workstreams", "workstream_id"),
            ("runs", "run_id"),
            ("project_jobs", "project_job_id"),
            ("attempts", "attempt_id"),
        }
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            for item in transitions:
                table = str(item["table"])
                id_column = str(item["id_column"])
                identifier = str(item["identifier"])
                expected_state = str(item["expected_state"])
                target_state = str(item["target_state"])
                if (table, id_column) not in allowed:
                    raise ValueError("unsupported runtime transition target")
                extra = dict(item.get("updates", {}))
                assignments = [
                    "state = ?",
                    "updated_at = ?",
                    *[f"{key} = ?" for key in extra],
                ]
                parameters = [target_state, now, *extra.values(), identifier, expected_state]
                cursor = connection.execute(
                    f"UPDATE {table} SET {', '.join(assignments)} "
                    f"WHERE {id_column} = ? AND state = ?",
                    parameters,
                )
                if cursor.rowcount != 1:
                    raise CoordinatorFencedError(
                        f"transition lost race or state mismatch for {table}:{identifier}"
                    )
                self._audit(
                    connection,
                    f"{table.upper()}_TRANSITION",
                    actor_id,
                    table,
                    identifier,
                    now,
                    {"from": expected_state, "to": target_state, **extra},
                )

    def record_acceptance(
        self,
        values: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        target_state: str,
        actor: ActorLike | None = None,
        correlation_id: str | None = None,
    ) -> None:
        audit_actor: ActorLike = actor if actor is not None else str(values.get("actor_id", ""))
        self._validate_actor(audit_actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """
                INSERT INTO acceptance_decisions (
                    decision_id, project_job_id, outcome, evidence_valid,
                    actor_id, reason, decided_at, evidence_ids, envelope_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["decision_id"],
                    values["project_job_id"],
                    values["outcome"],
                    int(bool(values["evidence_valid"])),
                    values["actor_id"],
                    values["reason"],
                    values["decided_at"],
                    json.dumps(values.get("evidence_ids", ())),
                    values.get("envelope_fingerprint"),
                ),
            )
            cursor = connection.execute(
                """UPDATE project_jobs SET state = ?, updated_at = ?
                   WHERE project_job_id = ? AND state = ?""",
                (target_state, now, values["project_job_id"], "FINISHED"),
            )
            if cursor.rowcount != 1:
                raise CoordinatorFencedError(
                    "acceptance lost race or ProjectJob is no longer FINISHED"
                )
            self._audit(
                connection,
                "ACCEPTANCE_DECIDED",
                audit_actor,
                "project_jobs",
                str(values["project_job_id"]),
                now,
                dict(values),
                correlation_id=correlation_id,
            )
            self._audit(
                connection,
                "PROJECT_JOBS_TRANSITION",
                audit_actor,
                "project_jobs",
                str(values["project_job_id"]),
                now,
                {"from": "FINISHED", "to": target_state},
                correlation_id=correlation_id,
            )

    def set_workspace_state(
        self,
        workspace_id: str,
        expected_state: str,
        target_state: str,
        token: FenceToken,
        *,
        now: int,
        actor_id: ActorLike,
    ) -> None:
        self._validate_actor(actor_id)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            cursor = connection.execute(
                "UPDATE workspaces SET state = ? WHERE workspace_id = ? AND state = ?",
                (target_state, workspace_id, expected_state),
            )
            if cursor.rowcount != 1:
                raise CoordinatorFencedError("workspace state changed or does not exist")
            self._audit(
                connection,
                "WORKSPACE_TRANSITION",
                actor_id,
                "workspaces",
                workspace_id,
                now,
                {"from": expected_state, "to": target_state},
            )

    def get(self, table: str, id_column: str, identifier: str) -> dict[str, Any] | None:
        allowed = {
            ("workstreams", "workstream_id"),
            ("runs", "run_id"),
            ("project_jobs", "project_job_id"),
            ("attempts", "attempt_id"),
            ("workspaces", "workspace_id"),
        }
        if (table, id_column) not in allowed:
            raise ValueError("unsupported runtime lookup")
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE {id_column} = ?",
                (identifier,),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["evidence_ids"] = json.loads(str(value.get("evidence_ids", "[]")))
        return value

    def propose_envelope(
        self,
        envelope: ExecutionEnvelope,
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        if envelope.approved:
            raise RuntimeAuthorizationError("Envelope proposal must not claim approval")
        principal = actor_principal(actor)
        principal.require("envelope:propose", envelope.project_id, now=now)
        payload = json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """INSERT INTO envelope_proposals
                   (envelope_id, version, project_id, fingerprint, proposed_by, payload,
                    proposed_at, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'PROPOSED')""",
                (
                    envelope.envelope_id,
                    envelope.version,
                    envelope.project_id,
                    envelope.fingerprint,
                    principal.actor_id,
                    payload,
                    now,
                ),
            )
            self._audit(
                connection,
                "ENVELOPE_PROPOSED",
                principal,
                "envelope",
                envelope.envelope_id,
                now,
                {"version": envelope.version, "fingerprint": envelope.fingerprint},
                correlation_id=correlation_id,
            )

    def envelope_proposal(self, envelope_id: str, version: int) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT * FROM envelope_proposals
                   WHERE envelope_id = ? AND version = ?""",
                (envelope_id, version),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["payload"] = json.loads(str(value["payload"]))
        return value

    def mark_envelope_proposal_approved(
        self,
        envelope_id: str,
        version: int,
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
    ) -> None:
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            cursor = connection.execute(
                """UPDATE envelope_proposals SET state = 'APPROVED'
                   WHERE envelope_id = ? AND version = ? AND state = 'PROPOSED'""",
                (envelope_id, version),
            )
            if cursor.rowcount != 1:
                raise CoordinatorFencedError("Envelope proposal is not pending approval")
            self._audit(
                connection,
                "ENVELOPE_PROPOSAL_APPROVED",
                actor,
                "envelope",
                envelope_id,
                now,
                {"version": version},
            )

    def create_interaction_session(
        self,
        values: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
    ) -> None:
        self._validate_actor(actor)
        columns = tuple(values)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                f"INSERT INTO interaction_sessions ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)})",
                tuple(values[column] for column in columns),
            )
            self._audit(
                connection,
                "INTERACTION_SESSION_OPENED",
                actor,
                "interaction_session",
                str(values["session_id"]),
                now,
                {
                    "project_id": values["project_id"],
                    "opened_revision": values["opened_revision"],
                },
            )

    def interaction_session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM interaction_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["delegated_actions"] = json.loads(str(value["delegated_actions"]))
        return value

    def interaction_sessions(self, project_id: str) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM interaction_sessions WHERE project_id = ? ORDER BY created_at",
                (project_id,),
            ).fetchall()
        return tuple(
            {**dict(row), "delegated_actions": json.loads(str(row["delegated_actions"]))}
            for row in rows
        )

    def update_interaction_session(
        self,
        session_id: str,
        *,
        expected_state: str,
        state: str,
        last_seen_revision: int,
        token: FenceToken,
        now: int,
        actor: ActorLike,
        event_type: str,
    ) -> None:
        self._validate_actor(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            cursor = connection.execute(
                """UPDATE interaction_sessions
                   SET state = ?, last_seen_revision = ?, updated_at = ?
                   WHERE session_id = ? AND state = ?""",
                (state, last_seen_revision, now, session_id, expected_state),
            )
            if cursor.rowcount != 1:
                raise CoordinatorFencedError(
                    f"interaction session state mismatch: {session_id}:{expected_state}"
                )
            self._audit(
                connection,
                event_type,
                actor,
                "interaction_session",
                session_id,
                now,
                {"from": expected_state, "to": state, "last_seen_revision": last_seen_revision},
            )

    def create_decision_request(
        self,
        values: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
    ) -> None:
        self._validate_actor(actor)
        columns = tuple(values)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            blocked_states = json.loads(str(values["blocked_from_states"]))
            if not isinstance(blocked_states, dict) or not blocked_states:
                raise ValueError("DecisionRequest requires affected Workstream states")
            for workstream_id, expected_state in blocked_states.items():
                cursor = connection.execute(
                    """UPDATE workstreams SET state = 'BLOCKED', updated_at = ?
                       WHERE workstream_id = ? AND project_id = ? AND state = ?""",
                    (now, workstream_id, values["project_id"], expected_state),
                )
                if cursor.rowcount != 1:
                    raise CoordinatorFencedError(
                        f"DecisionRequest Workstream lost race: {workstream_id}"
                    )
                self._audit(
                    connection,
                    "WORKSTREAM_BLOCKED_BY_DECISION",
                    actor,
                    "workstream",
                    str(workstream_id),
                    now,
                    {
                        "decision_request_id": values["decision_request_id"],
                        "from": expected_state,
                        "to": "BLOCKED",
                    },
                )
            connection.execute(
                f"INSERT INTO decision_requests ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)})",
                tuple(values[column] for column in columns),
            )
            self._audit(
                connection,
                "DECISION_REQUEST_CREATED",
                actor,
                "decision_request",
                str(values["decision_request_id"]),
                now,
                {
                    "materiality": values["materiality"],
                    "affected_workstreams": json.loads(str(values["affected_workstreams"])),
                },
            )

    def decision_request(self, decision_request_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM decision_requests WHERE decision_request_id = ?",
                (decision_request_id,),
            ).fetchone()
        return _decision_row(row)

    def decision_requests(self, project_id: str) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM decision_requests WHERE project_id = ? ORDER BY created_at",
                (project_id,),
            ).fetchall()
        return tuple(value for row in rows if (value := _decision_row(row)) is not None)

    def resolve_decision_request(
        self,
        decision_request_id: str,
        *,
        outcome: str,
        resolution: str,
        restore_workstreams: bool,
        token: FenceToken,
        now: int,
        actor: ActorLike,
    ) -> None:
        self._validate_actor(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            row = connection.execute(
                "SELECT * FROM decision_requests WHERE decision_request_id = ? AND state = 'OPEN'",
                (decision_request_id,),
            ).fetchone()
            if row is None:
                raise CoordinatorFencedError(f"decision request is not open: {decision_request_id}")
            if restore_workstreams:
                blocked_states = json.loads(str(row["blocked_from_states"]))
                for workstream_id, target_state in blocked_states.items():
                    cursor = connection.execute(
                        """UPDATE workstreams SET state = ?, updated_at = ?
                           WHERE workstream_id = ? AND state = 'BLOCKED'""",
                        (target_state, now, workstream_id),
                    )
                    if cursor.rowcount != 1:
                        raise CoordinatorFencedError(
                            f"blocked Workstream lost race: {workstream_id}"
                        )
                    self._audit(
                        connection,
                        "WORKSTREAM_RESUMED_AFTER_DECISION",
                        actor,
                        "workstream",
                        str(workstream_id),
                        now,
                        {
                            "decision_request_id": decision_request_id,
                            "from": "BLOCKED",
                            "to": target_state,
                        },
                    )
            cursor = connection.execute(
                """UPDATE decision_requests SET state = ?, outcome = ?, resolution = ?,
                   resolved_by = ?, resolved_at = ?
                   WHERE decision_request_id = ? AND state = 'OPEN'""",
                (
                    "RESOLVED",
                    outcome,
                    resolution,
                    actor_principal(actor).actor_id,
                    now,
                    decision_request_id,
                ),
            )
            if cursor.rowcount != 1:
                raise CoordinatorFencedError(f"decision request lost race: {decision_request_id}")
            self._audit(
                connection,
                "DECISION_REQUEST_RESOLVED",
                actor,
                "decision_request",
                decision_request_id,
                now,
                {"outcome": outcome, "resolution": resolution},
            )

    def set_operational_control(
        self,
        *,
        scope_type: str,
        scope_id: str,
        project_id: str | None,
        state: str,
        reason: str,
        generation: int,
        token: FenceToken,
        now: int,
        actor: ActorLike,
    ) -> None:
        self._validate_actor(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """INSERT INTO operational_controls
                   (scope_type, scope_id, project_id, state, reason, generation, actor_id,
                    updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scope_type, scope_id) DO UPDATE SET
                   project_id = excluded.project_id, state = excluded.state,
                   reason = excluded.reason, generation = excluded.generation,
                   actor_id = excluded.actor_id, updated_at = excluded.updated_at""",
                (
                    scope_type,
                    scope_id,
                    project_id,
                    state,
                    reason,
                    generation,
                    actor_principal(actor).actor_id,
                    now,
                ),
            )
            self._audit(
                connection,
                "OPERATIONAL_CONTROL_CHANGED",
                actor,
                "operational_control",
                f"{scope_type}:{scope_id}",
                now,
                {"state": state, "reason": reason, "generation": generation},
            )

    def operational_control(self, scope_type: str, scope_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM operational_controls WHERE scope_type = ? AND scope_id = ?",
                (scope_type, scope_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def operational_controls(self) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operational_controls ORDER BY scope_type, scope_id"
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def snapshot_run(self, run_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            run = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if run is None:
                raise KeyError(f"unknown Run: {run_id}")
            workstream = connection.execute(
                "SELECT * FROM workstreams WHERE workstream_id = ?", (run["workstream_id"],)
            ).fetchone()
            jobs = connection.execute(
                "SELECT * FROM project_jobs WHERE run_id = ? ORDER BY project_job_id", (run_id,)
            ).fetchall()
            attempts = connection.execute(
                """SELECT a.* FROM attempts a JOIN project_jobs j
                   ON a.project_job_id = j.project_job_id WHERE j.run_id = ?
                   ORDER BY a.attempt_id""",
                (run_id,),
            ).fetchall()
            decisions = connection.execute(
                """SELECT d.* FROM acceptance_decisions d JOIN project_jobs j
                   ON d.project_job_id = j.project_job_id WHERE j.run_id = ?
                   ORDER BY d.decided_at""",
                (run_id,),
            ).fetchall()
            workspaces = connection.execute(
                """SELECT w.* FROM workspaces w JOIN attempts a
                   ON w.attempt_id = a.attempt_id JOIN project_jobs j
                   ON a.project_job_id = j.project_job_id WHERE j.run_id = ?
                   ORDER BY w.workspace_id""",
                (run_id,),
            ).fetchall()
            dispatches = connection.execute(
                """SELECT d.* FROM dispatch_authorizations d JOIN attempts a
                   ON d.attempt_id = a.attempt_id JOIN project_jobs j
                   ON a.project_job_id = j.project_job_id WHERE j.run_id = ?
                   ORDER BY d.authorized_at""",
                (run_id,),
            ).fetchall()
            evidence = connection.execute(
                """SELECT e.* FROM evidence_records e JOIN project_jobs j
                   ON e.project_job_id = j.project_job_id WHERE j.run_id = ?
                   ORDER BY e.recorded_at""",
                (run_id,),
            ).fetchall()
        return {
            "workstream": dict(workstream) if workstream is not None else None,
            "run": dict(run),
            "project_jobs": [dict(row) for row in jobs],
            "attempts": [dict(row) for row in attempts],
            "acceptance_decisions": [dict(row) for row in decisions],
            "workspaces": [dict(row) for row in workspaces],
            "dispatch_authorizations": [
                {
                    **dict(row),
                    "requested_capabilities": json.loads(str(row["requested_capabilities"])),
                    "filesystem_permissions": json.loads(str(row["filesystem_permissions"])),
                    "network_permissions": json.loads(str(row["network_permissions"])),
                    "tool_permissions": json.loads(str(row["tool_permissions"])),
                    "credential_reference_ids": json.loads(str(row["credential_reference_ids"])),
                }
                for row in dispatches
            ],
            "evidence_records": [dict(row) for row in evidence],
        }

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM runtime_audit ORDER BY sequence").fetchall()
        return tuple({**dict(row), "payload": json.loads(str(row["payload"]))} for row in rows)

    def record_event(
        self,
        event_type: str,
        entity_type: str,
        entity_id: str,
        payload: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        actor: ActorLike,
        correlation_id: str | None = None,
    ) -> None:
        self._validate_actor(actor)
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            self._audit(
                connection,
                event_type,
                actor,
                entity_type,
                entity_id,
                now,
                payload,
                correlation_id=correlation_id,
            )

    def acceptance(self, project_job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT * FROM acceptance_decisions WHERE project_job_id = ?
                   ORDER BY decided_at DESC LIMIT 1""",
                (project_job_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def _assert_fence(self, connection: sqlite3.Connection, token: FenceToken, now: int) -> None:
        row = connection.execute(
            "SELECT holder_id, generation, expires_at FROM coordinator_lease WHERE id = 1"
        ).fetchone()
        if (
            row is None
            or row["holder_id"] != token.holder_id
            or int(row["generation"]) != token.generation
            or int(row["expires_at"]) <= now
        ):
            raise CoordinatorFencedError("coordinator token is stale, foreign, or expired")

    @staticmethod
    def _validate_actor(actor_id: ActorLike) -> None:
        principal = actor_principal(actor_id)
        if not principal.authenticated or principal.actor_id.casefold() == "anonymous":
            raise RuntimeAuthorizationError(
                "authenticated explicit actor identity is required for runtime mutation"
            )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        event_type: str,
        actor_id: ActorLike,
        entity_type: str,
        entity_id: str,
        occurred_at: int,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> None:
        principal = actor_principal(actor_id)
        safe_payload = _secret_safe({**dict(payload), "actor": principal.to_audit_dict()})
        connection.execute(
            """INSERT INTO runtime_audit
               (event_type, actor_id, actor_kind, authentication_method, delegation_id,
                correlation_id, entity_type, entity_id, occurred_at, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_type,
                principal.actor_id,
                principal.actor_type.value,
                principal.authentication_method,
                principal.delegation.grant_id if principal.delegation is not None else None,
                correlation_id,
                entity_type,
                entity_id,
                occurred_at,
                json.dumps(safe_payload, sort_keys=True, default=str),
            ),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS coordinator_lease (
                    id INTEGER PRIMARY KEY CHECK (id = 1), holder_id TEXT NOT NULL,
                    generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS envelopes (
                    envelope_id TEXT NOT NULL, version INTEGER NOT NULL,
                    project_id TEXT NOT NULL, approved INTEGER NOT NULL CHECK (approved = 1),
                    fingerprint TEXT NOT NULL, approved_by TEXT NOT NULL,
                    payload TEXT NOT NULL, PRIMARY KEY (envelope_id, version)
                );
                CREATE TABLE IF NOT EXISTS workstreams (
                    workstream_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                    state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY, workstream_id TEXT NOT NULL REFERENCES workstreams,
                    project_id TEXT NOT NULL, envelope_id TEXT NOT NULL,
                    envelope_version INTEGER NOT NULL,
                    state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    FOREIGN KEY (envelope_id, envelope_version)
                        REFERENCES envelopes(envelope_id, version)
                );
                CREATE TABLE IF NOT EXISTS project_jobs (
                    project_job_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs,
                    state TEXT NOT NULL, purpose TEXT NOT NULL,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    project_job_id TEXT NOT NULL REFERENCES project_jobs,
                    ordinal INTEGER NOT NULL, state TEXT NOT NULL, result_claim TEXT,
                    reconciliation_outcome TEXT, created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(project_job_id, ordinal)
                );
                CREATE TABLE IF NOT EXISTS workspaces (
                    workspace_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts,
                    project_root TEXT NOT NULL, workspace_root TEXT NOT NULL,
                    baseline_revision INTEGER NOT NULL, state TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS acceptance_decisions (
                    decision_id TEXT PRIMARY KEY,
                    project_job_id TEXT NOT NULL REFERENCES project_jobs,
                    outcome TEXT NOT NULL, evidence_valid INTEGER NOT NULL,
                    actor_id TEXT NOT NULL, reason TEXT NOT NULL, decided_at INTEGER NOT NULL,
                    evidence_ids TEXT NOT NULL DEFAULT '[]', envelope_fingerprint TEXT
                );
                CREATE TABLE IF NOT EXISTS dispatch_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts,
                    provider_id TEXT NOT NULL, provider_role TEXT NOT NULL,
                    requested_capabilities TEXT NOT NULL,
                    filesystem_permissions TEXT NOT NULL,
                    network_permissions TEXT NOT NULL,
                    tool_permissions TEXT NOT NULL,
                    credential_reference_ids TEXT NOT NULL,
                    envelope_fingerprint TEXT NOT NULL, actor_id TEXT NOT NULL,
                    authorized_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    project_job_id TEXT NOT NULL REFERENCES project_jobs,
                    attempt_id TEXT NOT NULL REFERENCES attempts,
                    gate TEXT NOT NULL, passed INTEGER NOT NULL,
                    envelope_fingerprint TEXT NOT NULL, baseline_revision INTEGER NOT NULL,
                    artifact_ref TEXT NOT NULL, artifact_digest TEXT NOT NULL,
                    actor_id TEXT NOT NULL, recorded_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL, actor_kind TEXT NOT NULL DEFAULT 'ARTIFEX_SERVICE',
                    authentication_method TEXT NOT NULL DEFAULT 'legacy-in-process',
                    delegation_id TEXT, correlation_id TEXT,
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS envelope_proposals (
                    envelope_id TEXT NOT NULL, version INTEGER NOT NULL,
                    project_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    proposed_by TEXT NOT NULL, payload TEXT NOT NULL,
                    proposed_at INTEGER NOT NULL, state TEXT NOT NULL,
                    PRIMARY KEY (envelope_id, version)
                );
                CREATE TABLE IF NOT EXISTS interaction_sessions (
                    session_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                    workstream_id TEXT, run_id TEXT, actor_id TEXT NOT NULL,
                    actor_type TEXT NOT NULL, delegation_id TEXT,
                    delegated_actions TEXT NOT NULL, opened_revision INTEGER NOT NULL,
                    last_seen_revision INTEGER NOT NULL, state TEXT NOT NULL,
                    reconnect_token_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decision_requests (
                    decision_request_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                    run_id TEXT, requested_by TEXT NOT NULL, materiality TEXT NOT NULL,
                    question TEXT NOT NULL, affected_workstreams TEXT NOT NULL,
                    blocked_from_states TEXT NOT NULL, state TEXT NOT NULL,
                    outcome TEXT, resolution TEXT, resolved_by TEXT,
                    created_at INTEGER NOT NULL, resolved_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS operational_controls (
                    scope_type TEXT NOT NULL, scope_id TEXT NOT NULL, project_id TEXT,
                    state TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL,
                    actor_id TEXT NOT NULL, updated_at INTEGER NOT NULL,
                    PRIMARY KEY (scope_type, scope_id)
                );
                """
            )
            _ensure_column(connection, "envelopes", "fingerprint", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(connection, "envelopes", "approved_by", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(
                connection, "acceptance_decisions", "evidence_ids", "TEXT NOT NULL DEFAULT '[]'"
            )
            _ensure_column(connection, "acceptance_decisions", "envelope_fingerprint", "TEXT")
            _ensure_column(
                connection,
                "runtime_audit",
                "actor_kind",
                "TEXT NOT NULL DEFAULT 'ARTIFEX_SERVICE'",
            )
            _ensure_column(
                connection,
                "runtime_audit",
                "authentication_method",
                "TEXT NOT NULL DEFAULT 'legacy-in-process'",
            )
            _ensure_column(connection, "runtime_audit", "delegation_id", "TEXT")
            _ensure_column(connection, "runtime_audit", "correlation_id", "TEXT")
            for row in connection.execute(
                "SELECT envelope_id, version, payload, fingerprint, approved_by FROM envelopes"
            ).fetchall():
                payload = json.loads(str(row["payload"]))
                fingerprint = str(row["fingerprint"])
                if not fingerprint:
                    payload = _upgrade_envelope_payload(payload)
                    fingerprint = str(payload["fingerprint"])
                approved_by = str(row["approved_by"]) or str(payload.get("actor_id", "legacy"))
                connection.execute(
                    "UPDATE envelopes SET fingerprint = ?, approved_by = ?, payload = ? "
                    "WHERE envelope_id = ? AND version = ?",
                    (
                        fingerprint,
                        approved_by,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        row["envelope_id"],
                        row["version"],
                    ),
                )


_SENSITIVE_KEYS = ("secret", "password", "token", "api_key", "credential_value")


def _ensure_column(
    connection: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    columns = {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _upgrade_envelope_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    defaults: Mapping[str, Any] = {
        "supervision_level": "L2",
        "materiality": "TACTICAL",
        "allowed_workstreams": [],
        "allowed_providers": [],
        "allowed_provider_roles": [],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": [],
        "tool_permissions": [],
        "data_classification": "INTERNAL",
        "credential_references": [],
        "resource_budget": {},
        "deadline_at": None,
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME"],
        "require_durable_evidence": False,
        "baseline_fingerprint": None,
        "baseline_commit": None,
    }
    for key, default in defaults.items():
        payload.setdefault(key, default)
    authority = {key: item for key, item in payload.items() if key != "fingerprint"}
    payload["fingerprint"] = hashlib.sha256(
        json.dumps(authority, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload


def _decision_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    value = dict(row)
    value["affected_workstreams"] = json.loads(str(value["affected_workstreams"]))
    value["blocked_from_states"] = json.loads(str(value["blocked_from_states"]))
    return value


def _secret_safe(value: Any, *, key: str = "") -> Any:
    if any(marker in key.casefold() for marker in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _secret_safe(item, key=str(item_key)) for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_secret_safe(item) for item in value]
    return value


__all__ = ["SQLiteRunStore"]
