"""Transactional SQLite RunStore and single-coordinator fencing authority."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from artifex.runtime.models import CoordinatorFencedError, ExecutionEnvelope, FenceToken


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

    def put_envelope(self, envelope: ExecutionEnvelope, token: FenceToken, *, now: int) -> None:
        payload = json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """
                INSERT INTO envelopes (envelope_id, version, project_id, approved, payload)
                VALUES (?, ?, ?, 1, ?)
                """,
                (envelope.envelope_id, envelope.version, envelope.project_id, payload),
            )
            self._audit(
                connection,
                "ENVELOPE_APPROVED",
                envelope.actor_id,
                "envelope",
                envelope.envelope_id,
                now,
                {"version": envelope.version},
            )

    def envelope(self, envelope_id: str, version: int) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM envelopes WHERE envelope_id = ? AND version = ?",
                (envelope_id, version),
            ).fetchone()
        return json.loads(str(row["payload"])) if row is not None else None

    def insert(
        self,
        table: str,
        values: Mapping[str, Any],
        token: FenceToken,
        *,
        now: int,
        actor_id: str,
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
        actor_id: str,
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
        actor_id: str,
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
    ) -> None:
        self._validate_actor(str(values.get("actor_id", "")))
        with self._transaction() as connection:
            self._assert_fence(connection, token, now)
            connection.execute(
                """
                INSERT INTO acceptance_decisions (
                    decision_id, project_job_id, outcome, evidence_valid,
                    actor_id, reason, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["decision_id"],
                    values["project_job_id"],
                    values["outcome"],
                    int(bool(values["evidence_valid"])),
                    values["actor_id"],
                    values["reason"],
                    values["decided_at"],
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
                str(values["actor_id"]),
                "project_jobs",
                str(values["project_job_id"]),
                now,
                dict(values),
            )
            self._audit(
                connection,
                "PROJECT_JOBS_TRANSITION",
                str(values["actor_id"]),
                "project_jobs",
                str(values["project_job_id"]),
                now,
                {"from": "FINISHED", "to": target_state},
            )

    def set_workspace_state(
        self,
        workspace_id: str,
        expected_state: str,
        target_state: str,
        token: FenceToken,
        *,
        now: int,
        actor_id: str,
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
        return dict(row) if row is not None else None

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
        return {
            "workstream": dict(workstream) if workstream is not None else None,
            "run": dict(run),
            "project_jobs": [dict(row) for row in jobs],
            "attempts": [dict(row) for row in attempts],
            "acceptance_decisions": [dict(row) for row in decisions],
        }

    def audit(self) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM runtime_audit ORDER BY sequence").fetchall()
        return tuple({**dict(row), "payload": json.loads(str(row["payload"]))} for row in rows)

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
    def _validate_actor(actor_id: str) -> None:
        if not actor_id.strip():
            raise ValueError("explicit actor identity is required for runtime mutation")

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        event_type: str,
        actor_id: str,
        entity_type: str,
        entity_id: str,
        occurred_at: int,
        payload: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """INSERT INTO runtime_audit
               (event_type, actor_id, entity_type, entity_id, occurred_at, payload)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event_type,
                actor_id,
                entity_type,
                entity_id,
                occurred_at,
                json.dumps(payload, sort_keys=True, default=str),
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
                    actor_id TEXT NOT NULL, reason TEXT NOT NULL, decided_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL, payload TEXT NOT NULL
                );
                """
            )


__all__ = ["SQLiteRunStore"]
