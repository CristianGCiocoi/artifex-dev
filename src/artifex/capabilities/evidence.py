"""Local, secret-free evidence for live provider role certification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from artifex.capabilities.models import ProviderRole

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SCHEMA_VERSION = "1.0"


def default_capability_evidence_path() -> Path:
    """Return a deterministic machine-local path outside Project Git."""

    configured = os.environ.get("ARTIFEX_LOCAL_STATE_ROOT")
    if configured:
        root = Path(configured).expanduser()
    elif os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "ARTIFEX" / "state"
    elif os.environ.get("XDG_STATE_HOME"):
        root = Path(os.environ["XDG_STATE_HOME"]) / "artifex"
    else:
        root = Path.home() / ".local" / "state" / "artifex"
    return root.resolve() / "capability-evidence.sqlite3"


@dataclass(frozen=True, slots=True)
class CapabilityReceipt:
    receipt_id: str
    provider_id: str
    role: ProviderRole
    project_id: str
    project_job_id: str
    observed_at: str
    input_sha256: str
    output_sha256: str
    baseline_sha256: str
    acceptance_decision_id: str | None = None
    promotion_revision: int | None = None

    @classmethod
    def issue(
        cls,
        *,
        provider_id: str,
        role: ProviderRole,
        project_id: str,
        project_job_id: str,
        input_sha256: str,
        output_sha256: str,
        baseline_sha256: str,
        acceptance_decision_id: str | None = None,
        promotion_revision: int | None = None,
        observed_at: str | None = None,
    ) -> CapabilityReceipt:
        timestamp = observed_at or datetime.now(UTC).isoformat()
        unsigned = {
            "schema_version": _SCHEMA_VERSION,
            "provider_id": provider_id,
            "role": role.value,
            "project_id": project_id,
            "project_job_id": project_job_id,
            "observed_at": timestamp,
            "input_sha256": input_sha256,
            "output_sha256": output_sha256,
            "baseline_sha256": baseline_sha256,
            "acceptance_decision_id": acceptance_decision_id,
            "promotion_revision": promotion_revision,
        }
        receipt_id = _sha256_json(unsigned)
        receipt = cls(
            receipt_id=receipt_id,
            provider_id=provider_id,
            role=role,
            project_id=project_id,
            project_job_id=project_job_id,
            observed_at=timestamp,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            baseline_sha256=baseline_sha256,
            acceptance_decision_id=acceptance_decision_id,
            promotion_revision=promotion_revision,
        )
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.provider_id,
                self.project_id,
                self.project_job_id,
                self.observed_at,
            )
        ):
            raise ValueError("capability receipt identity is required")
        for value in (
            self.receipt_id,
            self.input_sha256,
            self.output_sha256,
            self.baseline_sha256,
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError("capability receipt hashes must be canonical SHA-256")
        try:
            parsed = datetime.fromisoformat(self.observed_at)
        except ValueError as exc:
            raise ValueError("capability receipt timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise ValueError("capability receipt timestamp must be timezone-aware")
        if self.role is ProviderRole.EXECUTION_IMPLEMENTER:
            if not self.acceptance_decision_id or self.promotion_revision is None:
                raise ValueError(
                    "execution certification requires independent acceptance and promotion"
                )
            if self.promotion_revision < 1:
                raise ValueError("promotion revision must be positive")
        elif self.acceptance_decision_id is not None or self.promotion_revision is not None:
            raise ValueError("interaction receipt cannot claim acceptance or promotion")
        if self.receipt_id != _sha256_json(self._unsigned_payload()):
            raise ValueError("capability receipt integrity check failed")

    def _unsigned_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "provider_id": self.provider_id,
            "role": self.role.value,
            "project_id": self.project_id,
            "project_job_id": self.project_job_id,
            "observed_at": self.observed_at,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "baseline_sha256": self.baseline_sha256,
            "acceptance_decision_id": self.acceptance_decision_id,
            "promotion_revision": self.promotion_revision,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "provider_id": self.provider_id,
            "role": self.role.value,
            "project_id": self.project_id,
            "project_job_id": self.project_job_id,
            "observed_at": self.observed_at,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "baseline_sha256": self.baseline_sha256,
            "acceptance_decision_id": self.acceptance_decision_id,
            "promotion_revision": self.promotion_revision,
            "valid": True,
        }


class CapabilityEvidenceStore:
    """SQLite authority containing hashes and role-certification metadata only."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_capability_evidence_path()).expanduser().resolve()

    def append(self, receipt: CapabilityReceipt) -> None:
        receipt.validate()
        self._initialize()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                INSERT INTO capability_receipts (
                    receipt_id, provider_id, role, project_id, project_job_id,
                    observed_at, input_sha256, output_sha256, baseline_sha256,
                    acceptance_decision_id, promotion_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.provider_id,
                    receipt.role.value,
                    receipt.project_id,
                    receipt.project_job_id,
                    receipt.observed_at,
                    receipt.input_sha256,
                    receipt.output_sha256,
                    receipt.baseline_sha256,
                    receipt.acceptance_decision_id,
                    receipt.promotion_revision,
                ),
            )

    def valid_receipts(
        self, *, provider_id: str, project_id: str | None = None
    ) -> tuple[CapabilityReceipt, ...]:
        if not self.path.is_file():
            return ()
        query = "SELECT * FROM capability_receipts WHERE provider_id = ?"
        values: list[object] = [provider_id]
        if project_id is not None:
            query += " AND project_id = ?"
            values.append(project_id)
        query += " ORDER BY observed_at, receipt_id"
        receipts: list[CapabilityReceipt] = []
        try:
            with sqlite3.connect(self.path) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(query, values).fetchall()
            for row in rows:
                receipt = CapabilityReceipt(
                    receipt_id=str(row["receipt_id"]),
                    provider_id=str(row["provider_id"]),
                    role=ProviderRole(str(row["role"])),
                    project_id=str(row["project_id"]),
                    project_job_id=str(row["project_job_id"]),
                    observed_at=str(row["observed_at"]),
                    input_sha256=str(row["input_sha256"]),
                    output_sha256=str(row["output_sha256"]),
                    baseline_sha256=str(row["baseline_sha256"]),
                    acceptance_decision_id=(
                        str(row["acceptance_decision_id"])
                        if row["acceptance_decision_id"] is not None
                        else None
                    ),
                    promotion_revision=(
                        int(row["promotion_revision"])
                        if row["promotion_revision"] is not None
                        else None
                    ),
                )
                receipt.validate()
                receipts.append(receipt)
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"capability evidence store is corrupt: {type(exc).__name__}") from exc
        return tuple(receipts)

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS capability_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    project_job_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    output_sha256 TEXT NOT NULL,
                    baseline_sha256 TEXT NOT NULL,
                    acceptance_decision_id TEXT,
                    promotion_revision INTEGER
                )
                """
            )


def record_execution_implementer_evidence(
    *,
    project_id: str,
    project_job_id: str,
    accepted_result_sha256: str,
    promoted_baseline_sha256: str,
    acceptance_decision_id: str,
    promotion_revision: int,
    provider_id: str = "codex",
    store: CapabilityEvidenceStore | None = None,
) -> CapabilityReceipt:
    """Integration seam called only after independent acceptance and promotion."""

    receipt = CapabilityReceipt.issue(
        provider_id=provider_id,
        role=ProviderRole.EXECUTION_IMPLEMENTER,
        project_id=project_id,
        project_job_id=project_job_id,
        input_sha256=accepted_result_sha256,
        output_sha256=accepted_result_sha256,
        baseline_sha256=promoted_baseline_sha256,
        acceptance_decision_id=acceptance_decision_id,
        promotion_revision=promotion_revision,
    )
    (store or CapabilityEvidenceStore()).append(receipt)
    return receipt


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "CapabilityEvidenceStore",
    "CapabilityReceipt",
    "default_capability_evidence_path",
    "record_execution_implementer_evidence",
]
