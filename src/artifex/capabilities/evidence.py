"""Local, secret-free evidence for live provider role certification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from artifex.capabilities.models import ProviderRole

_SHA256 = re.compile(r"[0-9a-f]{64}")
_LEGACY_SCHEMA_VERSION = "1.0"
_SCHEMA_VERSION = "2.0"


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


def shipping_artifact_sha256(
    *,
    install_root: str | Path | None = None,
    security_root: str | Path | None = None,
) -> str | None:
    """Return trusted shipping identity, never package source state.

    Source and qualifier execution may supply an explicit frozen digest.  A
    managed shipping process instead resolves the authenticated install
    manifest beside its executable, which survives service restart without
    developer-only environment wiring.
    """

    value = os.environ.get("ARTIFEX_SHIPPING_ARTIFACT_SHA256", "").strip().casefold()
    if _SHA256.fullmatch(value) is not None:
        return value
    root = (
        Path(install_root).expanduser().resolve()
        if install_root is not None
        else Path(sys.executable).resolve().parent
    )
    try:
        from artifex.distribution.lifecycle import installed_shipping_artifact_sha256

        return installed_shipping_artifact_sha256(root, security_root=security_root)
    except (OSError, TypeError, ValueError):
        return None


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
    provider_version: str | None = None
    provider_executable_sha256: str | None = None
    auth_probe_sha256: str | None = None
    shipping_artifact_sha256: str | None = None

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
        provider_version: str | None = None,
        provider_executable_sha256: str | None = None,
        auth_probe_sha256: str | None = None,
        shipping_artifact_sha256: str | None = None,
        observed_at: str | None = None,
    ) -> CapabilityReceipt:
        timestamp = observed_at or datetime.now(UTC).isoformat()
        unsigned = _unsigned_payload(
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
            provider_version=provider_version,
            provider_executable_sha256=provider_executable_sha256,
            auth_probe_sha256=auth_probe_sha256,
            shipping_artifact_sha256=shipping_artifact_sha256,
        )
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
            provider_version=provider_version,
            provider_executable_sha256=provider_executable_sha256,
            auth_probe_sha256=auth_probe_sha256,
            shipping_artifact_sha256=shipping_artifact_sha256,
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
        bindings = (
            self.provider_version,
            self.provider_executable_sha256,
            self.auth_probe_sha256,
            self.shipping_artifact_sha256,
        )
        if any(item is not None for item in bindings) and not all(
            isinstance(item, str) and item.strip() for item in bindings
        ):
            raise ValueError("live certification binding must be complete")
        if self.live_role_eligible:
            for binding_hash in (
                self.provider_executable_sha256,
                self.auth_probe_sha256,
                self.shipping_artifact_sha256,
            ):
                if binding_hash is None or _SHA256.fullmatch(binding_hash) is None:
                    raise ValueError("live certification binding hashes must be canonical SHA-256")
        if self.receipt_id != _sha256_json(self._unsigned_payload()):
            raise ValueError("capability receipt integrity check failed")

    @property
    def live_role_eligible(self) -> bool:
        return all(
            isinstance(item, str) and item.strip()
            for item in (
                self.provider_version,
                self.provider_executable_sha256,
                self.auth_probe_sha256,
                self.shipping_artifact_sha256,
            )
        )

    def _unsigned_payload(self) -> dict[str, object]:
        return _unsigned_payload(
            provider_id=self.provider_id,
            role=self.role,
            project_id=self.project_id,
            project_job_id=self.project_job_id,
            observed_at=self.observed_at,
            input_sha256=self.input_sha256,
            output_sha256=self.output_sha256,
            baseline_sha256=self.baseline_sha256,
            acceptance_decision_id=self.acceptance_decision_id,
            promotion_revision=self.promotion_revision,
            provider_version=self.provider_version,
            provider_executable_sha256=self.provider_executable_sha256,
            auth_probe_sha256=self.auth_probe_sha256,
            shipping_artifact_sha256=self.shipping_artifact_sha256,
        )

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
            "provider_version": self.provider_version,
            "provider_executable_sha256": self.provider_executable_sha256,
            "auth_probe_sha256": self.auth_probe_sha256,
            "shipping_artifact_sha256": self.shipping_artifact_sha256,
            "live_role_eligible": self.live_role_eligible,
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
                    acceptance_decision_id, promotion_revision, provider_version,
                    provider_executable_sha256, auth_probe_sha256, shipping_artifact_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    receipt.provider_version,
                    receipt.provider_executable_sha256,
                    receipt.auth_probe_sha256,
                    receipt.shipping_artifact_sha256,
                ),
            )

    def valid_receipts(
        self, *, provider_id: str, project_id: str | None = None
    ) -> tuple[CapabilityReceipt, ...]:
        if not self.path.is_file():
            return ()
        self._initialize()
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
                    provider_version=(
                        str(row["provider_version"])
                        if row["provider_version"] is not None
                        else None
                    ),
                    provider_executable_sha256=(
                        str(row["provider_executable_sha256"])
                        if row["provider_executable_sha256"] is not None
                        else None
                    ),
                    auth_probe_sha256=(
                        str(row["auth_probe_sha256"])
                        if row["auth_probe_sha256"] is not None
                        else None
                    ),
                    shipping_artifact_sha256=(
                        str(row["shipping_artifact_sha256"])
                        if row["shipping_artifact_sha256"] is not None
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
                    promotion_revision INTEGER,
                    provider_version TEXT,
                    provider_executable_sha256 TEXT,
                    auth_probe_sha256 TEXT,
                    shipping_artifact_sha256 TEXT
                )
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(capability_receipts)").fetchall()
            }
            for name in (
                "provider_version",
                "provider_executable_sha256",
                "auth_probe_sha256",
                "shipping_artifact_sha256",
            ):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE capability_receipts ADD COLUMN {name} TEXT"
                    )


def record_execution_implementer_evidence(
    *,
    project_id: str,
    project_job_id: str,
    accepted_result_sha256: str,
    promoted_baseline_sha256: str,
    acceptance_decision_id: str,
    promotion_revision: int,
    provider_version: str | None = None,
    provider_executable_sha256: str | None = None,
    auth_probe_sha256: str | None = None,
    shipping_artifact_sha256: str | None = None,
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
        provider_version=provider_version,
        provider_executable_sha256=provider_executable_sha256,
        auth_probe_sha256=auth_probe_sha256,
        shipping_artifact_sha256=shipping_artifact_sha256,
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


def _unsigned_payload(
    *,
    provider_id: str,
    role: ProviderRole,
    project_id: str,
    project_job_id: str,
    observed_at: str,
    input_sha256: str,
    output_sha256: str,
    baseline_sha256: str,
    acceptance_decision_id: str | None,
    promotion_revision: int | None,
    provider_version: str | None,
    provider_executable_sha256: str | None,
    auth_probe_sha256: str | None,
    shipping_artifact_sha256: str | None,
) -> dict[str, object]:
    binding_values = (
        provider_version,
        provider_executable_sha256,
        auth_probe_sha256,
        shipping_artifact_sha256,
    )
    value: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION if any(binding_values) else _LEGACY_SCHEMA_VERSION,
        "provider_id": provider_id,
        "role": role.value,
        "project_id": project_id,
        "project_job_id": project_job_id,
        "observed_at": observed_at,
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "baseline_sha256": baseline_sha256,
        "acceptance_decision_id": acceptance_decision_id,
        "promotion_revision": promotion_revision,
    }
    if any(binding_values):
        value.update(
            {
                "provider_version": provider_version,
                "provider_executable_sha256": provider_executable_sha256,
                "auth_probe_sha256": auth_probe_sha256,
                "shipping_artifact_sha256": shipping_artifact_sha256,
            }
        )
    return value


__all__ = [
    "CapabilityEvidenceStore",
    "CapabilityReceipt",
    "default_capability_evidence_path",
    "record_execution_implementer_evidence",
    "shipping_artifact_sha256",
]
