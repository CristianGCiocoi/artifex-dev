"""Durable ARTIFEX runtime contracts for the M2 execution hierarchy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RuntimeError(Exception):
    """Base durable-runtime failure."""


class CoordinatorFencedError(RuntimeError):
    """The caller does not hold the active coordinator generation."""


class RuntimeTransitionError(RuntimeError):
    """A durable entity transition is not permitted."""


class EnvelopeError(RuntimeError):
    """A Run lacks an approved valid execution envelope."""


class PromotionConflictError(RuntimeError):
    """A workspace baseline is stale relative to Project Authority."""


class WorkstreamState(StrEnum):
    READY = "READY"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    COMPLETE = "COMPLETE"
    CANCELLED = "CANCELLED"


class RunState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_RECONCILIATION = "WAITING_RECONCILIATION"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class ProjectJobState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    REWORK = "REWORK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    PROMOTION_CONFLICT = "PROMOTION_CONFLICT"
    UNKNOWN = "UNKNOWN"
    CANCELLED = "CANCELLED"


class AttemptState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"
    NEEDS_RECONCILIATION = "NEEDS_RECONCILIATION"
    RECONCILED_RETRYABLE = "RECONCILED_RETRYABLE"


class AcceptanceOutcome(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    REWORK = "REWORK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ReconciliationOutcome(StrEnum):
    RECOVERED_FINISHED = "RECOVERED_FINISHED"
    SAFE_TO_RETRY = "SAFE_TO_RETRY"
    STILL_UNKNOWN = "STILL_UNKNOWN"


@dataclass(frozen=True, slots=True)
class FenceToken:
    holder_id: str
    generation: int
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "holder_id": self.holder_id,
            "generation": self.generation,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class ExecutionEnvelope:
    envelope_id: str
    version: int
    project_id: str
    objective: str
    baseline_revision: int
    actor_id: str
    allowed_paths: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]
    required_gates: tuple[str, ...]
    max_attempts: int
    recovery_policy: str
    stop_on_unknown: bool = True
    approved: bool = True

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.envelope_id, self.project_id, self.objective, self.actor_id)
        ):
            raise EnvelopeError("Envelope identity, Project, objective, and actor are required")
        if self.version < 1 or self.baseline_revision < 1 or self.max_attempts < 1:
            raise EnvelopeError("Envelope version, baseline, and attempt limit must be positive")
        if not self.allowed_paths or not self.required_gates or not self.recovery_policy.strip():
            raise EnvelopeError("Envelope scope, gates, and recovery policy are required")
        if not self.approved:
            raise EnvelopeError("Only approved Envelopes may authorize a Run")
        if "provider:codex" in self.allowed_capabilities:
            raise EnvelopeError("automated Codex execution is outside M2")

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "version": self.version,
            "project_id": self.project_id,
            "objective": self.objective,
            "baseline_revision": self.baseline_revision,
            "actor_id": self.actor_id,
            "allowed_paths": list(self.allowed_paths),
            "allowed_capabilities": list(self.allowed_capabilities),
            "required_gates": list(self.required_gates),
            "max_attempts": self.max_attempts,
            "recovery_policy": self.recovery_policy,
            "stop_on_unknown": self.stop_on_unknown,
            "approved": self.approved,
        }


@dataclass(frozen=True, slots=True)
class AcceptanceDecision:
    decision_id: str
    project_job_id: str
    outcome: AcceptanceOutcome
    evidence_valid: bool
    actor_id: str
    reason: str
    decided_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "project_job_id": self.project_job_id,
            "outcome": self.outcome.value,
            "evidence_valid": self.evidence_valid,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "decided_at": self.decided_at,
        }


__all__ = [
    "AcceptanceDecision",
    "AcceptanceOutcome",
    "AttemptState",
    "CoordinatorFencedError",
    "EnvelopeError",
    "ExecutionEnvelope",
    "FenceToken",
    "ProjectJobState",
    "PromotionConflictError",
    "ReconciliationOutcome",
    "RunState",
    "RuntimeError",
    "RuntimeTransitionError",
    "WorkstreamState",
]
