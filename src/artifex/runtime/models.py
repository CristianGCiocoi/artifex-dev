"""Durable ARTIFEX runtime security and execution contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from artifex.policy import scrub_secrets


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


class RuntimeAuthorizationError(RuntimeError):
    """An authenticated actor lacks delegated authority for an operation."""


class EvidenceBindingError(RuntimeError):
    """Evidence is incomplete or is bound to a different execution."""


class ActorType(StrEnum):
    USER = "USER"
    ARTIFEX_SERVICE = "ARTIFEX_SERVICE"
    INTERACTION_CLIENT = "INTERACTION_CLIENT"
    PROVIDER = "PROVIDER"
    AGENT = "AGENT"
    AUTOMATION_SYSTEM_ACTOR = "AUTOMATION_SYSTEM_ACTOR"


class SupervisionLevel(StrEnum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


class Materiality(StrEnum):
    OPERATIONAL = "OPERATIONAL"
    TACTICAL = "TACTICAL"
    STRATEGIC_MATERIAL = "STRATEGIC_MATERIAL"


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    grant_id: str
    delegator_id: str
    delegate_id: str
    project_id: str
    allowed_actions: tuple[str, ...]
    issued_at: int
    expires_at: int | None = None

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.grant_id, self.delegator_id, self.delegate_id, self.project_id)
        ):
            raise RuntimeAuthorizationError("delegation identity and Project are required")
        if not self.allowed_actions or any(not action.strip() for action in self.allowed_actions):
            raise RuntimeAuthorizationError("delegation must grant explicit actions")
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise RuntimeAuthorizationError("delegation expiry must follow issuance")

    def permits(self, actor_id: str, project_id: str, action: str, *, now: int) -> bool:
        return (
            actor_id == self.delegate_id
            and project_id == self.project_id
            and (self.expires_at is None or now < self.expires_at)
            and (action in self.allowed_actions or "*" in self.allowed_actions)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "delegator_id": self.delegator_id,
            "delegate_id": self.delegate_id,
            "project_id": self.project_id,
            "allowed_actions": list(self.allowed_actions),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class ActorPrincipal:
    actor_id: str
    actor_type: ActorType
    authenticated: bool
    authentication_method: str
    direct_permissions: tuple[str, ...] = ()
    delegation: DelegationGrant | None = None

    def __post_init__(self) -> None:
        if not self.actor_id.strip():
            raise RuntimeAuthorizationError("explicit actor identity is required")
        if self.authenticated and not self.authentication_method.strip():
            raise RuntimeAuthorizationError("authenticated actor requires an authentication method")
        if self.delegation is not None and self.delegation.delegate_id != self.actor_id:
            raise RuntimeAuthorizationError("delegation delegate does not match actor")

    def require(self, action: str, project_id: str, *, now: int) -> None:
        if not self.authenticated or self.actor_id.casefold() == "anonymous":
            raise RuntimeAuthorizationError("authenticated actor identity is required")
        if action in self.direct_permissions or "*" in self.direct_permissions:
            return
        if self.delegation is not None and self.delegation.permits(
            self.actor_id, project_id, action, now=now
        ):
            return
        raise RuntimeAuthorizationError(
            f"actor {self.actor_id} lacks {action} authority for Project {project_id}"
        )

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_type": self.actor_type.value,
            "authenticated": self.authenticated,
            "authentication_method": self.authentication_method,
            "delegation_id": self.delegation.grant_id if self.delegation is not None else None,
            "delegated_by": self.delegation.delegator_id if self.delegation is not None else None,
        }


type ActorLike = str | ActorPrincipal


def actor_principal(actor: ActorLike) -> ActorPrincipal:
    """Adapt M2 in-process actor strings while rejecting anonymous identity.

    New automated/provider paths require an explicit ``ActorPrincipal``. The
    adapter exists solely so the accepted M2 public runtime remains compatible.
    """

    if isinstance(actor, ActorPrincipal):
        return actor
    value = actor.strip()
    if not value or value.casefold() == "anonymous":
        return ActorPrincipal(value or "anonymous", ActorType.INTERACTION_CLIENT, False, "")
    return ActorPrincipal(
        value,
        ActorType.ARTIFEX_SERVICE,
        True,
        "legacy-in-process",
        direct_permissions=("*",),
    )


@dataclass(frozen=True, slots=True)
class CredentialReference:
    reference_id: str
    provider_id: str
    role: str
    project_id: str
    expires_at: int | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.reference_id, self.provider_id, self.role, self.project_id)
        ):
            raise RuntimeAuthorizationError("credential reference scope is required")
        if scrub_secrets(self.reference_id) != self.reference_id:
            raise RuntimeAuthorizationError("credential reference contains secret-like material")

    def permits(self, provider_id: str, role: str, project_id: str, *, now: int) -> bool:
        return (
            not self.revoked
            and self.provider_id == provider_id
            and self.role == role
            and self.project_id == project_id
            and (self.expires_at is None or now < self.expires_at)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "provider_id": self.provider_id,
            "role": self.role,
            "project_id": self.project_id,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }


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
    supervision_level: SupervisionLevel = SupervisionLevel.L2
    materiality: Materiality = Materiality.TACTICAL
    allowed_workstreams: tuple[str, ...] = ()
    allowed_providers: tuple[str, ...] = ()
    allowed_provider_roles: tuple[str, ...] = ()
    filesystem_permissions: tuple[str, ...] = ("READ", "WRITE")
    network_permissions: tuple[str, ...] = ()
    tool_permissions: tuple[str, ...] = ()
    data_classification: str = "INTERNAL"
    credential_references: tuple[CredentialReference, ...] = ()
    resource_budget: tuple[tuple[str, int], ...] = ()
    deadline_at: int | None = None
    stop_conditions: tuple[str, ...] = ("MAX_ATTEMPTS", "UNKNOWN_OUTCOME")
    require_durable_evidence: bool = False
    baseline_fingerprint: str | None = None
    baseline_commit: str | None = None

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
        normalized_paths = tuple(_safe_relative_path(path) for path in self.allowed_paths)
        if len(set(normalized_paths)) != len(normalized_paths):
            raise EnvelopeError("Envelope paths must be unique after normalization")
        if any(not value.strip() for value in self.allowed_capabilities + self.required_gates):
            raise EnvelopeError("Envelope capabilities and gates must be non-empty values")
        if self.supervision_level not in tuple(SupervisionLevel):
            raise EnvelopeError("Only L1-L4 supervision levels are allowed")
        if not self.data_classification.strip() or not self.stop_conditions:
            raise EnvelopeError("Envelope data rules and stop conditions are required")
        secret_safe_values = (
            self.objective,
            self.actor_id,
            self.recovery_policy,
            self.data_classification,
            *self.allowed_paths,
            *self.allowed_capabilities,
            *self.required_gates,
            *self.network_permissions,
            *self.tool_permissions,
            *self.stop_conditions,
        )
        if any(scrub_secrets(value) != value for value in secret_safe_values):
            raise EnvelopeError("Execution Envelope contains secret-like material")
        if any(permission not in {"READ", "WRITE"} for permission in self.filesystem_permissions):
            raise EnvelopeError("filesystem permissions must be READ and/or WRITE")
        if self.allowed_providers and not self.allowed_provider_roles:
            raise EnvelopeError("provider execution requires an explicit provider role")
        if self.allowed_provider_roles and not self.allowed_providers:
            raise EnvelopeError("provider roles require an explicit provider")
        if "provider:codex" in self.allowed_capabilities and "codex" not in self.allowed_providers:
            raise EnvelopeError(
                "automated Codex execution is outside M2 without M3 provider authority fields"
            )
        if self.allowed_providers and (
            self.baseline_fingerprint is None or self.baseline_commit is None
        ):
            raise EnvelopeError(
                "provider execution requires semantic fingerprint and Git commit baseline"
            )
        if self.baseline_fingerprint is not None and not re.fullmatch(
            r"[a-f0-9]{64}", self.baseline_fingerprint
        ):
            raise EnvelopeError("baseline fingerprint must be SHA-256")
        if self.baseline_commit is not None and not re.fullmatch(
            r"[a-f0-9]{40}", self.baseline_commit
        ):
            raise EnvelopeError("baseline commit must be a full Git SHA-1")
        if any(item.project_id != self.project_id for item in self.credential_references):
            raise EnvelopeError("credential references must be scoped to the Envelope Project")
        if any(not key.strip() or value < 0 for key, value in self.resource_budget):
            raise EnvelopeError("resource budget entries require names and non-negative limits")
        if self.deadline_at is not None and self.deadline_at < 1:
            raise EnvelopeError("Envelope deadline must be a positive timestamp")

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(
            self._authority_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _authority_dict(self) -> dict[str, Any]:
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
            "supervision_level": self.supervision_level.value,
            "materiality": self.materiality.value,
            "allowed_workstreams": list(self.allowed_workstreams),
            "allowed_providers": list(self.allowed_providers),
            "allowed_provider_roles": list(self.allowed_provider_roles),
            "filesystem_permissions": list(self.filesystem_permissions),
            "network_permissions": list(self.network_permissions),
            "tool_permissions": list(self.tool_permissions),
            "data_classification": self.data_classification,
            "credential_references": [item.to_dict() for item in self.credential_references],
            "resource_budget": {key: value for key, value in self.resource_budget},
            "deadline_at": self.deadline_at,
            "stop_conditions": list(self.stop_conditions),
            "require_durable_evidence": self.require_durable_evidence,
            "baseline_fingerprint": self.baseline_fingerprint,
            "baseline_commit": self.baseline_commit,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._authority_dict(), "fingerprint": self.fingerprint}

    def authorizes_path(self, path: str, *, permission: str) -> bool:
        if permission not in self.filesystem_permissions:
            return False
        candidate = _safe_relative_path(path)
        return any(
            owner == "." or candidate == owner or candidate.startswith(f"{owner}/")
            for owner in (_safe_relative_path(item) for item in self.allowed_paths)
        )

    def credential(self, reference_id: str) -> CredentialReference | None:
        return next(
            (item for item in self.credential_references if item.reference_id == reference_id),
            None,
        )


@dataclass(frozen=True, slots=True)
class DispatchAuthorization:
    authorization_id: str
    attempt_id: str
    provider_id: str
    provider_role: str
    requested_capabilities: tuple[str, ...]
    filesystem_permissions: tuple[str, ...]
    network_permissions: tuple[str, ...]
    tool_permissions: tuple[str, ...]
    credential_reference_ids: tuple[str, ...]
    envelope_fingerprint: str
    actor_id: str
    authorized_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "attempt_id": self.attempt_id,
            "provider_id": self.provider_id,
            "provider_role": self.provider_role,
            "requested_capabilities": list(self.requested_capabilities),
            "filesystem_permissions": list(self.filesystem_permissions),
            "network_permissions": list(self.network_permissions),
            "tool_permissions": list(self.tool_permissions),
            "credential_reference_ids": list(self.credential_reference_ids),
            "envelope_fingerprint": self.envelope_fingerprint,
            "actor_id": self.actor_id,
            "authorized_at": self.authorized_at,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    project_job_id: str
    attempt_id: str
    gate: str
    passed: bool
    envelope_fingerprint: str
    baseline_revision: int
    artifact_ref: str
    artifact_digest: str
    actor_id: str
    recorded_at: int

    def __post_init__(self) -> None:
        required = (
            self.evidence_id,
            self.project_job_id,
            self.attempt_id,
            self.gate,
            self.envelope_fingerprint,
            self.artifact_ref,
            self.artifact_digest,
            self.actor_id,
        )
        if not all(item.strip() for item in required):
            raise EvidenceBindingError(
                "evidence identity, binding, artifact and actor are required"
            )
        if self.baseline_revision < 1:
            raise EvidenceBindingError("evidence baseline must be positive")
        if not re.fullmatch(r"[a-f0-9]{64}", self.artifact_digest):
            raise EvidenceBindingError("evidence artifact digest must be SHA-256")
        if scrub_secrets(self.artifact_ref) != self.artifact_ref:
            raise EvidenceBindingError("evidence artifact reference contains secret-like material")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "project_job_id": self.project_job_id,
            "attempt_id": self.attempt_id,
            "gate": self.gate,
            "passed": self.passed,
            "envelope_fingerprint": self.envelope_fingerprint,
            "baseline_revision": self.baseline_revision,
            "artifact_ref": self.artifact_ref,
            "artifact_digest": self.artifact_digest,
            "actor_id": self.actor_id,
            "recorded_at": self.recorded_at,
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
    evidence_ids: tuple[str, ...] = ()
    envelope_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "project_job_id": self.project_job_id,
            "outcome": self.outcome.value,
            "evidence_valid": self.evidence_valid,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "decided_at": self.decided_at,
            "evidence_ids": list(self.evidence_ids),
            "envelope_fingerprint": self.envelope_fingerprint,
        }


def _safe_relative_path(value: str) -> str:
    candidate = value.replace("\\", "/").strip()
    if candidate in {"", "/"} or "\x00" in candidate:
        raise EnvelopeError("Envelope paths must be non-empty relative paths")
    path = PurePosixPath(candidate)
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise EnvelopeError(f"Envelope path escapes workspace: {value!r}")
    normalized = path.as_posix().removeprefix("./")
    return normalized or "."


__all__ = [
    "AcceptanceDecision",
    "AcceptanceOutcome",
    "ActorLike",
    "ActorPrincipal",
    "ActorType",
    "AttemptState",
    "CoordinatorFencedError",
    "CredentialReference",
    "DelegationGrant",
    "DispatchAuthorization",
    "EnvelopeError",
    "EvidenceBindingError",
    "EvidenceRecord",
    "ExecutionEnvelope",
    "FenceToken",
    "Materiality",
    "ProjectJobState",
    "PromotionConflictError",
    "ReconciliationOutcome",
    "RunState",
    "RuntimeAuthorizationError",
    "RuntimeError",
    "RuntimeTransitionError",
    "SupervisionLevel",
    "WorkstreamState",
    "actor_principal",
]
