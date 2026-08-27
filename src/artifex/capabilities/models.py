"""Provider-neutral capability, readiness, and eligibility contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ProviderRole(StrEnum):
    INTERACTION = "INTERACTION"
    EXECUTION_IMPLEMENTER = "EXECUTION_IMPLEMENTER"
    HARNESS = "HARNESS"
    RESEARCH = "RESEARCH"
    INFERENCE = "INFERENCE"
    COMPUTE = "COMPUTE"
    VALIDATION = "VALIDATION"


class ReadinessState(StrEnum):
    NOT_DETECTED = "NOT_DETECTED"
    DETECTED = "DETECTED"
    CONFIGURED = "CONFIGURED"
    AUTHENTICATED = "AUTHENTICATED"
    HEALTHY = "HEALTHY"
    REGISTERED = "REGISTERED"
    AVAILABLE = "AVAILABLE"


class GovernanceMode(StrEnum):
    STANDALONE = "STANDALONE"
    PROVIDER_MANAGED = "PROVIDER_MANAGED"
    ATLAS_GOVERNED = "ATLAS_GOVERNED"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass(frozen=True, slots=True)
class CredentialReference:
    """Secret-free pointer resolved by a scoped credential broker."""

    broker: str
    reference: str
    provider_id: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.broker, self.reference, self.provider_id)):
            raise ValueError("credential reference identity is required")
        if not self.scopes or any(not scope.strip() for scope in self.scopes):
            raise ValueError("credential reference scopes are required")

    def to_dict(self) -> dict[str, object]:
        return {
            "broker": self.broker,
            "reference": self.reference,
            "provider_id": self.provider_id,
            "scopes": list(self.scopes),
            "secret_material_present": False,
        }


@dataclass(frozen=True, slots=True)
class ProviderConfiguration:
    provider_id: str
    enabled: bool
    roles: frozenset[ProviderRole]
    governance_mode: GovernanceMode
    command: tuple[str, ...]
    credential_reference: CredentialReference | None = None

    def __post_init__(self) -> None:
        if not self.provider_id.strip() or not self.command or any(
            not part.strip() for part in self.command
        ):
            raise ValueError("provider ID and executable command are required")
        if not self.roles:
            raise ValueError("configured provider requires at least one role")
        reference = self.credential_reference
        if reference is not None and reference.provider_id != self.provider_id:
            raise ValueError("credential reference provider does not match configuration")

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "enabled": self.enabled,
            "roles": sorted(role.value for role in self.roles),
            "governance_mode": self.governance_mode.value,
            "command": list(self.command),
            "credential_reference": (
                self.credential_reference.to_dict()
                if self.credential_reference is not None
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class ProviderReadiness:
    provider_id: str
    state: ReadinessState
    checks: dict[str, bool]
    executable: str | None = None
    command: tuple[str, ...] = ()
    version: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "state": self.state.value,
            "checks": dict(sorted(self.checks.items())),
            "executable": self.executable,
            "command": list(self.command),
            "version": self.version,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ProviderInstance:
    instance_id: str
    configuration: ProviderConfiguration
    readiness: ProviderReadiness
    capabilities: frozenset[str]
    certified_roles: frozenset[ProviderRole] = frozenset()

    def __post_init__(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("provider instance ID is required")
        if self.readiness.provider_id != self.configuration.provider_id:
            raise ValueError("provider readiness does not match configuration")
        if not self.certified_roles.issubset(self.configuration.roles):
            raise ValueError("certified roles must be configured roles")

    @property
    def provider_id(self) -> str:
        return self.configuration.provider_id

    @property
    def globally_available(self) -> bool:
        return self.readiness.state is ReadinessState.AVAILABLE

    def to_dict(self) -> dict[str, object]:
        return {
            "instance_id": self.instance_id,
            "provider_id": self.provider_id,
            "configuration": self.configuration.to_dict(),
            "readiness": self.readiness.to_dict(),
            "capabilities": sorted(self.capabilities),
            "certified_roles": sorted(role.value for role in self.certified_roles),
            "globally_available": self.globally_available,
        }


@dataclass(frozen=True, slots=True)
class ActorContext:
    actor_id: str
    actor_type: str
    delegated_roles: frozenset[ProviderRole]

    def __post_init__(self) -> None:
        if not self.actor_id.strip() or not self.actor_type.strip():
            raise ValueError("explicit actor identity and type are required")


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    project_id: str
    project_job_id: str
    role: ProviderRole
    capabilities: frozenset[str]
    allowed_providers: frozenset[str]
    envelope_capabilities: frozenset[str]
    actor: ActorContext
    data_classification: DataClassification
    preferred_provider: str | None = None
    project_allowed_providers: frozenset[str] = frozenset()
    project_allowed_roles: frozenset[ProviderRole] = frozenset()

    def __post_init__(self) -> None:
        if not self.project_id.strip() or not self.project_job_id.strip():
            raise ValueError("Project and ProjectJob identity are required")


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    eligible: bool
    provider_id: str | None
    instance_id: str | None
    reasons: tuple[str, ...]
    evaluated: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "eligible": self.eligible,
            "provider_id": self.provider_id,
            "instance_id": self.instance_id,
            "reasons": list(self.reasons),
            "evaluated": [dict(item) for item in self.evaluated],
            "contextual": True,
        }
