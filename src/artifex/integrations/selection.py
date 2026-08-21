"""Capability-based, policy-owned integration selection foundation."""

from __future__ import annotations

from dataclasses import dataclass

from artifex import __version__
from artifex.integrations.contracts import HealthStatus, IntegrationError, IntegrationRole
from artifex.integrations.registry import Integration, IntegrationRegistry


@dataclass(frozen=True, slots=True)
class SelectionRequest:
    role: IntegrationRole
    capabilities: frozenset[str] = frozenset()
    integration_id: str | None = None


@dataclass(frozen=True, slots=True)
class SelectionPolicy:
    """Explicit preferences only; automatic performance routing is deferred."""

    allowed_integrations: frozenset[str] = frozenset()
    preferred_integrations: tuple[str, ...] = ("manual",)
    allow_fallback: bool = True


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    integration: Integration
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "integration_id": self.integration.metadata.integration_id,
            "reason": self.reason,
            "capabilities": sorted(self.integration.metadata.capabilities),
            "roles": sorted(role.value for role in self.integration.metadata.roles),
        }


def select_integration(
    registry: IntegrationRegistry,
    request: SelectionRequest,
    policy: SelectionPolicy | None = None,
    *,
    core_version: str = __version__,
) -> SelectionDecision:
    policy = SelectionPolicy() if policy is None else policy
    candidates = registry.compatible(
        role=request.role,
        capabilities=request.capabilities,
        core_version=core_version,
    )
    allowed = tuple(
        item
        for item in candidates
        if not policy.allowed_integrations
        or item.metadata.integration_id in policy.allowed_integrations
    )
    healthy = tuple(item for item in allowed if item.health().status is HealthStatus.PASS)
    if request.integration_id is not None:
        for integration in healthy:
            if integration.metadata.integration_id == request.integration_id:
                return SelectionDecision(integration, "explicit integration requested")
        raise IntegrationError(
            "requested integration is unavailable, unhealthy, incompatible, disallowed, "
            "or lacks capabilities"
        )

    by_id = {item.metadata.integration_id: item for item in healthy}
    for identifier in policy.preferred_integrations:
        if identifier in by_id:
            return SelectionDecision(by_id[identifier], "first compatible policy preference")
    if policy.allow_fallback and healthy:
        return SelectionDecision(healthy[0], "deterministic compatible fallback")
    raise IntegrationError("no integration satisfies the requested role and capabilities")
