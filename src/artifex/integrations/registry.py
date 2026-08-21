"""Deterministic integration registration, health, and compatibility reporting."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from artifex import __version__
from artifex.integrations.contracts import (
    HealthReport,
    IntegrationError,
    IntegrationMetadata,
    IntegrationRole,
)


class Integration(Protocol):
    @property
    def metadata(self) -> IntegrationMetadata: ...

    def health(self) -> HealthReport: ...


class IntegrationRegistry:
    def __init__(self, integrations: Iterable[Integration] = ()) -> None:
        self._integrations: dict[str, Integration] = {}
        for integration in integrations:
            self.register(integration)

    def register(self, integration: Integration) -> None:
        identifier = integration.metadata.integration_id
        if identifier in self._integrations:
            raise IntegrationError(f"integration already registered: {identifier}")
        self._integrations[identifier] = integration

    def get(self, integration_id: str) -> Integration:
        try:
            return self._integrations[integration_id]
        except KeyError as exc:
            raise IntegrationError(f"unknown integration: {integration_id}") from exc

    def all(self) -> tuple[Integration, ...]:
        return tuple(self._integrations[key] for key in sorted(self._integrations))

    def compatible(
        self,
        *,
        role: IntegrationRole | None = None,
        capabilities: frozenset[str] = frozenset(),
        core_version: str = __version__,
    ) -> tuple[Integration, ...]:
        return tuple(
            integration
            for integration in self.all()
            if integration.metadata.compatibility.supports(core_version)
            and (role is None or role in integration.metadata.roles)
            and capabilities.issubset(integration.metadata.capabilities)
        )

    def report(self, *, core_version: str = __version__) -> list[dict[str, object]]:
        return [
            {
                **integration.metadata.to_dict(core_version=core_version),
                "health": integration.health().to_dict(),
            }
            for integration in self.all()
        ]
