"""Cross-interface continuity proofs over repository-owned semantic state."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from artifex.compilation._util import copy_json, fingerprint_value, model_fingerprint
from artifex.integrations.contracts import IntegrationError, IntegrationMetadata
from artifex.project.repository import ProjectRepository

PRIMARY_CONTINUITY_ROUTE = ("hermes", "claude", "codex", "hermes")
ALTERNATE_CONTINUITY_ROUTE = ("claude", "hermes", "codex", "claude")


class StatusReader(Protocol):
    """Small adapter seam needed by the continuity harness."""

    @property
    def metadata(self) -> IntegrationMetadata: ...

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]: ...


AdapterFactory = Callable[[], StatusReader]


@dataclass(frozen=True, slots=True)
class ContinuityObservation:
    interface_id: str
    source: str
    semantic_fingerprint: str
    project_model_fingerprint: str
    state_authority: str = "ARTIFEX_PROJECT_REPOSITORY"
    native_memory_required: bool = False

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "interface_id": self.interface_id,
            "source": self.source,
            "semantic_fingerprint": self.semantic_fingerprint,
            "project_model_fingerprint": self.project_model_fingerprint,
            "state_authority": self.state_authority,
            "native_memory_required": self.native_memory_required,
        }


@dataclass(frozen=True, slots=True)
class ContinuityRouteReport:
    route: tuple[str, ...]
    observations: tuple[ContinuityObservation, ...]
    semantic_fingerprint: str
    project_model_fingerprint: str
    passed: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "route": list(self.route),
            "observations": [item.to_dict() for item in self.observations],
            "semantic_fingerprint": self.semantic_fingerprint,
            "project_model_fingerprint": self.project_model_fingerprint,
            "passed": self.passed,
            "native_memory_required": False,
        }


@dataclass(frozen=True, slots=True)
class CrossInterfaceContinuityReport:
    primary: ContinuityRouteReport
    alternate: ContinuityRouteReport

    @property
    def passed(self) -> bool:
        return self.primary.passed and self.alternate.passed

    def to_dict(self) -> dict[str, object]:
        return {
            "criterion": "INT-CONTINUITY",
            "primary": self.primary.to_dict(),
            "alternate": self.alternate.to_dict(),
            "passed": self.passed,
        }


def verify_continuity_route(
    project_root: str | Path,
    route: Sequence[str],
    adapter_factories: Mapping[str, AdapterFactory],
    *,
    expected_project_model_fingerprint: str,
) -> ContinuityRouteReport:
    """Run a route with a fresh adapter at every hop and reject semantic drift."""

    normalized_route = tuple(str(item).strip().casefold() for item in route)
    if len(normalized_route) < 2 or any(not item for item in normalized_route):
        raise IntegrationError("a continuity route requires at least two named interfaces")

    root = Path(project_root).resolve()
    repository = ProjectRepository(root)
    observed_model_fingerprint = model_fingerprint(repository.load().to_dict())
    if observed_model_fingerprint != expected_project_model_fingerprint:
        raise IntegrationError("Project Model fingerprint does not match the continuity contract")

    observations: list[ContinuityObservation] = []
    route_fingerprint: str | None = None
    for interface_id in normalized_route:
        factory = adapter_factories.get(interface_id)
        if factory is None:
            raise IntegrationError(f"continuity adapter is unavailable: {interface_id}")
        adapter = factory()
        observed_id = adapter.metadata.integration_id.strip().casefold()
        if observed_id != interface_id:
            raise IntegrationError(
                f"continuity adapter identity mismatch: expected {interface_id}, got {observed_id}"
            )
        status = adapter.read_project_status(root)
        source = status.get("source")
        state = status.get("state")
        if not isinstance(source, str) or not source or not isinstance(state, Mapping):
            raise IntegrationError(f"{interface_id} returned malformed project status")
        semantic_fingerprint = fingerprint_value(
            {"source": source.replace("\\", "/"), "state": copy_json(dict(state))}
        )
        if route_fingerprint is None:
            route_fingerprint = semantic_fingerprint
        elif semantic_fingerprint != route_fingerprint:
            raise IntegrationError(f"semantic state drifted at the {interface_id} continuity hop")

        current_model_fingerprint = model_fingerprint(repository.load().to_dict())
        if current_model_fingerprint != observed_model_fingerprint:
            raise IntegrationError(
                f"Project Model changed during the {interface_id} continuity hop"
            )
        observations.append(
            ContinuityObservation(
                interface_id,
                source.replace("\\", "/"),
                semantic_fingerprint,
                current_model_fingerprint,
            )
        )

    assert route_fingerprint is not None
    return ContinuityRouteReport(
        normalized_route,
        tuple(observations),
        route_fingerprint,
        observed_model_fingerprint,
    )


def verify_cross_interface_continuity(
    project_root: str | Path,
    adapter_factories: Mapping[str, AdapterFactory],
    *,
    expected_project_model_fingerprint: str,
    alternate_route: Sequence[str] = ALTERNATE_CONTINUITY_ROUTE,
) -> CrossInterfaceContinuityReport:
    """Verify the required M07 route and one explicit supported alternate route."""

    primary = verify_continuity_route(
        project_root,
        PRIMARY_CONTINUITY_ROUTE,
        adapter_factories,
        expected_project_model_fingerprint=expected_project_model_fingerprint,
    )
    alternate = verify_continuity_route(
        project_root,
        alternate_route,
        adapter_factories,
        expected_project_model_fingerprint=expected_project_model_fingerprint,
    )
    return CrossInterfaceContinuityReport(primary, alternate)


__all__ = [
    "ALTERNATE_CONTINUITY_ROUTE",
    "PRIMARY_CONTINUITY_ROUTE",
    "AdapterFactory",
    "ContinuityObservation",
    "ContinuityRouteReport",
    "CrossInterfaceContinuityReport",
    "StatusReader",
    "verify_continuity_route",
    "verify_cross_interface_continuity",
]
