from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from artifex.compilation._util import model_fingerprint
from artifex.integrations.claude import ClaudeDetection, ClaudeIntegration
from artifex.integrations.codex import CodexDetection, CodexIntegration
from artifex.integrations.continuity import (
    ALTERNATE_CONTINUITY_ROUTE,
    PRIMARY_CONTINUITY_ROUTE,
    verify_continuity_route,
    verify_cross_interface_continuity,
)
from artifex.integrations.contracts import IntegrationError
from artifex.integrations.hermes import HermesIntegration
from artifex.project.repository import ProjectRepository


def _factories() -> Mapping[str, Any]:
    return {
        "hermes": HermesIntegration.simulated,
        "claude": lambda: ClaudeIntegration(
            ClaudeDetection(True, "claude", "1.2.3", "deterministic fixture")
        ),
        "codex": lambda: CodexIntegration(CodexDetection(True, "codex", "1.2.3", "codex 1.2.3")),
    }


@pytest.mark.integration
@pytest.mark.conformance
def test_m07_t10_required_and_alternate_routes_preserve_repository_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "portable-project"
    repository = ProjectRepository.initialize(
        root,
        project_id="PRJ-CONTINUITY",
        name="Cross-interface continuity",
    )
    expected_model_fingerprint = model_fingerprint(repository.load().to_dict())

    report = verify_cross_interface_continuity(
        root,
        _factories(),
        expected_project_model_fingerprint=expected_model_fingerprint,
    )

    assert report.passed
    assert report.primary.route == PRIMARY_CONTINUITY_ROUTE
    assert report.alternate.route == ALTERNATE_CONTINUITY_ROUTE
    for route in (report.primary, report.alternate):
        assert len({item.semantic_fingerprint for item in route.observations}) == 1
        assert len({item.project_model_fingerprint for item in route.observations}) == 1
        assert all(not item.native_memory_required for item in route.observations)
        assert all(
            item.state_authority == "ARTIFEX_PROJECT_REPOSITORY" for item in route.observations
        )
    assert report.to_dict()["criterion"] == "INT-CONTINUITY"


@pytest.mark.adversarial
def test_continuity_fails_closed_on_contract_identity_or_semantic_drift(tmp_path: Path) -> None:
    root = tmp_path / "project"
    repository = ProjectRepository.initialize(root, project_id="PRJ-DRIFT", name="Drift proof")
    expected = model_fingerprint(repository.load().to_dict())

    with pytest.raises(IntegrationError, match="fingerprint"):
        verify_continuity_route(
            root,
            ("hermes", "codex"),
            _factories(),
            expected_project_model_fingerprint="0" * 64,
        )

    factories = dict(_factories())
    factories["claude"] = lambda: _DriftingReader()
    with pytest.raises(IntegrationError, match="drifted"):
        verify_continuity_route(
            root,
            ("hermes", "claude"),
            factories,
            expected_project_model_fingerprint=expected,
        )


class _DriftingReader:
    def __init__(self) -> None:
        self._delegate = ClaudeIntegration(ClaudeDetection(False))

    @property
    def metadata(self) -> Any:
        return self._delegate.metadata

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]:
        status = dict(self._delegate.read_project_status(project_root))
        state = dict(status["state"])
        state["vendor_memory"] = "must never become canonical"
        status["state"] = state
        return status
