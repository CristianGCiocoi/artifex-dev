from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from artifex.cli import app
from artifex.distribution import start_beginner_journey
from artifex.project import ProjectRepository


@pytest.mark.integration
def test_beginner_journey_creates_canonical_project_without_manual_configuration(
    tmp_path: Path,
) -> None:
    root = tmp_path / "weather-station"
    result = start_beginner_journey(root, "I want to build a weather station")
    assert result.manual_configuration_required is False
    assert result.canonical_authority == ".artifex/project-model.json"
    assert (root / ".git").is_dir()
    assert not list(root.rglob("*.yaml"))
    assert not list(root.rglob("*.yml"))
    model = ProjectRepository(root).load()
    assert model.project.description == "I want to build a weather station"
    assert model.project.id == "weather-station"
    assert model.project.workflow_depth.value == "STANDARD"


@pytest.mark.integration
def test_beginner_cli_accepts_plain_language_and_preserves_core_authority(tmp_path: Path) -> None:
    root = tmp_path / "plain-language-app"
    result = CliRunner().invoke(
        app,
        [
            "start",
            "I want to build X",
            "--project-root",
            str(root),
            "--project-name",
            "Plain Language App",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["value"]["canonical_authority"] == ".artifex/project-model.json"
    assert payload["value"]["manual_configuration_required"] is False
    assert payload["value"]["presentation"]["mode"] == "BEGINNER"
    assert ProjectRepository(root).load().project.id == "plain-language-app"


@pytest.mark.integration
def test_reentry_uses_existing_project_model_instead_of_hidden_session_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "persistent"
    first = start_beginner_journey(root, "I want to build one")
    second = start_beginner_journey(root, "Continue with a new conversational request")
    assert second.project_id == first.project_id
    assert ProjectRepository(root).load().project.description == "I want to build one"
