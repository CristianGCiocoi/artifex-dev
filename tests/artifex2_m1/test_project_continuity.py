from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.project import ProjectCatalog, ProjectControlService, ProjectRepository


@pytest.mark.integration
def test_catalog_identity_survives_restart_and_project_move(tmp_path: Path) -> None:
    catalog_path = tmp_path / "instance" / "catalog.sqlite3"
    project_root = tmp_path / "original"
    service = ProjectControlService(catalog_path)
    created = service.create(
        project_root,
        name="Continuity",
        project_id="stable-project-id",
    )
    moved_root = tmp_path / "moved"
    project_root.rename(moved_root)
    ProjectCatalog(catalog_path).move("stable-project-id", moved_root)

    continued = ProjectControlService(catalog_path).continue_by_name("continuity")

    assert continued["project"]["id"] == created["project"]["id"]
    assert continued["semantic_fingerprint"] == created["semantic_fingerprint"]
    assert continued["catalog"]["locations"] == [str(moved_root.resolve())]


@pytest.mark.integration
def test_bootstrap_creates_docs_and_project_dashboard_as_projections(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    created = ProjectControlService(catalog).create(root, name="Baseline")

    document = root / ".artifex" / "docs" / "README.md"
    dashboard_path = root / ".artifex" / "dashboard" / "project.json"
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    assert document.is_file()
    assert dashboard["scope"] == "PROJECT"
    assert dashboard["authoritative"] is False
    assert dashboard["semantic_revision"] == 1
    assert created["execution"] == {
        "automated_scheduler": False,
        "automated_codex_execution": False,
        "fallback": "manual",
        "fallback_mode": "DELIBERATE",
    }

    dashboard_path.write_text('{"forged": true}', encoding="utf-8")
    continued = ProjectControlService(catalog).continue_by_name("Baseline")
    rebuilt = json.loads(dashboard_path.read_text(encoding="utf-8"))
    assert continued["semantic_revision"] == 1
    assert rebuilt["authoritative"] is False
    assert "forged" not in rebuilt


@pytest.mark.conformance
def test_application_exposes_m1_public_composition(tmp_path: Path) -> None:
    root = tmp_path / "project"
    catalog = tmp_path / "catalog.sqlite3"
    application = Application()
    created = application.dispatch(
        OperationRequest(
            "project.create",
            {
                "name": "Public",
                "project_id": "public-id",
                "catalog_path": str(catalog),
            },
            OperationContext(project_root=str(root), actor="test-user"),
        )
    )
    continued = Application().dispatch(
        OperationRequest(
            "project.continue",
            {"name": "Public", "catalog_path": str(catalog)},
            OperationContext(actor="second-client"),
        )
    )

    assert created.ok is True
    assert continued.ok is True
    assert continued.value["project"]["id"] == "public-id"
    assert "project.accept" in Application().operation_names
    platform = Application().dispatch(
        OperationRequest("dashboard.platform", {"catalog_path": str(catalog)})
    )
    assert platform.value["scope"] == "PLATFORM"
    assert platform.value["authoritative"] is False


@pytest.mark.integration
def test_v1_adoption_preserves_model_and_git_history_without_fabricated_runtime(
    tmp_path: Path,
) -> None:
    root = tmp_path / "v1"
    ProjectRepository.initialize(root, project_id="v1-id", name="V1 Project")
    _git(root, "add", ".artifex/project-model.json", ".artifex/audit.jsonl")
    _git(
        root,
        "-c",
        "user.name=ARTIFEX Test",
        "-c",
        "user.email=artifex@example.invalid",
        "commit",
        "-m",
        "v1 baseline",
    )
    head = _git(root, "rev-parse", "HEAD").stdout.strip()
    model_before = (root / ".artifex" / "project-model.json").read_bytes()

    adopted = ProjectControlService(tmp_path / "catalog.sqlite3").adopt(root)

    assert _git(root, "rev-parse", "HEAD").stdout.strip() == head
    assert (root / ".artifex" / "project-model.json").read_bytes() == model_before
    assert adopted["project"]["id"] == "v1-id"
    assert adopted["semantic_revision"] == 1
    assert not (root / ".artifex" / "runstore.sqlite3").exists()


@pytest.mark.conformance
def test_j03_black_box_continue_by_name_survives_process_restart(tmp_path: Path) -> None:
    root = tmp_path / "project"
    catalog = tmp_path / "catalog.sqlite3"
    create = _cli(
        "project",
        "create",
        "Restartable",
        "--project-root",
        str(root),
        "--catalog",
        str(catalog),
        "--project-id",
        "restartable-id",
    )
    continued = _cli(
        "project",
        "continue",
        "Restartable",
        "--catalog",
        str(catalog),
    )

    created_value = json.loads(create.stdout)["value"]
    continued_value = json.loads(continued.stdout)["value"]
    assert continued_value["project"]["id"] == "restartable-id"
    assert continued_value["semantic_fingerprint"] == created_value["semantic_fingerprint"]
    assert str(root) not in continued.args[1:]


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "artifex.cli", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
