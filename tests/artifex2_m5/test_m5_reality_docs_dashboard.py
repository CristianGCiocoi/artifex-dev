from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.compilation._util import fingerprint_value
from artifex.documentation import DocumentationLifecycle
from artifex.project import (
    ProjectAuthority,
    ProjectControlService,
    ProjectModel,
    ProjectRepository,
)
from artifex.reality import (
    CallbackObserver,
    FileFingerprintObserver,
    GitStateObserver,
    Observation,
    ObservationStatus,
    ObserverKind,
    RealityReconciliationService,
)

_HASH = "a" * 64


def _accepted_architecture_model(root: Path) -> dict[str, object]:
    model = ProjectAuthority(root).current().model.to_dict()
    model["artifacts"] = [
        {
            "id": "ART-ARCH",
            "type": "architecture",
            "path": "architecture.json",
            "status": "ACCEPTED",
            "fingerprint": _HASH,
            "depends_on": [],
            "provenance": None,
            "metadata": {"understanding": {"architecture": {"style": "modular"}}},
        }
    ]
    return model


@pytest.mark.integration
def test_j08_accepted_change_marks_affected_docs_stale_then_regenerates_selectively(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    service = ProjectControlService(catalog)
    service.create(root, name="Documented", project_id="project-docs")

    baseline = service.documentation_status("Documented")
    assert {item["state"] for item in baseline["documents"]} == {"CURRENT"}

    proposal = service.propose(
        "Documented",
        _accepted_architecture_model(root),
        expected_revision=1,
        actor="designer",
    )
    accepted = service.accept(
        "Documented", proposal.id, expected_revision=1, actor="project-authority"
    )
    states = {
        item["name"]: item["state"]
        for item in accepted["project_dashboard"]["documentation"]["documents"]
    }
    assert states["ARCHITECTURE.md"] == "STALE"
    assert states["DEVELOPER_GUIDE.md"] == "STALE"
    assert states["USER_GUIDE.md"] == "CURRENT"

    regenerated = service.regenerate_documentation(
        "Documented", ("ARCHITECTURE.md",)
    )
    regenerated_states = {
        item["name"]: item["state"] for item in regenerated["documents"]
    }
    assert regenerated_states["ARCHITECTURE.md"] == "CURRENT"
    assert regenerated_states["DEVELOPER_GUIDE.md"] == "STALE"

    complete = service.regenerate_documentation("Documented")
    assert {item["state"] for item in complete["documents"]} == {"CURRENT"}
    assert complete["project_dashboard"]["semantic_revision"] == 2
    assert complete["project_dashboard"]["documentation"]["state"] == "CURRENT"


@pytest.mark.adversarial
def test_document_tampering_is_stale_projection_not_semantic_truth(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    service = ProjectControlService(catalog)
    service.create(root, name="Tamper", project_id="project-tamper")
    before = ProjectAuthority(root).current()

    (root / ".artifex/docs/USER_GUIDE.md").write_text("forged\n", encoding="utf-8")
    status = service.documentation_status("Tamper")
    user_guide = next(item for item in status["documents"] if item["name"] == "USER_GUIDE.md")

    assert user_guide["state"] == "STALE"
    assert ProjectAuthority(root).current() == before


@pytest.mark.conformance
def test_j14_external_project_model_edit_becomes_observation_divergence_and_proposal(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    service = ProjectControlService(catalog)
    service.create(root, name="Reality", project_id="project-reality")
    accepted = ProjectAuthority(root).current()
    changed = accepted.model.to_dict()
    changed["project"]["description"] = "external edit"
    ProjectRepository(root).save(ProjectModel.from_dict(changed))

    result = service.observe_external("Reality", actor="git-observer")

    assert result["semantic_revision"] == 1
    assert result["semantic_revision_unchanged"] is True
    assert result["observation"]["status"] == "DIVERGED"
    assert result["observation"]["semantic_acceptance"] is False
    assert result["divergence"]["status"] == "PROPOSED"
    assert result["proposal_id"]
    assert ProjectAuthority(root).current() == accepted
    dashboard = service.project_dashboard("Reality")
    assert dashboard["semantic_revision"] == 1
    assert dashboard["observed_reality"]["open_divergence_count"] == 1

    accepted_result = service.accept(
        "Reality",
        str(result["proposal_id"]),
        expected_revision=1,
        actor="project-authority",
    )
    reconciled = service.reality_state("Reality")
    assert accepted_result["semantic_revision"] == 2
    assert reconciled["open_divergence_count"] == 0
    assert reconciled["divergences"][0]["status"] == "RESOLVED"


@pytest.mark.architecture
@pytest.mark.parametrize(
    "kind",
    [
        ObserverKind.GIT,
        ObserverKind.FILE,
        ObserverKind.TEST,
        ObserverKind.PROVIDER,
        ObserverKind.RUNTIME,
        ObserverKind.SERVICE,
    ],
)
def test_observer_interfaces_record_sourced_facts_without_acceptance(
    tmp_path: Path, kind: ObserverKind
) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project", name="Observers")
    authority = ProjectAuthority.bootstrap(repository)
    before = authority.current()
    service = RealityReconciliationService(tmp_path)
    observation = service.observe_adapter(
        CallbackObserver(
            kind,
            lambda: (f"{kind.value.lower()}://health", ObservationStatus.MATCH, _HASH),
        ),
        actor="observer-adapter",
        expected_fingerprint=_HASH,
    )

    assert observation.observer_kind is kind
    assert observation.to_dict()["semantic_acceptance"] is False
    assert authority.current() == before


@pytest.mark.integration
def test_built_in_file_and_git_observers_measure_real_project_state(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project", name="Measured")
    authority = ProjectAuthority.bootstrap(repository)
    service = RealityReconciliationService(tmp_path)
    model_digest = repository.store.fingerprint(".artifex/project-model.json")

    file_observation = service.observe_adapter(
        FileFingerprintObserver(tmp_path, ".artifex/project-model.json", model_digest),
        actor="file-observer",
        expected_fingerprint=model_digest,
    )
    git_digest = fingerprint_value(repository.git.inspect().to_dict())
    git_observation = service.observe_adapter(
        GitStateObserver(tmp_path, git_digest),
        actor="git-observer",
        expected_fingerprint=git_digest,
    )

    assert file_observation.status is ObservationStatus.MATCH
    assert git_observation.status is ObservationStatus.MATCH
    assert authority.current().number == 1


def test_observation_rejects_secret_bearing_source_reference() -> None:
    with pytest.raises(ValueError, match="credential material"):
        Observation(
            observation_id="observation-1",
            project_id="project",
            observer_kind=ObserverKind.PROVIDER,
            source_ref="provider://health?token=super-secret-value",
            status=ObservationStatus.MATCH,
            observed_fingerprint=_HASH,
            expected_fingerprint=_HASH,
            observed_at="2026-08-27T00:00:00Z",
            actor="observer",
        )


@pytest.mark.conformance
def test_public_operations_and_dashboard_are_authoritative_store_projections(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    application = Application()
    created = application.dispatch(
        OperationRequest(
            "project.create",
            {
                "name": "Public M5",
                "project_id": "public-m5",
                "catalog_path": str(catalog),
            },
            OperationContext(project_root=str(root), actor="user"),
        )
    )
    assert created.ok, created.to_dict()
    (root / ".artifex/dashboard/project.json").write_text(
        json.dumps({"forged": True}), encoding="utf-8"
    )

    project = application.dispatch(
        OperationRequest(
            "dashboard.project", {"name": "Public M5", "catalog_path": str(catalog)}
        )
    )
    docs = application.dispatch(
        OperationRequest(
            "documentation.status", {"name": "Public M5", "catalog_path": str(catalog)}
        )
    )
    reality = application.dispatch(
        OperationRequest(
            "reality.state", {"name": "Public M5", "catalog_path": str(catalog)}
        )
    )
    platform = application.dispatch(
        OperationRequest("dashboard.platform", {"catalog_path": str(catalog)})
    )

    assert project.ok and docs.ok and reality.ok and platform.ok
    assert project.value["authoritative"] is False
    assert project.value["semantic_revision"] == 1
    assert "forged" not in project.value
    assert docs.value["derived_from"] == "PROJECT_AUTHORITY"
    assert reality.value["derived_from"] == ["PROJECT_AUTHORITY", "OBSERVATION_STORE"]
    assert platform.value["projects"][0]["semantic_fingerprint"] == project.value[
        "semantic_fingerprint"
    ]
    assert {
        "reality.state",
        "documentation.status",
        "documentation.regenerate",
        "dashboard.project",
        "dashboard.platform",
    } <= set(application.operation_names)


def test_manifest_is_rebuildable_and_never_claims_authority(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project", name="Manifest")
    revision = ProjectAuthority.bootstrap(repository).current()
    lifecycle = DocumentationLifecycle(tmp_path)
    lifecycle.establish_baseline(revision)
    manifest = json.loads(
        (tmp_path / ".artifex/docs/manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["authoritative"] is False
    assert manifest["derived_from"] == "PROJECT_AUTHORITY"
    (tmp_path / ".artifex/docs/manifest.json").unlink()
    lifecycle.establish_baseline(revision)
    assert {item.state.value for item in lifecycle.status(revision)} == {"CURRENT"}


@pytest.mark.conformance
def test_j08_public_cli_reads_docs_and_project_dashboard_after_fresh_create(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    catalog = tmp_path / "catalog.sqlite3"
    _cli(
        "project",
        "create",
        "CLI M5",
        "--project-root",
        str(root),
        "--catalog",
        str(catalog),
        "--project-id",
        "cli-m5",
    )
    docs = _cli("documentation", "status", "CLI M5", "--catalog", str(catalog))
    dashboard = _cli("dashboard", "project", "CLI M5", "--catalog", str(catalog))

    docs_value = json.loads(docs.stdout)["value"]
    dashboard_value = json.loads(dashboard.stdout)["value"]
    assert {item["state"] for item in docs_value["documents"]} == {"CURRENT"}
    assert dashboard_value["semantic_revision"] == 1
    assert dashboard_value["authoritative"] is False


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "artifex.cli", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
