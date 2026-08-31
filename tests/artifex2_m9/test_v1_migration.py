from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.distribution.approvals import ApprovalStore
from artifex.migration import V1MigrationService
from artifex.project import ProjectRepository


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.strip()


def _v1_project(root: Path) -> Path:
    ProjectRepository.initialize(root, project_id="v1-id", name="V1 Project")
    _git(root, "add", ".artifex/project-model.json", ".artifex/audit.jsonl")
    _git(
        root,
        "-c",
        "user.name=ARTIFEX Migration Test",
        "-c",
        "user.email=artifex-migration@example.invalid",
        "commit",
        "-m",
        "V1 baseline",
    )
    return root


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and ".git" not in path.relative_to(root).parts
    }


def _service(tmp_path: Path) -> tuple[V1MigrationService, Path, Path, Path, Path]:
    project = _v1_project(tmp_path / "project")
    catalog = tmp_path / "instance" / "catalog.sqlite3"
    runstore = tmp_path / "instance" / "runstore.sqlite3"
    state = tmp_path / "instance" / "migration"
    service = V1MigrationService(
        project,
        catalog_path=catalog,
        runstore_path=runstore,
        state_root=state,
        approval_store=ApprovalStore(tmp_path / "approvals"),
    )
    return service, project, catalog, runstore, state


def _apply(service: V1MigrationService) -> dict[str, object]:
    plan = service.plan()
    token = plan["decision"]["confirmation_token"]
    assert isinstance(token, str)
    return service.apply(token)


def _dispatch(operation: str, arguments: dict[str, object]) -> dict[str, object]:
    result = Application().dispatch(
        OperationRequest(operation, arguments, OperationContext(actor="m9-test"))
    )
    assert result.ok, result.to_dict()
    assert result.value is not None
    return dict(result.value)


def _envelope() -> dict[str, object]:
    return {
        "envelope_id": "m9-first-envelope",
        "version": 1,
        "project_id": "v1-id",
        "objective": "First new ARTIFEX 2.0 Run after V1 migration",
        "baseline_revision": 1,
        "actor_id": "architect",
        "allowed_paths": [".artifex/project-model.json"],
        "allowed_capabilities": ["filesystem:workspace"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
    }


@pytest.mark.integration
def test_inspect_and_dry_run_are_read_only_and_fail_closed(tmp_path: Path) -> None:
    service, project, catalog, runstore, state = _service(tmp_path)
    before = _files(project)
    head = _git(project, "rev-parse", "HEAD")

    inspection = service.inspect()
    plan = service.plan()

    assert inspection["bounded_read_only"] is True
    assert inspection["source"]["git_clean"] is True
    assert inspection["target"]["already_migrated"] is False
    assert plan["operation"] == "DRY_RUN"
    assert plan["decision"]["approval_required"] is True
    assert _files(project) == before
    assert _git(project, "rev-parse", "HEAD") == head
    assert not catalog.exists()
    assert not runstore.exists()
    assert not state.exists()

    with pytest.raises(PermissionError, match="approval"):
        service.apply(None)


@pytest.mark.integration
def test_migration_preserves_semantics_and_exact_rollback(tmp_path: Path) -> None:
    service, project, catalog, runstore, _ = _service(tmp_path)
    before = _files(project)
    model_before = (project / ".artifex/project-model.json").read_bytes()
    head_before = _git(project, "rev-parse", "HEAD")

    applied = _apply(service)
    validation = applied["validation"]

    assert applied["status"] == "PASS"
    assert validation["migration_validation"] == "PASS"
    assert validation["first_new_run"]["status"] == "PENDING"
    assert all(validation["checks"].values())
    assert (project / ".artifex/project-model.json").read_bytes() == model_before
    assert _git(project, "rev-parse", "HEAD") == head_before
    assert catalog.is_file()
    assert runstore.is_file()
    record = json.loads(Path(str(applied["record_path"])).read_text(encoding="utf-8"))
    preservation = record["post_migration"]["preservation_inventory"]
    assert preservation["changed"] == []
    assert preservation["missing"] == []
    assert preservation["extended"] == ["audit.jsonl"]
    assert record["validation"]["initial_outcome"] == "PASS"
    assert "EMPTY_RUNSTORE_INITIALIZED" in record["post_migration"][
        "target_runtime_bootstrap_actions"
    ]

    rollback_plan = service.rollback_plan(str(applied["record_path"]))
    token = rollback_plan["decision"]["confirmation_token"]
    rollback = service.rollback(str(applied["record_path"]), str(token))

    assert rollback["status"] == "PASS"
    assert all(rollback["checks"].values())
    assert _files(project) == before
    assert _git(project, "status", "--porcelain", "--untracked-files=all") == ""
    assert not catalog.exists()
    assert not runstore.exists()


@pytest.mark.integration
def test_first_new_run_is_post_migration_and_rollback_refuses_drift(tmp_path: Path) -> None:
    service, project, _, runstore, _ = _service(tmp_path)
    applied = _apply(service)
    common: dict[str, object] = {
        "store_path": str(runstore),
        "service_id": "m9-managed-service",
    }
    _dispatch(
        "runtime.bootstrap",
        {
            **common,
            "envelope": _envelope(),
            "workstream_id": "m9-first-workstream",
            "run_id": "m9-first-run",
            "project_job_id": "m9-first-job",
            "attempt_id": "m9-first-attempt",
            "purpose": "First new 2.0 Run",
        },
    )
    _dispatch(
        "runtime.attempt.finish",
        {
            **common,
            "attempt_id": "m9-first-attempt",
            "result_claim": "post-migration validation passed",
        },
    )
    _dispatch(
        "runtime.accept",
        {
            **common,
            "project_job_id": "m9-first-job",
            "evidence_valid": True,
            "reason": "M9 acceptance authority evidence",
        },
    )

    validation = service.validate(str(applied["record_path"]))

    assert validation["migration_validation"] == "PASS"
    assert validation["first_new_run"]["status"] == "PASS"
    assert validation["activation_state"] == "ACTIVE"
    assert (project / ".artifex/project-model.json").is_file()

    rollback_plan = service.rollback_plan(str(applied["record_path"]))
    with pytest.raises(ValueError, match="Catalog or RunStore changed"):
        service.rollback(
            str(applied["record_path"]),
            str(rollback_plan["decision"]["confirmation_token"]),
        )


def test_public_application_surface_exposes_m9_operations(tmp_path: Path) -> None:
    service, project, catalog, runstore, state = _service(tmp_path)
    del service
    common: dict[str, object] = {
        "project_root": str(project),
        "catalog_path": str(catalog),
        "runstore_path": str(runstore),
        "state_root": str(state),
    }
    operations = set(Application().operation_names)
    assert {
        "migration.inspect",
        "migration.plan",
        "migration.apply",
        "migration.validate",
        "migration.rollback.plan",
        "migration.rollback",
    } <= operations
    inspection = _dispatch("migration.inspect", common)
    assert inspection["operation"] == "INSPECT"
    assert json.loads(json.dumps(inspection))["source"]["project_id"] == "v1-id"


@pytest.mark.integration
def test_legacy_provider_setup_is_preserved_and_freshly_revalidated(tmp_path: Path) -> None:
    service, project, _, _, _ = _service(tmp_path)
    setup = project / ".artifex/integrations.json"
    setup.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "enabled": ["manual"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _git(project, "add", ".artifex/integrations.json")
    _git(
        project,
        "-c",
        "user.name=ARTIFEX Migration Test",
        "-c",
        "user.email=artifex-migration@example.invalid",
        "commit",
        "-m",
        "Persist legacy provider setup",
    )

    inspection = service.inspect()
    applied = _apply(service)
    record = json.loads(Path(str(applied["record_path"])).read_text(encoding="utf-8"))
    provider = record["post_migration"]["provider_setup"]

    assert inspection["provider_setup"]["legacy_persisted_setup_detected"] is True
    assert provider["source_schema"] == "1.0"
    assert provider["fresh_runtime_consumed"] is True
    assert provider["readiness_revalidation"] == "PERFORMED"
    assert provider["certification_carried_forward"] is False
    assert setup.is_file()
