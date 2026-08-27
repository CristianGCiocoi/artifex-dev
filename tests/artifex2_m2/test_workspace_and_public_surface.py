from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.project import ProjectAuthority, ProjectRepository
from artifex.runtime import ExecutionEnvelope, ManagedRuntimeService, PromotionConflictError


def _envelope() -> ExecutionEnvelope:
    return ExecutionEnvelope(
        envelope_id="envelope-j15",
        version=1,
        project_id="project-j15",
        objective="prove guarded isolated promotion",
        baseline_revision=1,
        actor_id="architect",
        allowed_paths=(".artifex/project-model.json",),
        allowed_capabilities=("filesystem:workspace",),
        required_gates=("validation", "acceptance", "project-authority"),
        max_attempts=1,
        recovery_policy="RECONCILE_BEFORE_RETRY",
    )


@pytest.mark.integration
def test_j15_parallel_workspace_promotion_detects_stale_baseline(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    repository = ProjectRepository.initialize(
        project_root, project_id="project-j15", name="J15"
    )
    authority = ProjectAuthority.bootstrap(repository)
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3")
    service.bootstrap_run(
        _envelope(),
        workstream_id="workstream-j15",
        run_id="run-j15",
        project_job_id="job-a",
        attempt_id="attempt-a",
        purpose="workspace A",
        actor_id="coordinator",
    )
    service.coordinator.create_project_job(
        "job-b", "run-j15", "workspace B", actor_id="coordinator"
    )
    service.coordinator.create_attempt("attempt-b", "job-b", actor_id="coordinator")
    service.coordinator.start_attempt("attempt-b", actor_id="coordinator")
    workspace_a = service.create_workspace(
        "workspace-a", "attempt-a", project_root, 1, actor_id="coordinator"
    )
    workspace_b = service.create_workspace(
        "workspace-b", "attempt-b", project_root, 1, actor_id="coordinator"
    )
    assert workspace_a != workspace_b
    assert workspace_a.is_dir()
    assert workspace_b.is_dir()

    baseline = authority.current().model
    model_a = replace(
        baseline, project=replace(baseline.project, description="workspace A accepted")
    )
    model_b = replace(
        baseline, project=replace(baseline.project, description="workspace B stale")
    )
    service.finish("attempt-a", "A passed", actor_id="worker-a")
    decision_a = service.accept(
        "job-a", evidence_valid=True, actor_id="acceptance", reason="A evidence valid"
    )
    assert service.promote_workspace(
        "workspace-a", model_a, decision_a, actor_id="project-authority"
    ) == 2

    service.finish("attempt-b", "B passed", actor_id="worker-b")
    decision_b = service.accept(
        "job-b", evidence_valid=True, actor_id="acceptance", reason="B evidence valid"
    )
    with pytest.raises(PromotionConflictError, match="baseline 1 is stale"):
        service.promote_workspace(
            "workspace-b", model_b, decision_b, actor_id="project-authority"
        )

    assert ProjectAuthority(project_root).current().model.project.description == (
        "workspace A accepted"
    )
    assert service.store.get("workspaces", "workspace_id", "workspace-a")["state"] == (
        "PROMOTED"
    )
    assert service.store.get("workspaces", "workspace_id", "workspace-b")["state"] == (
        "PROMOTION_CONFLICT"
    )
    jobs = {
        job["project_job_id"]: job["state"]
        for job in service.status("run-j15")["project_jobs"]
    }
    assert jobs == {"job-a": "ACCEPTED", "job-b": "PROMOTION_CONFLICT"}


@pytest.mark.conformance
def test_runtime_public_operations_recover_state_without_provider_dispatch(tmp_path: Path) -> None:
    store = str(tmp_path / "runstore.sqlite3")
    common = {"store_path": store, "service_id": "managed-runtime"}
    bootstrap = Application().dispatch(
        OperationRequest(
            "runtime.bootstrap",
            {
                **common,
                "envelope": _envelope().to_dict(),
                "workstream_id": "public-workstream",
                "run_id": "public-run",
                "project_job_id": "public-job",
                "attempt_id": "public-attempt",
                "purpose": "public durable outcome",
            },
            OperationContext(actor="operator"),
        )
    )
    assert bootstrap.value["provider_dispatch"] is False

    Application().dispatch(
        OperationRequest(
            "runtime.attempt.finish",
            {**common, "attempt_id": "public-attempt", "result_claim": "passed"},
            OperationContext(actor="worker"),
        )
    )
    status = Application().dispatch(
        OperationRequest(
            "runtime.status",
            {**common, "run_id": "public-run"},
            OperationContext(actor="observer"),
        )
    )
    assert status.value["project_jobs"][0]["state"] == "FINISHED"
    assert status.value["acceptance_decisions"] == []
    assert status.value["projection"]["authoritative"] is False
    assert status.value["automated_codex_execution"] is False
