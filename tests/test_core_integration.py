from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from artifex.compilation import compile_dashboard, generation_manifest
from artifex.policy import AcceptanceAuthority
from artifex.project import ProjectRepository
from artifex.validation import (
    AcceptanceContract,
    AcceptanceCriterion,
    EvidenceBinding,
    EvidenceEntry,
    EvidenceLedger,
    EvidenceRequirement,
    GateDefinition,
    GateGraph,
    GateLevel,
    GateState,
    MeasuredFact,
    StructuredInspectionValidator,
    ValidationContext,
    ValidatorKind,
)
from artifex.workflow import ExecutionBaseline, StageContract, StageState, WorkflowEngine


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.mark.integration
def test_project_workflow_evidence_gate_and_dashboard_survive_reopen(tmp_path: Path) -> None:
    root = tmp_path / "integrated-project"
    repository = ProjectRepository.initialize(root, project_id="INT-DEMO", name="Integration")
    _git(root, "config", "user.name", "ARTIFEX Test")
    _git(root, "config", "user.email", "artifex-test@local.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    model = repository.establish_baseline()
    assert model.git.baseline_commit is not None
    model_fingerprint = str(generation_manifest(model.to_dict())["project_model_fingerprint"])

    acceptance = AcceptanceContract(
        contract_id="VAL-INT-DEMO",
        deliverable="integrated artifact",
        requirements=("REQ-F-053",),
        interfaces=("Application API",),
        invariants=("INV-017",),
        criteria=(AcceptanceCriterion("AC-INT-01", "integrated path passes"),),
        validators=("VAL-INT",),
        base_commit=model.git.baseline_commit,
        project_model_fingerprint=model_fingerprint,
    ).start()
    binding = EvidenceBinding(
        acceptance.base_commit,
        acceptance.fingerprint,
        (acceptance.project_model_fingerprint,),
    )

    stage = StageContract(
        stage_id="STG-INTEGRATE",
        requires=("project-model",),
        produces=("integrated-artifact",),
        capabilities=frozenset({"repository_read"}),
        validators=("VAL-INT",),
    )
    workflow = WorkflowEngine()
    workflow.register(stage)
    workflow.transition(stage.stage_id, StageState.READY)
    workflow.start(
        stage.stage_id,
        available_inputs={"project-model"},
        available_capabilities={"repository_read"},
        baseline=ExecutionBaseline(
            binding.base_commit, binding.contract_hash, binding.project_model_fingerprints[0]
        ),
    )
    workflow.claim_complete(stage.stage_id, outputs={"integrated-artifact"})
    workflow.transition(stage.stage_id, StageState.VALIDATING)

    result = StructuredInspectionValidator("VAL-INT", "1").validate(
        ValidationContext("integrated path", "worker", binding),
        inspector_id="independent-reviewer",
        passed=True,
        facts=(MeasuredFact("components", 4),),
    )
    entry = EvidenceEntry.create(
        "EVD-INT-DEMO", result, binding, recorded_at=datetime(2026, 8, 21, tzinfo=UTC)
    )
    journal = root / ".artifex" / "validation" / "evidence" / "ledger.jsonl"
    ledger = EvidenceLedger({"VAL-INT": "1"}, journal_path=journal)
    ledger.append(entry)
    gate = GateGraph(
        (
            GateDefinition(
                "G-INT-DEMO",
                GateLevel.TASK,
                (
                    EvidenceRequirement(
                        "integrated path",
                        frozenset({"VAL-INT"}),
                        frozenset({ValidatorKind.STRUCTURED_INSPECTION}),
                        require_independent=True,
                    ),
                ),
            ),
        )
    )
    assert (
        gate.evaluate(
            "G-INT-DEMO", ledger=ledger, binding=binding, authority=AcceptanceAuthority.CORE
        )
        is GateState.PASS
    )
    workflow.transition(stage.stage_id, StageState.ACCEPTED, authority=AcceptanceAuthority.CORE)

    reopened_model = ProjectRepository(root).load()
    reopened_ledger = EvidenceLedger({"VAL-INT": "1"}, journal_path=journal)
    assert (
        generation_manifest(reopened_model.to_dict())["project_model_fingerprint"]
        == model_fingerprint
    )
    assert reopened_ledger.entries == (entry,)
    dashboard = compile_dashboard(
        reopened_model.to_dict(),
        {
            "milestones": [
                {"id": "M-INTEGRATION", "state": "ACCEPTED", "completed_tasks": 1, "total_tasks": 1}
            ],
            "gates": [{"id": "G-INT-DEMO", "state": "PASS"}],
            "evidence": [{"id": entry.evidence_id, "state": "CURRENT"}],
            "tests": {"suites": [{"id": "integration", "state": "PASS"}]},
            "traceability": {"requirements_total": 1, "requirements_traced": 1},
        },
    )
    assert "Generated non-canonical view" in dashboard
    assert "PASS: 1" in dashboard
