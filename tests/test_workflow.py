from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from artifex.policy import AcceptanceAuthority, InstructionTrust
from artifex.workflow import (
    ExecutionBaseline,
    ExecutionStatus,
    LivenessGuard,
    LivenessPolicy,
    LivenessStatus,
    LivenessViolation,
    StageContract,
    StageState,
    StageTransition,
    WorkflowEngine,
    WorkflowError,
    classify_execution_result,
    require_instruction_authority,
)


def _baseline(suffix: str = "current") -> ExecutionBaseline:
    return ExecutionBaseline(f"commit-{suffix}", f"contract-{suffix}", f"model-{suffix}")


def _contract(**changes: object) -> StageContract:
    values: dict[str, object] = {
        "stage_id": "STG-BUILD",
        "requires": ("design",),
        "produces": ("artifact",),
        "capabilities": frozenset({"repository_write"}),
        "validators": ("VAL-TESTS",),
    }
    values.update(changes)
    return StageContract(**values)  # type: ignore[arg-type]


@pytest.mark.unit
def test_stage_contract_and_engine_enforce_claim_vs_acceptance() -> None:
    contract = _contract()
    assert contract.fingerprint == _contract().fingerprint
    engine = WorkflowEngine()
    assert engine.register(contract).state is StageState.PENDING
    engine.transition(contract.stage_id, StageState.READY)
    running = engine.start(
        contract.stage_id,
        available_inputs={"design"},
        available_capabilities={"repository_write"},
        baseline=_baseline(),
    )
    assert running.baseline == _baseline()

    with pytest.raises(WorkflowError, match="missing outputs"):
        engine.claim_complete(contract.stage_id, outputs=set())
    claimed = engine.claim_complete(contract.stage_id, outputs={"artifact", "log"})
    assert claimed.state is StageState.CLAIMED_COMPLETE
    assert claimed.outputs == frozenset({"artifact", "log"})
    engine.transition(contract.stage_id, StageState.VALIDATING)
    with pytest.raises(WorkflowError, match="only Core"):
        engine.transition(contract.stage_id, StageState.ACCEPTED)
    accepted = engine.transition(
        contract.stage_id, StageState.ACCEPTED, authority=AcceptanceAuthority.CORE
    )
    assert accepted.state is StageState.ACCEPTED


@pytest.mark.unit
def test_engine_rejects_unknown_duplicate_invalid_and_unready_stages() -> None:
    engine = WorkflowEngine()
    engine.register(_contract())
    with pytest.raises(WorkflowError, match="already registered"):
        engine.register(_contract())
    with pytest.raises(WorkflowError, match="unknown stage"):
        engine.get("STG-MISSING")
    with pytest.raises(WorkflowError, match="not permitted"):
        engine.transition("STG-BUILD", StageState.RUNNING)
    engine.transition("STG-BUILD", StageState.READY)
    with pytest.raises(WorkflowError, match="prerequisites"):
        engine.start(
            "STG-BUILD",
            available_inputs=set(),
            available_capabilities=set(),
            baseline=_baseline(),
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"stage_id": ""}, "stage_id"),
        ({"validators": ()}, "validator"),
        ({"requires": ("x", "x")}, "duplicate stage requirements"),
        ({"produces": ("x", "x")}, "duplicate stage outputs"),
        (
            {
                "transitions": (
                    StageTransition(StageState.PENDING, StageState.READY),
                    StageTransition(StageState.PENDING, StageState.READY),
                )
            },
            "duplicate transitions",
        ),
    ],
)
def test_invalid_stage_contracts_fail(changes: dict[str, object], message: str) -> None:
    with pytest.raises(WorkflowError, match=message):
        _contract(**changes)


@pytest.mark.unit
def test_transition_and_liveness_policy_validation() -> None:
    with pytest.raises(WorkflowError, match="change state"):
        StageTransition(StageState.READY, StageState.READY)
    with pytest.raises(WorkflowError, match="positive"):
        LivenessPolicy(max_stage_visits=0)
    with pytest.raises(WorkflowError, match="positive"):
        LivenessPolicy(max_stall_seconds=0)
    with pytest.raises(WorkflowError, match="normalized"):
        ExecutionBaseline(" commit", "contract", "model")


@pytest.mark.unit
def test_execution_baseline_returns_rebase_required_for_stale_worker() -> None:
    current = _baseline()
    assert (
        classify_execution_result(current, current, ExecutionStatus.SUCCESS)
        is ExecutionStatus.SUCCESS
    )
    assert (
        classify_execution_result(_baseline("old"), current, ExecutionStatus.SUCCESS)
        is ExecutionStatus.REBASE_REQUIRED
    )


@pytest.mark.unit
def test_liveness_guard_detects_progress_no_progress_revisit_and_order() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    guard = LivenessGuard(
        LivenessPolicy(max_stage_visits=4, max_no_progress_observations=3, max_stall_seconds=60)
    )
    assert guard.observe("STG-X", "a", at=start).status is LivenessStatus.PROGRESS
    report = guard.observe("STG-X", "a", at=start + timedelta(seconds=1))
    assert report.status is LivenessStatus.NO_PROGRESS
    assert report.no_progress_observations == 1
    assert (
        guard.observe("STG-X", "b", at=start + timedelta(seconds=2)).status
        is LivenessStatus.PROGRESS
    )
    guard.observe("STG-X", "b", at=start + timedelta(seconds=3))
    with pytest.raises(LivenessViolation, match="REVISIT_LIMIT"):
        guard.observe("STG-X", "c", at=start + timedelta(seconds=4))

    with pytest.raises(WorkflowError, match="chronological"):
        guard.observe("STG-Y", "a", at=start)
        guard.observe("STG-Y", "a", at=start - timedelta(seconds=1))


@pytest.mark.unit
def test_liveness_guard_detects_no_progress_and_stall() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    no_progress = LivenessGuard(
        LivenessPolicy(max_stage_visits=10, max_no_progress_observations=2, max_stall_seconds=60)
    )
    no_progress.observe("STG-X", "a", at=start)
    no_progress.observe("STG-X", "a", at=start + timedelta(seconds=1))
    with pytest.raises(LivenessViolation, match="NO_PROGRESS_LIMIT"):
        no_progress.observe("STG-X", "a", at=start + timedelta(seconds=2))

    stalled = LivenessGuard(LivenessPolicy(max_stall_seconds=5))
    stalled.observe("STG-X", "a", at=start)
    with pytest.raises(LivenessViolation, match="STALLED"):
        stalled.observe("STG-X", "a", at=start + timedelta(seconds=5))


@pytest.mark.unit
def test_external_data_cannot_become_instruction_authority() -> None:
    require_instruction_authority(InstructionTrust.USER)
    with pytest.raises(WorkflowError, match="external data"):
        require_instruction_authority(InstructionTrust.EXTERNAL_DATA)
