from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from artifex.policy import AcceptanceAuthority
from artifex.validation import (
    EvidenceBinding,
    EvidenceEntry,
    EvidenceLedger,
    EvidenceRequirement,
    GateDefinition,
    GateGraph,
    GateLevel,
    GateState,
    IndependentAgentValidator,
    MeasuredFact,
    StructuredInspectionValidator,
    ValidationContext,
    ValidationError,
    ValidatorKind,
    WaiverRequest,
)
from artifex.workflow import (
    ExecutionBaseline,
    ExecutionStatus,
    LivenessGuard,
    LivenessPolicy,
    LivenessViolation,
    StageContract,
    StageState,
    WorkflowEngine,
    WorkflowError,
    classify_execution_result,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
BINDING = EvidenceBinding("commit", "contract", ("model",))


def _gate(require_independent: bool = True) -> GateGraph:
    requirement = EvidenceRequirement(
        "critical claim",
        frozenset({"VAL-REVIEW"}),
        frozenset({ValidatorKind.INDEPENDENT_AGENT, ValidatorKind.STRUCTURED_INSPECTION}),
        require_independent=require_independent,
    )
    return GateGraph((GateDefinition("G-TASK", GateLevel.TASK, (requirement,)),))


@pytest.mark.adversarial
def test_premature_done_is_only_a_claim_not_acceptance() -> None:
    engine = WorkflowEngine()
    engine.register(
        StageContract(
            "STG-X", (), ("artifact",), frozenset(), ("VAL-REVIEW",)
        )
    )
    engine.transition("STG-X", StageState.READY)
    engine.start(
        "STG-X",
        available_inputs=set(),
        available_capabilities=set(),
        baseline=ExecutionBaseline("commit", "contract", "model"),
    )
    assert engine.claim_complete("STG-X", outputs={"artifact"}).state is StageState.CLAIMED_COMPLETE
    with pytest.raises(WorkflowError):
        engine.transition("STG-X", StageState.ACCEPTED, authority=AcceptanceAuthority.CORE)


@pytest.mark.adversarial
def test_self_certification_is_rejected() -> None:
    context = ValidationContext("critical claim", "worker", BINDING)
    with pytest.raises(ValidationError, match="cannot be the executor"):
        IndependentAgentValidator("VAL-REVIEW", "1").validate(
            context, evaluator_id="worker", passed=True, facts=()
        )
    self_report = StructuredInspectionValidator("VAL-REVIEW", "1").validate(
        context, inspector_id="worker", passed=True, facts=()
    )
    ledger = EvidenceLedger({"VAL-REVIEW": "1"})
    ledger.append(EvidenceEntry.create("EVD-SELF", self_report, BINDING, recorded_at=NOW))
    assert (
        _gate().evaluate(
            "G-TASK",
            ledger=ledger,
            binding=BINDING,
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.PENDING
    )


@pytest.mark.adversarial
def test_evidence_tampering_is_rejected() -> None:
    result = StructuredInspectionValidator("VAL-REVIEW", "1").validate(
        ValidationContext("critical claim", "worker", BINDING),
        inspector_id="reviewer",
        passed=True,
        facts=(MeasuredFact("tests", 1),),
    )
    entry = EvidenceEntry.create("EVD-REAL", result, BINDING, recorded_at=NOW)
    tampered = replace(entry, claim="different claim")
    with pytest.raises(ValidationError, match="integrity"):
        EvidenceLedger({"VAL-REVIEW": "1"}).append(tampered)


@pytest.mark.adversarial
def test_validator_spoofing_is_rejected() -> None:
    result = StructuredInspectionValidator("VAL-REVIEW", "forged").validate(
        ValidationContext("critical claim", "worker", BINDING),
        inspector_id="reviewer",
        passed=True,
        facts=(),
    )
    entry = EvidenceEntry.create("EVD-SPOOF", result, BINDING, recorded_at=NOW)
    with pytest.raises(ValidationError, match="spoofed"):
        EvidenceLedger({"VAL-REVIEW": "trusted"}).append(entry)


@pytest.mark.adversarial
def test_stale_evidence_cannot_pass_a_gate() -> None:
    old = EvidenceBinding("old-commit", "contract", ("model",))
    result = StructuredInspectionValidator("VAL-REVIEW", "1").validate(
        ValidationContext("critical claim", "worker", old),
        inspector_id="reviewer",
        passed=True,
        facts=(),
    )
    ledger = EvidenceLedger({"VAL-REVIEW": "1"})
    ledger.append(EvidenceEntry.create("EVD-OLD", result, old, recorded_at=NOW))
    assert (
        _gate().evaluate(
            "G-TASK",
            ledger=ledger,
            binding=BINDING,
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.STALE
    )


@pytest.mark.adversarial
def test_waiver_abuse_fails_closed() -> None:
    request = WaiverRequest("WAV-X", "G-TASK", "skip", "risk", "worker")
    with pytest.raises(ValidationError, match="self-approve"):
        request.approve(
            approved_by="worker",
            authority=AcceptanceAuthority.HUMAN,
            revisit_condition="later",
        )
    expired = request.approve(
        approved_by="architect",
        authority=AcceptanceAuthority.ARCHITECT,
        expires_at=NOW - timedelta(seconds=1),
    )
    assert (
        _gate().evaluate(
            "G-TASK",
            ledger=EvidenceLedger({"VAL-REVIEW": "1"}),
            binding=BINDING,
            authority=AcceptanceAuthority.CORE,
            waivers=(expired,),
            at=NOW,
        )
        is GateState.PENDING
    )


@pytest.mark.adversarial
def test_no_progress_loop_is_stopped_mechanically() -> None:
    guard = LivenessGuard(
        LivenessPolicy(max_stage_visits=10, max_no_progress_observations=2, max_stall_seconds=60)
    )
    guard.observe("STG-X", "same", at=NOW)
    guard.observe("STG-X", "same", at=NOW + timedelta(seconds=1))
    with pytest.raises(LivenessViolation):
        guard.observe("STG-X", "same", at=NOW + timedelta(seconds=2))


@pytest.mark.adversarial
def test_stale_worker_returns_rebase_required() -> None:
    stale = ExecutionBaseline("old", "contract", "model")
    current = ExecutionBaseline("new", "contract", "model")
    assert (
        classify_execution_result(stale, current, ExecutionStatus.SUCCESS)
        is ExecutionStatus.REBASE_REQUIRED
    )
