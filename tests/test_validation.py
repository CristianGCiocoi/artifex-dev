from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest

from artifex.policy import AcceptanceAuthority
from artifex.validation import (
    AcceptanceContract,
    AcceptanceContractState,
    AcceptanceCriterion,
    CommandOutcome,
    DeterministicValidator,
    EvidenceBinding,
    EvidenceEntry,
    EvidenceLedger,
    EvidenceOutcome,
    EvidenceRequirement,
    EvidenceState,
    GateDefinition,
    GateGraph,
    GateLevel,
    GateState,
    IndependentAgentValidator,
    ManualValidator,
    MeasuredFact,
    StructuredInspectionValidator,
    ValidationContext,
    ValidationError,
    ValidatorKind,
    WaiverRequest,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _contract() -> AcceptanceContract:
    return AcceptanceContract(
        contract_id="VAL-M02-T01",
        deliverable="workflow core",
        requirements=("REQ-F-031",),
        interfaces=("ProjectStore",),
        invariants=("INV-019",),
        criteria=(AcceptanceCriterion("AC-1", "tests pass"),),
        validators=("VAL-TEST",),
        base_commit="abc",
        project_model_fingerprint="model",
    )


def _binding(suffix: str = "current") -> EvidenceBinding:
    return EvidenceBinding(f"commit-{suffix}", f"contract-{suffix}", (f"model-{suffix}",))


def _context(claim: str = "tests pass") -> ValidationContext:
    return ValidationContext(claim, "executor", _binding())


def _result(
    *,
    claim: str = "tests pass",
    outcome: EvidenceOutcome = EvidenceOutcome.PASS,
    validator_id: str = "VAL-TEST",
    kind: ValidatorKind = ValidatorKind.DETERMINISTIC,
    independent: bool = True,
) -> object:
    validator = StructuredInspectionValidator(validator_id, "1")
    result = validator.validate(
        _context(claim),
        inspector_id="reviewer" if independent else "executor",
        passed=outcome is EvidenceOutcome.PASS,
        facts=(MeasuredFact("count", 1),),
    )
    if outcome is EvidenceOutcome.BLOCKED or kind is not ValidatorKind.STRUCTURED_INSPECTION:
        result = replace(result, outcome=outcome, kind=kind)
    return result


def _entry(
    evidence_id: str = "EVD-ONE",
    *,
    claim: str = "tests pass",
    outcome: EvidenceOutcome = EvidenceOutcome.PASS,
    binding: EvidenceBinding | None = None,
    validator_id: str = "VAL-TEST",
    kind: ValidatorKind = ValidatorKind.STRUCTURED_INSPECTION,
    independent: bool = True,
) -> EvidenceEntry:
    result = _result(
        claim=claim,
        outcome=outcome,
        validator_id=validator_id,
        kind=kind,
        independent=independent,
    )
    return EvidenceEntry.create(
        evidence_id,
        result,  # type: ignore[arg-type]
        _binding() if binding is None else binding,
        recorded_at=NOW,
    )


@pytest.mark.unit
def test_acceptance_contract_is_deterministic_sealed_and_versioned() -> None:
    draft = _contract()
    assert draft.fingerprint == _contract().fingerprint
    started = draft.start()
    assert started.state is AcceptanceContractState.EXECUTION_STARTED
    assert started.sealed_hash == started.fingerprint
    started.assert_untampered()
    with pytest.raises(ValidationError, match="only a draft"):
        started.start()
    revised = started.new_version(
        criteria=(AcceptanceCriterion("AC-2", "new explicit criteria"),),
        base_commit="def",
    )
    assert revised.version == 2
    assert revised.state is AcceptanceContractState.DRAFT
    assert revised.fingerprint != started.fingerprint


@pytest.mark.unit
@pytest.mark.parametrize(
    "contract",
    [
        AcceptanceContract,
    ],
)
def test_acceptance_contract_rejects_invalid_values(contract: type[AcceptanceContract]) -> None:
    values = _contract()
    with pytest.raises(ValidationError, match="identity"):
        replace(values, contract_id="")
    with pytest.raises(ValidationError, match="criteria"):
        replace(values, criteria=())
    duplicate = AcceptanceCriterion("AC-1", "different")
    with pytest.raises(ValidationError, match="unique"):
        replace(values, criteria=(values.criteria[0], duplicate))
    with pytest.raises(ValidationError, match="seal"):
        replace(values, sealed_hash="not-allowed")
    with pytest.raises(ValidationError, match="has not started"):
        values.assert_untampered()
    assert contract is AcceptanceContract


@pytest.mark.unit
def test_typed_validators_produce_structured_results(tmp_path: Path) -> None:
    context = _context()
    deterministic = DeterministicValidator(
        "VAL-CMD", "1", (sys.executable, "-c", "raise SystemExit(0)"), tmp_path, 5
    )
    assert deterministic.validate(context).outcome is EvidenceOutcome.PASS
    failed = deterministic.validate(
        context, runner=lambda argv, cwd, timeout: CommandOutcome(2, "out", "err")
    )
    assert failed.outcome is EvidenceOutcome.FAIL
    assert failed.output == "outerr"

    structured = StructuredInspectionValidator("VAL-STRUCT", "1").validate(
        context,
        inspector_id="executor",
        passed=True,
        facts=(MeasuredFact("files", 2),),
    )
    assert not structured.independent_of_executor
    with pytest.raises(ValidationError, match="provenance"):
        StructuredInspectionValidator("VAL-STRUCT", "1").validate(
            context, inspector_id="", passed=True, facts=()
        )

    independent = IndependentAgentValidator("VAL-AGENT", "1").validate(
        context, evaluator_id="reviewer", passed=True, facts=()
    )
    assert independent.independent_of_executor
    with pytest.raises(ValidationError, match="cannot be the executor"):
        IndependentAgentValidator("VAL-AGENT", "1").validate(
            context, evaluator_id="executor", passed=True, facts=()
        )

    manual = ManualValidator("VAL-HUMAN", "1").validate(
        context,
        human_id="architect",
        authority=AcceptanceAuthority.ARCHITECT,
        passed=False,
        facts=(),
    )
    assert manual.outcome is EvidenceOutcome.FAIL
    with pytest.raises(ValidationError, match="human authority"):
        ManualValidator("VAL-HUMAN", "1").validate(
            context,
            human_id="core",
            authority=AcceptanceAuthority.CORE,
            passed=True,
            facts=(),
        )


@pytest.mark.unit
def test_deterministic_validator_configuration_is_bounded() -> None:
    with pytest.raises(ValidationError, match="identity"):
        DeterministicValidator("", "1", ("tool",), Path.cwd(), 1)
    with pytest.raises(ValidationError, match="safe and bounded"):
        DeterministicValidator("VAL-X", "1", ("tool",), Path.cwd(), 0)
    with pytest.raises(ValidationError, match="safe and bounded"):
        DeterministicValidator("VAL-X", "1", ("",), Path.cwd(), 1)


@pytest.mark.unit
def test_evidence_is_scrubbed_minimized_integrity_checked_and_invalidated() -> None:
    result = StructuredInspectionValidator("VAL-TEST", "1").validate(
        _context(),
        inspector_id="reviewer",
        passed=True,
        facts=(MeasuredFact("tests", 42), MeasuredFact("detail", "password=do-not-store")),
        output="token=super-secret " + "x" * 5000,
    )
    entry = EvidenceEntry.create("EVD-SAFE", result, _binding(), recorded_at=NOW)
    assert "super-secret" not in entry.output
    assert "do-not-store" not in str(entry.facts)
    assert len(entry.output) == 4000
    assert entry.verify_integrity()

    ledger = EvidenceLedger({"VAL-TEST": "1"})
    ledger.append(entry)
    assert ledger.entries == (entry,)
    assert ledger.state(entry, _binding()) is EvidenceState.CURRENT
    assert ledger.state(entry, _binding("new")) is EvidenceState.STALE
    ledger.invalidate([entry.evidence_id], reason="source changed")
    assert ledger.state(entry, _binding()) is EvidenceState.STALE


@pytest.mark.unit
def test_evidence_and_ledger_reject_invalid_operations() -> None:
    with pytest.raises(ValidationError, match="EVD"):
        EvidenceEntry.create("BAD", _result(), _binding(), recorded_at=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timezone"):
        EvidenceEntry.create(
            "EVD-X", _result(), _binding(), recorded_at=datetime(2026, 1, 1)  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="bind"):
        EvidenceBinding("", "contract", ("model",))

    entry = _entry()
    with pytest.raises(ValidationError, match="spoofed"):
        EvidenceLedger({"VAL-TEST": "2"}).append(entry)
    ledger = EvidenceLedger({"VAL-TEST": "1"})
    ledger.append(entry)
    with pytest.raises(ValidationError, match="duplicate"):
        ledger.append(entry)
    with pytest.raises(ValidationError, match="reason"):
        ledger.invalidate([entry.evidence_id], reason="")
    with pytest.raises(ValidationError, match="unknown evidence"):
        ledger.invalidate(["EVD-MISSING"], reason="test")


@pytest.mark.unit
def test_waiver_requires_separate_explicit_authority_and_expiry() -> None:
    request = WaiverRequest("WAV-ONE", "G-TASK", "tool unavailable", "coverage gap", "worker")
    with pytest.raises(ValidationError, match="self-approve"):
        request.approve(
            approved_by="worker",
            authority=AcceptanceAuthority.HUMAN,
            revisit_condition="tool restored",
        )
    with pytest.raises(ValidationError, match="authority"):
        request.approve(
            approved_by="core",
            authority=AcceptanceAuthority.CORE,
            revisit_condition="tool restored",
        )
    with pytest.raises(ValidationError, match="expiry"):
        request.approve(approved_by="human", authority=AcceptanceAuthority.HUMAN)
    waiver = request.approve(
        approved_by="human",
        authority=AcceptanceAuthority.HUMAN,
        expires_at=NOW + timedelta(days=1),
    )
    assert waiver.is_active(at=NOW)
    assert not waiver.is_active(at=NOW + timedelta(days=2))


def _requirement(claim: str, validator: str = "VAL-TEST") -> EvidenceRequirement:
    return EvidenceRequirement(
        claim,
        frozenset({validator}),
        frozenset({ValidatorKind.STRUCTURED_INSPECTION}),
        require_independent=True,
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (EvidenceOutcome.PASS, GateState.PASS),
        (EvidenceOutcome.FAIL, GateState.FAIL),
        (EvidenceOutcome.BLOCKED, GateState.BLOCKED),
    ],
)
def test_gate_evaluates_current_evidence(
    outcome: EvidenceOutcome, expected: GateState
) -> None:
    ledger = EvidenceLedger({"VAL-TEST": "1"})
    ledger.append(_entry(outcome=outcome))
    graph = GateGraph((GateDefinition("G-TASK", GateLevel.TASK, (_requirement("tests pass"),)),))
    assert (
        graph.evaluate(
            "G-TASK",
            ledger=ledger,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is expected
    )


@pytest.mark.unit
def test_gate_states_pending_stale_waived_and_authority() -> None:
    graph = GateGraph(
        (
            GateDefinition(
                "G-TASK", GateLevel.TASK, (_requirement("tests pass"),), waiver_allowed=True
            ),
        )
    )
    empty = EvidenceLedger({"VAL-TEST": "1"})
    assert (
        graph.evaluate(
            "G-TASK",
            ledger=empty,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.PENDING
    )
    empty.append(_entry(binding=_binding("old")))
    assert (
        graph.evaluate(
            "G-TASK",
            ledger=empty,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.STALE
    )
    waiver = WaiverRequest("WAV-X", "G-TASK", "reason", "impact", "worker").approve(
        approved_by="architect",
        authority=AcceptanceAuthority.ARCHITECT,
        revisit_condition="dependency restored",
    )
    assert (
        graph.evaluate(
            "G-TASK",
            ledger=empty,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            waivers=(waiver,),
            at=NOW,
        )
        is GateState.WAIVED
    )
    with pytest.raises(ValidationError, match="only Core"):
        graph.evaluate(
            "G-TASK",
            ledger=empty,
            binding=_binding(),
            authority=AcceptanceAuthority.HUMAN,
        )


@pytest.mark.unit
def test_hierarchical_gate_requires_distinct_parent_evidence() -> None:
    gates = (
        GateDefinition("G-TASK", GateLevel.TASK, (_requirement("task"),)),
        GateDefinition(
            "G-INT", GateLevel.INTEGRATION, (_requirement("integration"),), ("G-TASK",)
        ),
        GateDefinition(
            "G-MILESTONE", GateLevel.MILESTONE, (_requirement("milestone"),), ("G-INT",)
        ),
        GateDefinition(
            "G-RELEASE", GateLevel.RELEASE, (_requirement("release"),), ("G-MILESTONE",)
        ),
    )
    graph = GateGraph(gates)
    ledger = EvidenceLedger({"VAL-TEST": "1"})
    ledger.append(_entry("EVD-TASK", claim="task"))
    assert (
        graph.evaluate(
            "G-RELEASE",
            ledger=ledger,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.PENDING
    )
    for number, claim in enumerate(("integration", "milestone", "release"), start=1):
        ledger.append(_entry(f"EVD-PARENT-{number}", claim=claim))
    assert (
        graph.evaluate(
            "G-RELEASE",
            ledger=ledger,
            binding=_binding(),
            authority=AcceptanceAuthority.CORE,
            at=NOW,
        )
        is GateState.PASS
    )


@pytest.mark.unit
def test_contract_schemas_accept_representative_documents() -> None:
    root = Path(__file__).parents[1]
    stage_schema = json.loads((root / "schemas" / "stage-contract.schema.json").read_text())
    jsonschema.validate(
        {
            "stage_id": "STG-X",
            "requires": [],
            "produces": ["artifact"],
            "capabilities": ["repository_write"],
            "validators": ["VAL-X"],
            "transitions": [{"source": "PENDING", "target": "READY"}],
            "liveness": {
                "max_stage_visits": 3,
                "max_no_progress_observations": 2,
                "max_stall_seconds": 30,
            },
        },
        stage_schema,
    )
    evidence_schema = json.loads(
        (root / "schemas" / "acceptance-evidence.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(evidence_schema)
