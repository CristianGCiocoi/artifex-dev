from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest
import yaml

from artifex.policy import AcceptanceAuthority
from artifex.validation import (
    AcceptanceContract,
    AcceptanceContractState,
    AcceptanceCriterion,
    CommandOutcome,
    DeterministicValidator,
    EvidenceBinding,
    EvidenceClassification,
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
    classify_evidence_payload,
    decode_evidence,
    dump_evidence,
    evidence_to_payload,
    load_evidence,
    validate_evidence_set,
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
    commit = hashlib.sha256(f"commit-{suffix}".encode()).hexdigest()
    contract = hashlib.sha256(f"contract-{suffix}".encode()).hexdigest()
    model = hashlib.sha256(f"model-{suffix}".encode()).hexdigest()
    return EvidenceBinding(commit[:40], contract, (model,))


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


def _legacy_entry(evidence_id: str = "EVD-ONE") -> EvidenceEntry:
    return _entry(
        evidence_id,
        binding=EvidenceBinding("a" * 40, "b" * 64, ("c" * 64,)),
    )


@pytest.mark.unit
def test_canonical_evidence_codec_round_trips_yaml_and_json(tmp_path: Path) -> None:
    entry = _entry()
    assert evidence_to_payload(entry)["schema_version"] == "2.0"
    for suffix in (".yaml", ".json"):
        path = tmp_path / f"evidence{suffix}"
        dump_evidence(entry, path)
        decoded = load_evidence(
            path,
            trusted_validators={"VAL-TEST": "1"},
            expected_binding=_binding(),
        )
        assert decoded.classification is EvidenceClassification.CANONICAL
        assert decoded.entry == entry


@pytest.mark.adversarial
def test_canonical_evidence_fails_closed_for_tampering_spoofing_and_staleness() -> None:
    payload = evidence_to_payload(_entry())
    with pytest.raises(ValidationError, match="spoofed"):
        decode_evidence(payload, trusted_validators={"VAL-TEST": "2"})
    with pytest.raises(ValidationError, match="stale"):
        decode_evidence(
            payload,
            trusted_validators={"VAL-TEST": "1"},
            expected_binding=_binding("other"),
        )
    tampered = dict(payload)
    tampered["claim"] = "forged"
    with pytest.raises(ValidationError, match="integrity"):
        decode_evidence(tampered, trusted_validators={"VAL-TEST": "1"})
    self_certified = evidence_to_payload(_entry(independent=False))
    with pytest.raises(ValidationError, match="independent"):
        decode_evidence(self_certified, trusted_validators={"VAL-TEST": "1"})


@pytest.mark.adversarial
def test_legacy_is_historical_unknown_is_rejected_and_duplicates_fail(tmp_path: Path) -> None:
    wrapped_legacy = {
        "schema_version": "1.0",
        "evidence": {
            "id": "EVD-OLD",
            "gate": "G-OLD",
            "claim": "historical",
            "validator": {"id": "old", "version": "1", "type": "independent_agent"},
            "source": {
                "commit": "a" * 40,
                "contract_hash": "b" * 64,
                "project_model_fingerprint": "c" * 64,
            },
            "result": {"status": "PASS", "measured": {}},
            "evidence_excerpt": "independent historical validation",
            "scrubbed": True,
            "created_at": NOW.isoformat(),
        },
    }
    assert classify_evidence_payload(wrapped_legacy) is EvidenceClassification.LEGACY_HISTORICAL
    flat_legacy = evidence_to_payload(_entry())
    flat_legacy.pop("schema_version")
    flat_legacy.pop("independent_of_executor")
    flat_legacy["validator"] = {
        "id": flat_legacy.pop("validator_id"),
        "version": flat_legacy.pop("validator_version"),
        "kind": flat_legacy.pop("validator_kind"),
    }
    assert classify_evidence_payload(flat_legacy) is EvidenceClassification.LEGACY_HISTORICAL
    with pytest.raises(ValidationError, match="unknown"):
        classify_evidence_payload({"schema_version": "1.0", "evidence": {"id": "invented"}})
    paths = [tmp_path / "one.yaml", tmp_path / "two.yaml"]
    for path in paths:
        dump_evidence(_entry(), path)
    with pytest.raises(ValidationError, match="duplicate"):
        validate_evidence_set(
            paths,
            trusted_validators={"VAL-TEST": "1"},
            expected_binding=_binding(),
        )


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "shape,mutation",
    [
        ("wrapped", "outer-extra"),
        ("wrapped", "missing"),
        ("wrapped", "numeric-id"),
        ("wrapped", "bad-validator"),
        ("wrapped", "bad-commit"),
        ("wrapped", "nonfinite"),
        ("wrapped", "unaware-time"),
        ("flat", "outer-extra"),
        ("flat", "missing"),
        ("flat", "numeric-id"),
        ("flat", "numeric-fact-name"),
        ("flat", "structured-fact"),
        ("flat", "bad-binding"),
        ("flat", "bad-validator"),
        ("flat", "numeric-producer"),
        ("flat", "unaware-time"),
        ("flat", "bad-hash"),
    ],
)
def test_legacy_classification_requires_exact_historical_signatures(
    shape: str, mutation: str
) -> None:
    canonical = evidence_to_payload(_entry())
    if shape == "wrapped":
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "evidence": {
                "id": "EVD-OLD",
                "gate": "G-OLD",
                "claim": "historical validation",
                "validator": {"id": "legacy", "version": "1", "type": "independent_agent"},
                "source": {
                    "commit": "a" * 40,
                    "contract_hash": "b" * 64,
                    "project_model_fingerprint": "c" * 64,
                },
                "result": {"status": "PASS", "measured": {"tests": 1}},
                "evidence_excerpt": "independent historical validation",
                "scrubbed": True,
                "created_at": NOW.isoformat(),
            },
        }
        evidence = payload["evidence"]
        assert isinstance(evidence, dict)
        if mutation == "outer-extra":
            payload["unexpected"] = True
        elif mutation == "missing":
            evidence.pop("evidence_excerpt")
        elif mutation == "numeric-id":
            evidence["id"] = 7
        elif mutation == "bad-validator":
            evidence["validator"] = {"id": "legacy", "version": 1, "type": "manual"}
        elif mutation == "bad-commit":
            evidence["source"] = {
                "commit": "main",
                "contract_hash": "b" * 64,
                "project_model_fingerprint": "c" * 64,
            }
        elif mutation == "nonfinite":
            evidence["result"] = {"status": "PASS", "measured": {"coverage": float("nan")}}
        else:
            evidence["created_at"] = "2026-08-22T00:00:00"
    else:
        payload = dict(canonical)
        payload.pop("schema_version")
        payload.pop("independent_of_executor")
        payload["validator"] = {
            "id": payload.pop("validator_id"),
            "version": payload.pop("validator_version"),
            "kind": payload.pop("validator_kind"),
        }
        if mutation == "outer-extra":
            payload["unexpected"] = True
        elif mutation == "missing":
            payload.pop("output")
        elif mutation == "numeric-id":
            payload["evidence_id"] = 7
        elif mutation == "numeric-fact-name":
            payload["facts"] = [{"name": 7, "value": True}]
        elif mutation == "structured-fact":
            payload["facts"] = [{"name": "tests", "value": [1]}]
        elif mutation == "bad-binding":
            payload["binding"] = {
                "base_commit": "main",
                "contract_hash": "b" * 64,
                "project_model_fingerprints": ["c" * 64],
            }
        elif mutation == "bad-validator":
            payload["validator"] = {"id": "legacy", "version": 1, "kind": "MANUAL"}
        elif mutation == "numeric-producer":
            payload["producer_id"] = 7
        elif mutation == "unaware-time":
            payload["recorded_at"] = "2026-08-22T00:00:00"
        else:
            payload["entry_hash"] = "not-a-hash"
    with pytest.raises(ValidationError, match="unknown"):
        classify_evidence_payload(payload)


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
    deterministic = DeterministicValidator("VAL-CMD", "1", ("git", "--version"), tmp_path, 5)
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
        facts=(MeasuredFact("tests", 42), MeasuredFact("detail", "safe result")),
        output="token=super-secret " + "x" * 5000,
    )
    entry = EvidenceEntry.create("EVD-SAFE", result, _binding(), recorded_at=NOW)
    assert "super-secret" not in entry.output
    assert entry.facts[1].value == "safe result"
    assert len(entry.output) == 4000
    assert entry.verify_integrity()

    ledger = EvidenceLedger({"VAL-TEST": "1"})
    ledger.append(entry)
    assert ledger.entries == (entry,)
    assert ledger.state(entry, _binding()) is EvidenceState.CURRENT
    assert ledger.state(entry, _binding("new")) is EvidenceState.STALE
    ledger.invalidate([entry.evidence_id], reason="source changed")
    assert ledger.state(entry, _binding()) is EvidenceState.STALE


@pytest.mark.integration
def test_evidence_ledger_persists_and_reconstructs_jsonl(tmp_path: Path) -> None:
    journal = tmp_path / ".artifex" / "validation" / "evidence" / "ledger.jsonl"
    entry = _entry()
    ledger = EvidenceLedger({"VAL-TEST": "1"}, journal_path=journal)
    ledger.append(entry)
    ledger.invalidate([entry.evidence_id], reason="verified input changed")

    reconstructed = EvidenceLedger({"VAL-TEST": "1"}, journal_path=journal)
    assert reconstructed.entries == (entry,)
    assert reconstructed.state(entry, _binding()) is EvidenceState.STALE
    lines = journal.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["type"] for line in lines] == ["EVIDENCE", "INVALIDATION"]
    assert json.loads(lines[0])["entry"] == evidence_to_payload(entry)
    assert json.loads(lines[0])["entry"]["schema_version"] == "2.0"


@pytest.mark.integration
def test_evidence_ledger_fails_closed_on_corrupt_journal(tmp_path: Path) -> None:
    journal = tmp_path / "ledger.jsonl"
    journal.write_text('{"type":"EVIDENCE","entry":{}}\n', encoding="utf-8")
    with pytest.raises(ValidationError, match="corrupt evidence journal"):
        EvidenceLedger({"VAL-TEST": "1"}, journal_path=journal)


@pytest.mark.integration
def test_legacy_journal_is_preserved_and_new_entries_use_ledger_v2(tmp_path: Path) -> None:
    entry = _legacy_entry()
    legacy_payload = evidence_to_payload(entry)
    legacy_payload.pop("schema_version")
    legacy = tmp_path / "ledger.jsonl"
    legacy.write_text(
        json.dumps({"type": "EVIDENCE", "entry": legacy_payload}) + "\n",
        encoding="utf-8",
    )
    before = legacy.read_bytes()
    with pytest.raises(ValidationError, match=r"legacy unversioned.*ledger-v2"):
        EvidenceLedger({"VAL-TEST": "1"}, journal_path=legacy)
    assert legacy.read_bytes() == before

    canonical = EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)
    with pytest.raises(ValidationError, match="duplicate evidence ID"):
        canonical.append(entry)
    canonical.append(_legacy_entry("EVD-TWO"))
    event = json.loads((tmp_path / "ledger-v2.jsonl").read_text(encoding="utf-8"))
    assert event["entry"]["schema_version"] == "2.0"
    assert legacy.read_bytes() == before


@pytest.mark.integration
def test_actual_repository_legacy_journal_is_historical_and_collision_safe(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / ".artifex/validation/ledger.jsonl"
    legacy = tmp_path / "ledger.jsonl"
    legacy.write_bytes(source.read_bytes())
    before = legacy.read_bytes()
    ledger = EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)
    with pytest.raises(ValidationError, match="duplicate evidence ID"):
        ledger.append(_entry("EVD-M11-SELFHOST-PROJECTION"))
    ledger.append(_entry("EVD-V2-NEW"))
    assert legacy.read_bytes() == before
    assert ledger.entries[0].evidence_id == "EVD-V2-NEW"


@pytest.mark.integration
@pytest.mark.parametrize(
    "content,match",
    [
        ('{"type":"UNKNOWN"}\n', "unknown legacy"),
        ('{"type":"EVIDENCE"', "truncated"),
        ("not-json\n", "corrupt legacy"),
    ],
)
def test_open_canonical_rejects_unknown_or_corrupt_legacy_journal(
    tmp_path: Path, content: str, match: str
) -> None:
    (tmp_path / "ledger.jsonl").write_text(content, encoding="utf-8")
    with pytest.raises(ValidationError, match=match):
        EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)


@pytest.mark.integration
def test_legacy_journal_rejects_duplicate_ids_and_incoherent_invalidations(
    tmp_path: Path,
) -> None:
    payload = evidence_to_payload(_legacy_entry())
    payload.pop("schema_version")
    evidence_event = {"type": "EVIDENCE", "entry": payload}
    legacy = tmp_path / "ledger.jsonl"
    legacy.write_text(
        "\n".join(json.dumps(evidence_event) for _ in range(2)) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="duplicate evidence ID"):
        EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)

    legacy.write_text(
        json.dumps({"type": "INVALIDATION", "evidence_id": "EVD-MISSING", "reason": "stale"})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="invalid legacy evidence invalidation"):
        EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)

    invalidation = {"type": "INVALIDATION", "evidence_id": "EVD-ONE", "reason": "stale"}
    legacy.write_text(
        "\n".join((json.dumps(evidence_event), json.dumps(invalidation), json.dumps(invalidation)))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="invalid legacy evidence invalidation"):
        EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)


@pytest.mark.adversarial
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_measured_facts_fail_create_load_and_ledger(tmp_path: Path, value: float) -> None:
    with pytest.raises(ValidationError, match="finite"):
        MeasuredFact("nonfinite", value)
    payload = evidence_to_payload(_entry())
    payload["facts"][0]["value"] = value
    for suffix, text in (
        (".json", json.dumps(payload)),
        (".yaml", yaml.safe_dump(payload)),
    ):
        path = tmp_path / f"nonfinite{suffix}"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_evidence(path, trusted_validators={"VAL-TEST": "1"})
    journal = tmp_path / "ledger-v2.jsonl"
    journal.write_text(json.dumps({"type": "EVIDENCE", "entry": payload}) + "\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="corrupt evidence journal"):
        EvidenceLedger({"VAL-TEST": "1"}, journal_path=journal)


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("password=do-not-store", "safe", "secret-safe"),
        ("x" * 201, "safe", "required"),
        ("safe", "token=super-secret", "secret-safe"),
        ("safe", "x" * 1001, "1000"),
    ],
)
def test_measured_facts_reject_noncanonical_secret_or_truncated_text(
    name: str, value: str, match: str
) -> None:
    with pytest.raises(ValidationError, match=match):
        MeasuredFact(name, value)


@pytest.mark.adversarial
@pytest.mark.parametrize("suffix", [".json", ".yaml"])
def test_evidence_codec_rejects_duplicate_keys(tmp_path: Path, suffix: str) -> None:
    payload = evidence_to_payload(_entry())
    if suffix == ".json":
        text = json.dumps(payload)
        text = text.replace('"outcome": "PASS"', '"outcome":"FAIL","outcome":"PASS"')
    else:
        text = yaml.safe_dump(payload)
        text = text.replace("outcome: PASS", "outcome: FAIL\noutcome: PASS")
    path = tmp_path / f"duplicate{suffix}"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValidationError, match="duplicate"):
        load_evidence(path, trusted_validators={"VAL-TEST": "1"})


@pytest.mark.adversarial
def test_evidence_ledger_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    entry_text = json.dumps(evidence_to_payload(_entry()), separators=(",", ":"))
    event = '{"type":"UNKNOWN","type":"EVIDENCE","entry":' + entry_text + "}\n"
    journal = tmp_path / "ledger-v2.jsonl"
    journal.write_text(event, encoding="utf-8")
    with pytest.raises(ValidationError, match="duplicate JSON key"):
        EvidenceLedger({"VAL-TEST": "1"}, journal_path=journal)


@pytest.mark.adversarial
def test_evidence_entry_rejects_invalid_direct_construction_and_secret_claims() -> None:
    entry = _entry()
    with pytest.raises(ValidationError, match="canonical EVD"):
        replace(entry, evidence_id="not-evidence")
    with pytest.raises(ValidationError, match="secret-safe"):
        replace(entry, claim="token=super-secret")
    with pytest.raises(ValidationError, match="timezone-aware"):
        replace(entry, recorded_at=datetime(2026, 1, 1))
    with pytest.raises(ValidationError, match="canonical validator ID"):
        replace(entry, validator_id="validator with spaces")


@pytest.mark.adversarial
def test_canonical_journal_invalidation_requires_exact_unique_typed_event(tmp_path: Path) -> None:
    entry = _entry()
    ledger = EvidenceLedger({"VAL-TEST": "1"}, journal_path=tmp_path / "ledger-v2.jsonl")
    ledger.append(entry)
    with pytest.raises(ValidationError, match="unknown evidence"):
        ledger.invalidate([7], reason="stale")  # type: ignore[list-item]
    ledger.invalidate([entry.evidence_id], reason="stale")
    with pytest.raises(ValidationError, match="duplicate evidence invalidation"):
        ledger.invalidate([entry.evidence_id], reason="stale again")

    lines = (tmp_path / "ledger-v2.jsonl").read_text(encoding="utf-8").splitlines()
    invalidation = json.loads(lines[-1])
    for mutation in (
        {**invalidation, "evidence_id": 7},
        {**invalidation, "reason": 7},
        {**invalidation, "extra": True},
    ):
        candidate = tmp_path / "candidate.jsonl"
        candidate.write_text(lines[0] + "\n" + json.dumps(mutation) + "\n", encoding="utf-8")
        with pytest.raises(ValidationError, match="invalid evidence invalidation"):
            EvidenceLedger({"VAL-TEST": "1"}, journal_path=candidate)

    duplicate = tmp_path / "duplicate-invalidation.jsonl"
    duplicate.write_text("\n".join((*lines, lines[-1])) + "\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="invalid evidence invalidation"):
        EvidenceLedger({"VAL-TEST": "1"}, journal_path=duplicate)


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "field,value",
    [
        ("evidence_id", 7),
        ("validator_id", 7),
        ("validator_version", 1),
        ("validator_kind", 7),
        ("claim", 7),
        ("outcome", 7),
        ("fact_name", 7),
        ("base_commit", 7),
        ("contract_hash", 7),
        ("model", 7),
        ("output", 7),
        ("recorded_at", 7),
        ("producer_id", 7),
        ("independent_of_executor", 1),
        ("entry_hash", 7),
    ],
)
def test_legacy_journal_rejects_type_spoofed_fields(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = evidence_to_payload(_legacy_entry())
    payload.pop("schema_version")
    if field == "fact_name":
        payload["facts"][0]["name"] = value
    elif field in {"base_commit", "contract_hash"}:
        payload["binding"][field] = value
    elif field == "model":
        payload["binding"]["project_model_fingerprints"] = [value]
    else:
        payload[field] = value
    (tmp_path / "ledger.jsonl").write_text(
        json.dumps({"type": "EVIDENCE", "entry": payload}) + "\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError, match="corrupt legacy evidence journal entry"):
        EvidenceLedger.open_canonical({"VAL-TEST": "1"}, journal_root=tmp_path)


@pytest.mark.unit
def test_evidence_and_ledger_reject_invalid_operations() -> None:
    with pytest.raises(ValidationError, match="EVD"):
        EvidenceEntry.create("BAD", _result(), _binding(), recorded_at=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timezone"):
        EvidenceEntry.create(
            "EVD-X",
            _result(),
            _binding(),
            recorded_at=datetime(2026, 1, 1),  # type: ignore[arg-type]
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
def test_gate_evaluates_current_evidence(outcome: EvidenceOutcome, expected: GateState) -> None:
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
        GateDefinition("G-INT", GateLevel.INTEGRATION, (_requirement("integration"),), ("G-TASK",)),
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
    evidence_schema = json.loads((root / "schemas" / "acceptance-evidence.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(evidence_schema)
