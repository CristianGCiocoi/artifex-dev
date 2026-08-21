"""Acceptance is derived from immutable contracts and verified evidence."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from artifex.policy import AcceptanceAuthority, scrub_secrets


class ValidationError(ValueError):
    """Validation input failed a trust, integrity, or policy check."""


class AcceptanceContractState(StrEnum):
    DRAFT = "DRAFT"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class AcceptanceCriterion:
    criterion_id: str
    outcome: str

    def __post_init__(self) -> None:
        if not self.criterion_id or not self.outcome:
            raise ValidationError("criterion ID and outcome are required")


@dataclass(frozen=True, slots=True)
class AcceptanceContract:
    """Versioned contract sealed to its execution baseline."""

    contract_id: str
    deliverable: str
    requirements: tuple[str, ...]
    interfaces: tuple[str, ...]
    invariants: tuple[str, ...]
    criteria: tuple[AcceptanceCriterion, ...]
    validators: tuple[str, ...]
    base_commit: str
    project_model_fingerprint: str
    version: int = 1
    state: AcceptanceContractState = AcceptanceContractState.DRAFT
    sealed_hash: str | None = None

    def __post_init__(self) -> None:
        required = (
            self.contract_id,
            self.deliverable,
            self.base_commit,
            self.project_model_fingerprint,
        )
        if not all(required) or self.version < 1:
            raise ValidationError(
                "contract identity, deliverable, baseline, and version are required"
            )
        if not self.criteria or not self.validators:
            raise ValidationError("acceptance contracts require criteria and validators")
        if len({item.criterion_id for item in self.criteria}) != len(self.criteria):
            raise ValidationError("criterion IDs must be unique")
        if self.state is AcceptanceContractState.EXECUTION_STARTED:
            if self.sealed_hash is None or self.sealed_hash != self.fingerprint:
                raise ValidationError("started contract does not match its immutable seal")
        elif self.sealed_hash is not None:
            raise ValidationError("only a started contract may carry a seal")

    @property
    def fingerprint(self) -> str:
        payload = {
            "contract_id": self.contract_id,
            "deliverable": self.deliverable,
            "requirements": self.requirements,
            "interfaces": self.interfaces,
            "invariants": self.invariants,
            "criteria": [
                {"criterion_id": item.criterion_id, "outcome": item.outcome}
                for item in self.criteria
            ],
            "validators": self.validators,
            "base_commit": self.base_commit,
            "project_model_fingerprint": self.project_model_fingerprint,
            "version": self.version,
        }
        return _hash_payload(payload)

    def start(self) -> AcceptanceContract:
        if self.state is not AcceptanceContractState.DRAFT:
            raise ValidationError("only a draft contract can start execution")
        return replace(
            self,
            state=AcceptanceContractState.EXECUTION_STARTED,
            sealed_hash=self.fingerprint,
        )

    def assert_untampered(self) -> None:
        if self.state is not AcceptanceContractState.EXECUTION_STARTED:
            raise ValidationError("contract execution has not started")
        if self.sealed_hash != self.fingerprint:
            raise ValidationError("acceptance contract was modified after execution started")

    def new_version(
        self,
        *,
        criteria: tuple[AcceptanceCriterion, ...],
        validators: tuple[str, ...] | None = None,
        base_commit: str | None = None,
        project_model_fingerprint: str | None = None,
    ) -> AcceptanceContract:
        """Make contract changes explicit; existing evidence will not match the new hash."""

        return AcceptanceContract(
            contract_id=self.contract_id,
            deliverable=self.deliverable,
            requirements=self.requirements,
            interfaces=self.interfaces,
            invariants=self.invariants,
            criteria=criteria,
            validators=self.validators if validators is None else validators,
            base_commit=self.base_commit if base_commit is None else base_commit,
            project_model_fingerprint=(
                self.project_model_fingerprint
                if project_model_fingerprint is None
                else project_model_fingerprint
            ),
            version=self.version + 1,
        )


class ValidatorKind(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    STRUCTURED_INSPECTION = "STRUCTURED_INSPECTION"
    INDEPENDENT_AGENT = "INDEPENDENT_AGENT"
    MANUAL = "MANUAL"


class EvidenceOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class MeasuredFact:
    name: str
    value: str | int | float | bool | None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValidationError("measured fact names are required")
        object.__setattr__(self, "name", scrub_secrets(self.name)[:200])
        if isinstance(self.value, str):
            object.__setattr__(self, "value", scrub_secrets(self.value)[:1_000])


@dataclass(frozen=True, slots=True)
class EvidenceBinding:
    base_commit: str
    contract_hash: str
    project_model_fingerprints: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.base_commit or not self.contract_hash or not self.project_model_fingerprints:
            raise ValidationError("evidence must bind commit, contract, and model fingerprints")


@dataclass(frozen=True, slots=True)
class ValidationContext:
    claim: str
    executor_id: str
    binding: EvidenceBinding


@dataclass(frozen=True, slots=True)
class ValidatorResult:
    validator_id: str
    validator_version: str
    kind: ValidatorKind
    claim: str
    outcome: EvidenceOutcome
    facts: tuple[MeasuredFact, ...]
    output: str
    producer_id: str
    independent_of_executor: bool = False


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def __call__(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: float
    ) -> CommandOutcome: ...


def _subprocess_runner(argv: tuple[str, ...], cwd: Path, timeout_seconds: float) -> CommandOutcome:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        timeout=timeout_seconds,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    return CommandOutcome(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class DeterministicValidator:
    validator_id: str
    version: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float
    expected_exit_code: int = 0
    kind: ValidatorKind = field(default=ValidatorKind.DETERMINISTIC, init=False)

    def __post_init__(self) -> None:
        if not self.validator_id or not self.version or not self.argv:
            raise ValidationError("deterministic validator identity and argv are required")
        if self.timeout_seconds <= 0 or any(not argument for argument in self.argv):
            raise ValidationError("validator argv and timeout must be safe and bounded")

    def validate(
        self,
        context: ValidationContext,
        *,
        runner: CommandRunner = _subprocess_runner,
    ) -> ValidatorResult:
        outcome = runner(self.argv, self.cwd, self.timeout_seconds)
        passed = outcome.exit_code == self.expected_exit_code
        return ValidatorResult(
            self.validator_id,
            self.version,
            self.kind,
            context.claim,
            EvidenceOutcome.PASS if passed else EvidenceOutcome.FAIL,
            (MeasuredFact("exit_code", outcome.exit_code),),
            outcome.stdout + outcome.stderr,
            "ARTIFEX_DETERMINISTIC_RUNNER",
            True,
        )


@dataclass(frozen=True, slots=True)
class StructuredInspectionValidator:
    validator_id: str
    version: str
    kind: ValidatorKind = field(default=ValidatorKind.STRUCTURED_INSPECTION, init=False)

    def validate(
        self,
        context: ValidationContext,
        *,
        inspector_id: str,
        passed: bool,
        facts: Iterable[MeasuredFact],
        output: str = "",
    ) -> ValidatorResult:
        if not inspector_id:
            raise ValidationError("structured inspection requires inspector provenance")
        return ValidatorResult(
            self.validator_id,
            self.version,
            self.kind,
            context.claim,
            EvidenceOutcome.PASS if passed else EvidenceOutcome.FAIL,
            tuple(facts),
            output,
            inspector_id,
            inspector_id != context.executor_id,
        )


@dataclass(frozen=True, slots=True)
class IndependentAgentValidator:
    validator_id: str
    version: str
    kind: ValidatorKind = field(default=ValidatorKind.INDEPENDENT_AGENT, init=False)

    def validate(
        self,
        context: ValidationContext,
        *,
        evaluator_id: str,
        passed: bool,
        facts: Iterable[MeasuredFact],
        output: str = "",
    ) -> ValidatorResult:
        if not evaluator_id or evaluator_id == context.executor_id:
            raise ValidationError("an independent validator cannot be the executor")
        return ValidatorResult(
            self.validator_id,
            self.version,
            self.kind,
            context.claim,
            EvidenceOutcome.PASS if passed else EvidenceOutcome.FAIL,
            tuple(facts),
            output,
            evaluator_id,
            True,
        )


@dataclass(frozen=True, slots=True)
class ManualValidator:
    validator_id: str
    version: str
    kind: ValidatorKind = field(default=ValidatorKind.MANUAL, init=False)

    def validate(
        self,
        context: ValidationContext,
        *,
        human_id: str,
        authority: AcceptanceAuthority,
        passed: bool,
        facts: Iterable[MeasuredFact],
        output: str = "",
    ) -> ValidatorResult:
        if not human_id or authority not in {
            AcceptanceAuthority.HUMAN,
            AcceptanceAuthority.ARCHITECT,
        }:
            raise ValidationError("manual validation requires explicit human authority")
        return ValidatorResult(
            self.validator_id,
            self.version,
            self.kind,
            context.claim,
            EvidenceOutcome.PASS if passed else EvidenceOutcome.FAIL,
            tuple(facts),
            output,
            human_id,
            human_id != context.executor_id,
        )


_MAX_EVIDENCE_OUTPUT = 4_000


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    evidence_id: str
    validator_id: str
    validator_version: str
    validator_kind: ValidatorKind
    claim: str
    outcome: EvidenceOutcome
    facts: tuple[MeasuredFact, ...]
    binding: EvidenceBinding
    output: str
    recorded_at: datetime
    producer_id: str
    independent_of_executor: bool
    entry_hash: str

    def __post_init__(self) -> None:
        if len(self.output) > _MAX_EVIDENCE_OUTPUT or scrub_secrets(self.output) != self.output:
            raise ValidationError("canonical evidence output must be minimized and secret-safe")

    @classmethod
    def create(
        cls,
        evidence_id: str,
        result: ValidatorResult,
        binding: EvidenceBinding,
        *,
        recorded_at: datetime | None = None,
    ) -> EvidenceEntry:
        if not evidence_id.startswith("EVD-"):
            raise ValidationError("evidence IDs must use the EVD- prefix")
        timestamp = datetime.now(UTC) if recorded_at is None else recorded_at
        if timestamp.tzinfo is None:
            raise ValidationError("evidence timestamps must be timezone-aware")
        output = scrub_secrets(result.output)[:_MAX_EVIDENCE_OUTPUT]
        values: dict[str, Any] = {
            "evidence_id": evidence_id,
            "validator_id": result.validator_id,
            "validator_version": result.validator_version,
            "validator_kind": result.kind,
            "claim": result.claim,
            "outcome": result.outcome,
            "facts": [(fact.name, fact.value) for fact in result.facts],
            "binding": {
                "base_commit": binding.base_commit,
                "contract_hash": binding.contract_hash,
                "project_model_fingerprints": binding.project_model_fingerprints,
            },
            "output": output,
            "recorded_at": timestamp.isoformat(),
            "producer_id": result.producer_id,
            "independent_of_executor": result.independent_of_executor,
        }
        return cls(
            evidence_id,
            result.validator_id,
            result.validator_version,
            result.kind,
            result.claim,
            result.outcome,
            result.facts,
            binding,
            output,
            timestamp,
            result.producer_id,
            result.independent_of_executor,
            _hash_payload(values),
        )

    def verify_integrity(self) -> bool:
        values: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "validator_id": self.validator_id,
            "validator_version": self.validator_version,
            "validator_kind": self.validator_kind,
            "claim": self.claim,
            "outcome": self.outcome,
            "facts": [(fact.name, fact.value) for fact in self.facts],
            "binding": {
                "base_commit": self.binding.base_commit,
                "contract_hash": self.binding.contract_hash,
                "project_model_fingerprints": self.binding.project_model_fingerprints,
            },
            "output": self.output,
            "recorded_at": self.recorded_at.isoformat(),
            "producer_id": self.producer_id,
            "independent_of_executor": self.independent_of_executor,
        }
        return self.entry_hash == _hash_payload(values)


class EvidenceState(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"


class EvidenceLedger:
    """Append-only evidence with trusted validator identities and explicit invalidation."""

    def __init__(
        self, trusted_validators: Mapping[str, str], *, journal_path: Path | None = None
    ) -> None:
        self._trusted = dict(trusted_validators)
        self._entries: list[EvidenceEntry] = []
        self._invalidations: dict[str, str] = {}
        self._journal_path = journal_path
        if journal_path is not None and journal_path.exists():
            self._load_journal()

    @property
    def entries(self) -> tuple[EvidenceEntry, ...]:
        return tuple(self._entries)

    def append(self, entry: EvidenceEntry) -> None:
        self._validate_entry(entry)
        self._persist({"type": "EVIDENCE", "entry": self._entry_payload(entry)})
        self._entries.append(entry)

    def _validate_entry(self, entry: EvidenceEntry) -> None:
        if self._trusted.get(entry.validator_id) != entry.validator_version:
            raise ValidationError("untrusted or spoofed validator identity")
        if not entry.verify_integrity():
            raise ValidationError("evidence integrity check failed")
        if any(item.evidence_id == entry.evidence_id for item in self._entries):
            raise ValidationError(f"duplicate evidence ID: {entry.evidence_id}")

    def invalidate(self, evidence_ids: Iterable[str], *, reason: str) -> None:
        if not reason:
            raise ValidationError("invalidation requires a reason")
        known = {entry.evidence_id for entry in self._entries}
        for evidence_id in evidence_ids:
            if evidence_id not in known:
                raise ValidationError(f"cannot invalidate unknown evidence: {evidence_id}")
            self._persist({"type": "INVALIDATION", "evidence_id": evidence_id, "reason": reason})
            self._invalidations[evidence_id] = reason

    def state(self, entry: EvidenceEntry, expected: EvidenceBinding) -> EvidenceState:
        if entry.evidence_id in self._invalidations or entry.binding != expected:
            return EvidenceState.STALE
        return EvidenceState.CURRENT

    def _persist(self, event: Mapping[str, Any]) -> None:
        if self._journal_path is None:
            return
        self._journal_path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._journal_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def _load_journal(self) -> None:
        assert self._journal_path is not None
        try:
            lines = self._journal_path.read_text(encoding="utf-8").splitlines()
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                event_type = event.get("type")
                if event_type == "EVIDENCE":
                    entry = self._entry_from_payload(event["entry"])
                    self._validate_entry(entry)
                    self._entries.append(entry)
                elif event_type == "INVALIDATION":
                    evidence_id = str(event["evidence_id"])
                    reason = str(event["reason"])
                    if not reason or evidence_id not in {
                        entry.evidence_id for entry in self._entries
                    }:
                        raise ValidationError("invalid evidence invalidation event")
                    self._invalidations[evidence_id] = reason
                else:
                    raise ValidationError(f"unknown evidence journal event at line {line_number}")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError(f"corrupt evidence journal: {exc}") from exc

    @staticmethod
    def _entry_payload(entry: EvidenceEntry) -> dict[str, Any]:
        return {
            "evidence_id": entry.evidence_id,
            "validator_id": entry.validator_id,
            "validator_version": entry.validator_version,
            "validator_kind": entry.validator_kind,
            "claim": entry.claim,
            "outcome": entry.outcome,
            "facts": [{"name": fact.name, "value": fact.value} for fact in entry.facts],
            "binding": {
                "base_commit": entry.binding.base_commit,
                "contract_hash": entry.binding.contract_hash,
                "project_model_fingerprints": list(entry.binding.project_model_fingerprints),
            },
            "output": entry.output,
            "recorded_at": entry.recorded_at.isoformat(),
            "producer_id": entry.producer_id,
            "independent_of_executor": entry.independent_of_executor,
            "entry_hash": entry.entry_hash,
        }

    @staticmethod
    def _entry_from_payload(payload: Mapping[str, Any]) -> EvidenceEntry:
        binding_payload = payload["binding"]
        if not isinstance(binding_payload, Mapping):
            raise ValidationError("corrupt evidence binding")
        facts_payload = payload["facts"]
        if not isinstance(facts_payload, list):
            raise ValidationError("corrupt evidence facts")
        return EvidenceEntry(
            evidence_id=str(payload["evidence_id"]),
            validator_id=str(payload["validator_id"]),
            validator_version=str(payload["validator_version"]),
            validator_kind=ValidatorKind(str(payload["validator_kind"])),
            claim=str(payload["claim"]),
            outcome=EvidenceOutcome(str(payload["outcome"])),
            facts=tuple(
                MeasuredFact(str(fact["name"]), fact["value"])
                for fact in facts_payload
                if isinstance(fact, Mapping)
            ),
            binding=EvidenceBinding(
                str(binding_payload["base_commit"]),
                str(binding_payload["contract_hash"]),
                tuple(str(item) for item in binding_payload["project_model_fingerprints"]),
            ),
            output=str(payload["output"]),
            recorded_at=datetime.fromisoformat(str(payload["recorded_at"])),
            producer_id=str(payload["producer_id"]),
            independent_of_executor=bool(payload["independent_of_executor"]),
            entry_hash=str(payload["entry_hash"]),
        )


@dataclass(frozen=True, slots=True)
class WaiverRequest:
    waiver_id: str
    gate_id: str
    reason: str
    impact: str
    requested_by: str

    def __post_init__(self) -> None:
        if not self.waiver_id.startswith("WAV-") or not all(
            (self.gate_id, self.reason, self.impact, self.requested_by)
        ):
            raise ValidationError(
                "waiver request requires identity, provenance, reason, and impact"
            )

    def approve(
        self,
        *,
        approved_by: str,
        authority: AcceptanceAuthority,
        expires_at: datetime | None = None,
        revisit_condition: str | None = None,
    ) -> ApprovedWaiver:
        if approved_by == self.requested_by:
            raise ValidationError("a waiver requester cannot self-approve")
        if authority not in {AcceptanceAuthority.ARCHITECT, AcceptanceAuthority.HUMAN}:
            raise ValidationError("waiver approval requires architect or human authority")
        if expires_at is None and not revisit_condition:
            raise ValidationError("waiver approval requires expiry or a revisit condition")
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValidationError("waiver expiry must be timezone-aware")
        return ApprovedWaiver(
            self.waiver_id,
            self.gate_id,
            self.reason,
            self.impact,
            self.requested_by,
            approved_by,
            authority,
            expires_at,
            revisit_condition,
        )


@dataclass(frozen=True, slots=True)
class ApprovedWaiver:
    waiver_id: str
    gate_id: str
    reason: str
    impact: str
    requested_by: str
    approved_by: str
    authority: AcceptanceAuthority
    expires_at: datetime | None
    revisit_condition: str | None

    def is_active(self, *, at: datetime) -> bool:
        if at.tzinfo is None:
            raise ValidationError("waiver evaluation time must be timezone-aware")
        return self.expires_at is None or at < self.expires_at


class GateLevel(StrEnum):
    TASK = "TASK"
    INTEGRATION = "INTEGRATION"
    MILESTONE = "MILESTONE"
    RELEASE = "RELEASE"


class GateState(StrEnum):
    PENDING = "PENDING"
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    WAIVED = "WAIVED"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    claim: str
    allowed_validator_ids: frozenset[str]
    allowed_kinds: frozenset[ValidatorKind]
    require_independent: bool = False
    minimum_passes: int = 1

    def __post_init__(self) -> None:
        if not self.claim or not self.allowed_validator_ids or not self.allowed_kinds:
            raise ValidationError("evidence requirement must constrain claim and validators")
        if self.minimum_passes < 1:
            raise ValidationError("minimum_passes must be positive")


@dataclass(frozen=True, slots=True)
class GateDefinition:
    gate_id: str
    level: GateLevel
    evidence: tuple[EvidenceRequirement, ...]
    children: tuple[str, ...] = ()
    waiver_allowed: bool = False

    def __post_init__(self) -> None:
        if not self.gate_id or len(set(self.children)) != len(self.children):
            raise ValidationError("gate identity and unique children are required")
        if self.level is GateLevel.TASK and self.children:
            raise ValidationError("task gates cannot have child gates")
        if not self.evidence:
            raise ValidationError("every gate requires its own evidence policy")


_LEVEL_RANK = {
    GateLevel.TASK: 0,
    GateLevel.INTEGRATION: 1,
    GateLevel.MILESTONE: 2,
    GateLevel.RELEASE: 3,
}


class GateGraph:
    def __init__(self, gates: Iterable[GateDefinition]) -> None:
        gate_list = tuple(gates)
        self._gates = {gate.gate_id: gate for gate in gate_list}
        if len(self._gates) != len(gate_list):
            raise ValidationError("gate IDs must be unique")
        for gate in gate_list:
            for child_id in gate.children:
                child = self._gates.get(child_id)
                if child is None:
                    raise ValidationError(f"unknown child gate: {child_id}")
                if _LEVEL_RANK[gate.level] != _LEVEL_RANK[child.level] + 1:
                    raise ValidationError("gate hierarchy must advance one level at a time")

    def evaluate(
        self,
        gate_id: str,
        *,
        ledger: EvidenceLedger,
        binding: EvidenceBinding,
        authority: AcceptanceAuthority,
        waivers: Iterable[ApprovedWaiver] = (),
        at: datetime | None = None,
    ) -> GateState:
        if authority is not AcceptanceAuthority.CORE:
            raise ValidationError("only Core may evaluate canonical gate state")
        now = datetime.now(UTC) if at is None else at
        if now.tzinfo is None:
            raise ValidationError("gate evaluation time must be timezone-aware")
        try:
            gate = self._gates[gate_id]
        except KeyError as error:
            raise ValidationError(f"unknown gate: {gate_id}") from error

        active_waivers = {waiver.gate_id: waiver for waiver in waivers if waiver.is_active(at=now)}
        if gate.gate_id in active_waivers:
            if not gate.waiver_allowed:
                raise ValidationError("this gate cannot be waived")
            return GateState.WAIVED

        child_states = [
            self.evaluate(
                child,
                ledger=ledger,
                binding=binding,
                authority=authority,
                waivers=active_waivers.values(),
                at=now,
            )
            for child in gate.children
        ]
        for state in (GateState.FAIL, GateState.BLOCKED, GateState.STALE, GateState.PENDING):
            if state in child_states:
                return state

        states = [self._evaluate_requirement(item, ledger, binding) for item in gate.evidence]
        for state in (GateState.FAIL, GateState.BLOCKED, GateState.STALE, GateState.PENDING):
            if state in states:
                return state
        return GateState.PASS

    @staticmethod
    def _evaluate_requirement(
        requirement: EvidenceRequirement,
        ledger: EvidenceLedger,
        binding: EvidenceBinding,
    ) -> GateState:
        candidates = [
            entry
            for entry in ledger.entries
            if entry.claim == requirement.claim
            and entry.validator_id in requirement.allowed_validator_ids
            and entry.validator_kind in requirement.allowed_kinds
            and (not requirement.require_independent or entry.independent_of_executor)
        ]
        current = [
            entry for entry in candidates if ledger.state(entry, binding) is EvidenceState.CURRENT
        ]
        if any(entry.outcome is EvidenceOutcome.FAIL for entry in current):
            return GateState.FAIL
        if any(entry.outcome is EvidenceOutcome.BLOCKED for entry in current):
            return GateState.BLOCKED
        passes = sum(entry.outcome is EvidenceOutcome.PASS for entry in current)
        if passes >= requirement.minimum_passes:
            return GateState.PASS
        if candidates:
            return GateState.STALE
        return GateState.PENDING


def _hash_payload(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
