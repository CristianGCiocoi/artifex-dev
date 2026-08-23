"""Acceptance is derived from immutable contracts and verified evidence."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
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
        if not isinstance(self.name, str) or not self.name or len(self.name) > 200:
            raise ValidationError("measured fact names are required")
        if scrub_secrets(self.name) != self.name:
            raise ValidationError("measured fact names must be secret-safe")
        if not isinstance(self.value, (str, int, float, bool, type(None))):
            raise ValidationError("measured fact values must be finite JSON scalars")
        if isinstance(self.value, float) and not math.isfinite(self.value):
            raise ValidationError("measured fact numeric values must be finite")
        if isinstance(self.value, str):
            if len(self.value) > 1_000:
                raise ValidationError("measured fact string values must be at most 1000 characters")
            if scrub_secrets(self.value) != self.value:
                raise ValidationError("measured fact values must be secret-safe")


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
_MAX_EVIDENCE_CLAIM = 1_000
_IDENTITY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
_EVIDENCE_ID_PATTERN = re.compile(r"EVD-[A-Z0-9][A-Z0-9-]*")
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_loads(value: str) -> Any:
    return json.loads(value, object_pairs_hook=_strict_json_object)


def _secret_safe_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{label} is missing or exceeds its canonical length bound")
    if scrub_secrets(value) != value:
        raise ValidationError(f"{label} must be secret-safe")
    return value


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
        if (
            not isinstance(self.evidence_id, str)
            or len(self.evidence_id) > 128
            or _EVIDENCE_ID_PATTERN.fullmatch(self.evidence_id) is None
        ):
            raise ValidationError("evidence IDs must use the canonical EVD- pattern")
        for value, label, pattern in (
            (self.validator_id, "validator ID", _IDENTITY_PATTERN),
            (self.producer_id, "producer ID", _IDENTITY_PATTERN),
            (self.validator_version, "validator version", _VERSION_PATTERN),
        ):
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise ValidationError(f"invalid canonical {label}")
            if scrub_secrets(value) != value:
                raise ValidationError(f"canonical {label} must be secret-safe")
        _secret_safe_text(self.claim, label="evidence claim", maximum=_MAX_EVIDENCE_CLAIM)
        if not isinstance(self.validator_kind, ValidatorKind):
            raise ValidationError("invalid canonical validator kind")
        if not isinstance(self.outcome, EvidenceOutcome):
            raise ValidationError("invalid canonical evidence outcome")
        if not isinstance(self.facts, tuple) or any(
            not isinstance(fact, MeasuredFact) for fact in self.facts
        ):
            raise ValidationError("canonical evidence facts must be measured facts")
        if not isinstance(self.binding, EvidenceBinding):
            raise ValidationError("invalid canonical evidence binding")
        if (
            not isinstance(self.output, str)
            or len(self.output) > _MAX_EVIDENCE_OUTPUT
            or scrub_secrets(self.output) != self.output
        ):
            raise ValidationError("canonical evidence output must be minimized and secret-safe")
        if not isinstance(self.recorded_at, datetime) or self.recorded_at.tzinfo is None:
            raise ValidationError("evidence timestamps must be timezone-aware")
        if not isinstance(self.independent_of_executor, bool):
            raise ValidationError("evidence independence must be boolean")
        if not isinstance(self.entry_hash, str) or _HASH_PATTERN.fullmatch(self.entry_hash) is None:
            raise ValidationError("evidence entry hash must be canonical SHA-256")

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
        self._historical_ids: set[str] = set()
        self._historical_invalidations: dict[str, str] = {}
        self._journal_path = journal_path
        if journal_path is not None and journal_path.exists():
            self._load_journal()

    @classmethod
    def open_canonical(
        cls, trusted_validators: Mapping[str, str], *, journal_root: Path
    ) -> EvidenceLedger:
        """Audit the read-only legacy journal, then open the schema-2 append path."""

        ledger = cls(trusted_validators)
        ledger._load_legacy_journal(journal_root / "ledger.jsonl")
        ledger._journal_path = journal_root / "ledger-v2.jsonl"
        if ledger._journal_path.exists():
            ledger._load_journal()
        return ledger

    @property
    def entries(self) -> tuple[EvidenceEntry, ...]:
        return tuple(self._entries)

    def append(self, entry: EvidenceEntry) -> None:
        self._validate_entry(entry)
        self._persist({"type": "EVIDENCE", "entry": self._entry_payload(entry)})
        self._entries.append(entry)

    def _validate_entry(self, entry: EvidenceEntry) -> None:
        # The canonical codec is also the write boundary: a directly constructed
        # dataclass may not bypass schema, type, or round-trip invariants.
        decoded = self._entry_from_payload(self._entry_payload(entry))
        if decoded != entry:
            raise ValidationError("canonical evidence codec is not a stable round trip")
        if self._trusted.get(entry.validator_id) != entry.validator_version:
            raise ValidationError("untrusted or spoofed validator identity")
        if not entry.verify_integrity():
            raise ValidationError("evidence integrity check failed")
        if entry.evidence_id in self._historical_ids or any(
            item.evidence_id == entry.evidence_id for item in self._entries
        ):
            raise ValidationError(f"duplicate evidence ID: {entry.evidence_id}")

    def invalidate(self, evidence_ids: Iterable[str], *, reason: str) -> None:
        _secret_safe_text(reason, label="invalidation reason", maximum=500)
        known = {entry.evidence_id for entry in self._entries}
        for evidence_id in evidence_ids:
            if (
                not isinstance(evidence_id, str)
                or _EVIDENCE_ID_PATTERN.fullmatch(evidence_id) is None
                or evidence_id not in known
            ):
                raise ValidationError(f"cannot invalidate unknown evidence: {evidence_id}")
            if evidence_id in self._invalidations:
                raise ValidationError(f"duplicate evidence invalidation: {evidence_id}")
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
        encoded = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
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
                event = _strict_json_loads(line)
                if not isinstance(event, Mapping):
                    raise ValidationError("evidence journal event must be an object")
                event_type = event.get("type")
                if event_type == "EVIDENCE":
                    if set(event) != {"type", "entry"} or not isinstance(
                        event.get("entry"), Mapping
                    ):
                        raise ValidationError("invalid evidence journal entry event")
                    entry = self._entry_from_payload(event["entry"])
                    self._validate_entry(entry)
                    self._entries.append(entry)
                elif event_type == "INVALIDATION":
                    evidence_id = event.get("evidence_id")
                    reason = event.get("reason")
                    if (
                        set(event) != {"type", "evidence_id", "reason"}
                        or not isinstance(evidence_id, str)
                        or _EVIDENCE_ID_PATTERN.fullmatch(evidence_id) is None
                        or not isinstance(reason, str)
                        or not reason
                        or len(reason) > 500
                        or scrub_secrets(reason) != reason
                        or evidence_id in self._invalidations
                        or evidence_id
                        not in {entry.evidence_id for entry in self._entries}
                    ):
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
        # Lazy import avoids a core<->codec import cycle while retaining one canonical encoder.
        from artifex.validation.evidence import evidence_to_payload

        return evidence_to_payload(entry)

    def _entry_from_payload(self, payload: Mapping[str, Any]) -> EvidenceEntry:
        # Journal loading uses the same schema/integrity/identity decoder as YAML and JSON.
        from artifex.validation.evidence import evidence_from_payload

        legacy_keys = {
            "evidence_id",
            "validator_id",
            "validator_version",
            "validator_kind",
            "claim",
            "outcome",
            "facts",
            "binding",
            "output",
            "recorded_at",
            "producer_id",
            "independent_of_executor",
            "entry_hash",
        }
        if "schema_version" not in payload and legacy_keys <= set(payload):
            raise ValidationError(
                "legacy unversioned evidence journal is historical; preserve it and use "
                "ledger-v2.jsonl"
            )
        try:
            return evidence_from_payload(
                payload,
                trusted_validators=self._trusted,
                require_independent=False,
            )
        except ValidationError as exc:
            raise ValidationError(f"corrupt evidence journal: {exc}") from exc

    def _load_legacy_journal(self, path: Path) -> None:
        """Classify known pre-codec events without exposing them as current entries."""

        if not path.exists():
            return
        try:
            content = path.read_text(encoding="utf-8")
            if content and not content.endswith("\n"):
                raise ValidationError("corrupt legacy evidence journal: truncated final event")
            for line_number, line in enumerate(content.splitlines(), start=1):
                if not line.strip():
                    continue
                event = _strict_json_loads(line)
                if not isinstance(event, Mapping):
                    raise ValidationError(
                        f"corrupt legacy evidence journal event at line {line_number}"
                    )
                event_type = event.get("type")
                if event_type == "EVIDENCE" and set(event) == {"type", "entry"}:
                    payload = event.get("entry")
                    if not isinstance(payload, Mapping):
                        raise ValidationError(
                            f"corrupt legacy evidence journal event at line {line_number}"
                        )
                    evidence_id = self._legacy_entry_id(payload)
                    if evidence_id in self._historical_ids or any(
                        item.evidence_id == evidence_id for item in self._entries
                    ):
                        raise ValidationError(f"duplicate evidence ID: {evidence_id}")
                    self._historical_ids.add(evidence_id)
                elif event_type == "INVALIDATION" and set(event) == {
                    "type",
                    "evidence_id",
                    "reason",
                }:
                    invalidated_id = event.get("evidence_id")
                    reason_value = event.get("reason")
                    if (
                        not isinstance(invalidated_id, str)
                        or invalidated_id not in self._historical_ids
                        or not isinstance(reason_value, str)
                        or not reason_value
                        or invalidated_id in self._historical_invalidations
                    ):
                        raise ValidationError("invalid legacy evidence invalidation event")
                    self._historical_invalidations[invalidated_id] = reason_value
                else:
                    raise ValidationError(
                        f"unknown legacy evidence journal event at line {line_number}"
                    )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError(f"corrupt legacy evidence journal: {exc}") from exc

    @staticmethod
    def _legacy_entry_id(payload: Mapping[str, Any]) -> str:
        """Validate the one known unversioned EvidenceEntry journal representation."""

        legacy_keys = {
            "evidence_id",
            "validator_id",
            "validator_version",
            "validator_kind",
            "claim",
            "outcome",
            "facts",
            "binding",
            "output",
            "recorded_at",
            "producer_id",
            "independent_of_executor",
            "entry_hash",
        }
        if set(payload) != legacy_keys:
            raise ValidationError("unknown legacy evidence journal entry representation")
        try:
            binding = payload["binding"]
            facts = payload["facts"]
            scalar_types = (str, int, float, bool, type(None))
            if (
                not isinstance(binding, Mapping)
                or set(binding) != {"base_commit", "contract_hash", "project_model_fingerprints"}
                or not isinstance(facts, list)
                or not isinstance(payload["independent_of_executor"], bool)
                or not isinstance(payload["evidence_id"], str)
                or re.fullmatch(r"EVD-[A-Z0-9][A-Z0-9-]*", payload["evidence_id"]) is None
                or not isinstance(payload["validator_id"], str)
                or not payload["validator_id"]
                or not isinstance(payload["validator_version"], str)
                or not payload["validator_version"]
                or not isinstance(payload["claim"], str)
                or not payload["claim"]
                or not isinstance(payload["output"], str)
                or not isinstance(payload["producer_id"], str)
                or not payload["producer_id"]
                or not isinstance(payload["entry_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", payload["entry_hash"]) is None
                or not isinstance(binding["base_commit"], str)
                or re.fullmatch(r"[0-9a-f]{40}", binding["base_commit"]) is None
                or not isinstance(binding["contract_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", binding["contract_hash"]) is None
                or not isinstance(binding["project_model_fingerprints"], list)
                or not binding["project_model_fingerprints"]
                or any(
                    not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
                    for item in binding["project_model_fingerprints"]
                )
                or any(
                    not isinstance(item, Mapping)
                    or set(item) != {"name", "value"}
                    or not isinstance(item["name"], str)
                    or not item["name"]
                    or not isinstance(item["value"], scalar_types)
                    or (isinstance(item["value"], float) and not math.isfinite(item["value"]))
                    for item in facts
                )
            ):
                raise ValueError("legacy evidence structure invalid")
            recorded_at = payload["recorded_at"]
            if not isinstance(recorded_at, str):
                raise ValueError("legacy evidence timestamp invalid")
            timestamp = datetime.fromisoformat(recorded_at)
            if timestamp.tzinfo is None:
                raise ValueError("legacy evidence timestamp must be timezone-aware")
            entry = EvidenceEntry(
                evidence_id=payload["evidence_id"],
                validator_id=payload["validator_id"],
                validator_version=payload["validator_version"],
                validator_kind=ValidatorKind(payload["validator_kind"]),
                claim=payload["claim"],
                outcome=EvidenceOutcome(payload["outcome"]),
                facts=tuple(MeasuredFact(item["name"], item["value"]) for item in facts),
                binding=EvidenceBinding(
                    binding["base_commit"],
                    binding["contract_hash"],
                    tuple(binding["project_model_fingerprints"]),
                ),
                output=payload["output"],
                recorded_at=timestamp,
                producer_id=payload["producer_id"],
                independent_of_executor=payload["independent_of_executor"],
                entry_hash=payload["entry_hash"],
            )
            if len(entry.facts) != len(facts) or not entry.verify_integrity():
                raise ValueError("legacy evidence integrity check failed")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"corrupt legacy evidence journal entry: {exc}") from exc
        return entry.evidence_id


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
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"canonical validation payload is invalid: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()
