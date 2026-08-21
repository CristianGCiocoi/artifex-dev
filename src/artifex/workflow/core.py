"""Typed workflow contracts whose state can only advance through Core policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum

from artifex.policy import AcceptanceAuthority, InstructionTrust, can_supply_instructions


class WorkflowError(ValueError):
    """A workflow request failed a contract or authority check."""


class LivenessViolation(WorkflowError):
    """Execution exceeded a mechanical liveness bound."""


class StageState(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    CLAIMED_COMPLETE = "CLAIMED_COMPLETE"
    VALIDATING = "VALIDATING"
    ACCEPTED = "ACCEPTED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class ExecutionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    REBASE_REQUIRED = "REBASE_REQUIRED"


@dataclass(frozen=True, slots=True)
class ExecutionBaseline:
    """The exact semantic basis given to a worker at execution start."""

    base_commit: str
    contract_hash: str
    project_model_fingerprint: str

    def __post_init__(self) -> None:
        for name, value in (
            ("base_commit", self.base_commit),
            ("contract_hash", self.contract_hash),
            ("project_model_fingerprint", self.project_model_fingerprint),
        ):
            if not value or value.strip() != value:
                raise WorkflowError(f"{name} must be a non-empty normalized value")

    def matches(self, current: ExecutionBaseline) -> bool:
        return self == current


def classify_execution_result(
    worker_baseline: ExecutionBaseline,
    current_baseline: ExecutionBaseline,
    claimed_status: ExecutionStatus,
) -> ExecutionStatus:
    """A stale worker can never publish a successful result."""

    if not worker_baseline.matches(current_baseline):
        return ExecutionStatus.REBASE_REQUIRED
    return claimed_status


@dataclass(frozen=True, slots=True)
class StageTransition:
    source: StageState
    target: StageState

    def __post_init__(self) -> None:
        if self.source == self.target:
            raise WorkflowError("a stage transition must change state")


@dataclass(frozen=True, slots=True)
class LivenessPolicy:
    max_stage_visits: int = 8
    max_no_progress_observations: int = 3
    max_stall_seconds: float = 900.0

    def __post_init__(self) -> None:
        if min(self.max_stage_visits, self.max_no_progress_observations) < 1:
            raise WorkflowError("liveness counters must be positive")
        if self.max_stall_seconds <= 0:
            raise WorkflowError("max_stall_seconds must be positive")


_STANDARD_TRANSITIONS = (
    StageTransition(StageState.PENDING, StageState.READY),
    StageTransition(StageState.PENDING, StageState.BLOCKED),
    StageTransition(StageState.READY, StageState.RUNNING),
    StageTransition(StageState.READY, StageState.BLOCKED),
    StageTransition(StageState.RUNNING, StageState.CLAIMED_COMPLETE),
    StageTransition(StageState.RUNNING, StageState.READY),
    StageTransition(StageState.RUNNING, StageState.FAILED),
    StageTransition(StageState.RUNNING, StageState.BLOCKED),
    StageTransition(StageState.CLAIMED_COMPLETE, StageState.VALIDATING),
    StageTransition(StageState.CLAIMED_COMPLETE, StageState.RUNNING),
    StageTransition(StageState.VALIDATING, StageState.ACCEPTED),
    StageTransition(StageState.VALIDATING, StageState.RUNNING),
    StageTransition(StageState.VALIDATING, StageState.FAILED),
    StageTransition(StageState.BLOCKED, StageState.READY),
)


@dataclass(frozen=True, slots=True)
class StageContract:
    """Immutable requirements for running and validating one stage."""

    stage_id: str
    requires: tuple[str, ...]
    produces: tuple[str, ...]
    capabilities: frozenset[str]
    validators: tuple[str, ...]
    transitions: tuple[StageTransition, ...] = _STANDARD_TRANSITIONS
    liveness: LivenessPolicy = field(default_factory=LivenessPolicy)

    def __post_init__(self) -> None:
        if not self.stage_id:
            raise WorkflowError("stage_id is required")
        if not self.validators:
            raise WorkflowError("a stage must name at least one validator")
        if len(set(self.requires)) != len(self.requires):
            raise WorkflowError("duplicate stage requirements are not allowed")
        if len(set(self.produces)) != len(self.produces):
            raise WorkflowError("duplicate stage outputs are not allowed")
        if len(set(self.transitions)) != len(self.transitions):
            raise WorkflowError("duplicate transitions are not allowed")

    @property
    def fingerprint(self) -> str:
        payload = {
            "stage_id": self.stage_id,
            "requires": self.requires,
            "produces": self.produces,
            "capabilities": sorted(self.capabilities),
            "validators": self.validators,
            "transitions": [(item.source, item.target) for item in self.transitions],
            "liveness": {
                "max_stage_visits": self.liveness.max_stage_visits,
                "max_no_progress_observations": self.liveness.max_no_progress_observations,
                "max_stall_seconds": self.liveness.max_stall_seconds,
            },
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def permits(self, source: StageState, target: StageState) -> bool:
        return StageTransition(source, target) in self.transitions


@dataclass(frozen=True, slots=True)
class StageRuntime:
    contract: StageContract
    state: StageState = StageState.PENDING
    baseline: ExecutionBaseline | None = None
    outputs: frozenset[str] = frozenset()


class WorkflowEngine:
    """In-memory authority that enforces stage contracts deterministically."""

    def __init__(self) -> None:
        self._stages: dict[str, StageRuntime] = {}

    def register(self, contract: StageContract) -> StageRuntime:
        if contract.stage_id in self._stages:
            raise WorkflowError(f"stage already registered: {contract.stage_id}")
        runtime = StageRuntime(contract)
        self._stages[contract.stage_id] = runtime
        return runtime

    def get(self, stage_id: str) -> StageRuntime:
        try:
            return self._stages[stage_id]
        except KeyError as error:
            raise WorkflowError(f"unknown stage: {stage_id}") from error

    def transition(
        self,
        stage_id: str,
        target: StageState,
        *,
        authority: AcceptanceAuthority | None = None,
    ) -> StageRuntime:
        runtime = self.get(stage_id)
        if target is StageState.ACCEPTED and authority is not AcceptanceAuthority.CORE:
            raise WorkflowError("only Core may transition canonical acceptance")
        if not runtime.contract.permits(runtime.state, target):
            raise WorkflowError(f"transition not permitted: {runtime.state} -> {target}")
        updated = replace(runtime, state=target)
        self._stages[stage_id] = updated
        return updated

    def start(
        self,
        stage_id: str,
        *,
        available_inputs: set[str],
        available_capabilities: set[str],
        baseline: ExecutionBaseline,
    ) -> StageRuntime:
        runtime = self.get(stage_id)
        missing_inputs = set(runtime.contract.requires) - available_inputs
        missing_capabilities = set(runtime.contract.capabilities) - available_capabilities
        if missing_inputs or missing_capabilities:
            raise WorkflowError(
                f"stage prerequisites missing: inputs={sorted(missing_inputs)}, "
                f"capabilities={sorted(missing_capabilities)}"
            )
        running = self.transition(stage_id, StageState.RUNNING)
        running = replace(running, baseline=baseline)
        self._stages[stage_id] = running
        return running

    def claim_complete(self, stage_id: str, *, outputs: set[str]) -> StageRuntime:
        runtime = self.get(stage_id)
        missing = set(runtime.contract.produces) - outputs
        if missing:
            raise WorkflowError(f"completion claim is missing outputs: {sorted(missing)}")
        claimed = self.transition(stage_id, StageState.CLAIMED_COMPLETE)
        claimed = replace(claimed, outputs=frozenset(outputs))
        self._stages[stage_id] = claimed
        return claimed


class LivenessStatus(StrEnum):
    PROGRESS = "PROGRESS"
    NO_PROGRESS = "NO_PROGRESS"
    REVISIT_LIMIT = "REVISIT_LIMIT"
    NO_PROGRESS_LIMIT = "NO_PROGRESS_LIMIT"
    STALLED = "STALLED"


@dataclass(frozen=True, slots=True)
class LivenessReport:
    status: LivenessStatus
    stage_id: str
    visits: int
    no_progress_observations: int


@dataclass(slots=True)
class _Observation:
    token: str
    visits: int
    no_progress: int
    last_progress_at: datetime
    last_observed_at: datetime


class LivenessGuard:
    def __init__(self, policy: LivenessPolicy) -> None:
        self._policy = policy
        self._observations: dict[str, _Observation] = {}

    def observe(self, stage_id: str, progress_token: str, *, at: datetime) -> LivenessReport:
        previous = self._observations.get(stage_id)
        if previous is None:
            self._observations[stage_id] = _Observation(progress_token, 1, 0, at, at)
            return LivenessReport(LivenessStatus.PROGRESS, stage_id, 1, 0)
        if at < previous.last_observed_at:
            raise WorkflowError("liveness observations must be chronological")

        visits = previous.visits + 1
        if visits > self._policy.max_stage_visits:
            raise LivenessViolation(LivenessStatus.REVISIT_LIMIT)
        if progress_token != previous.token:
            self._observations[stage_id] = _Observation(progress_token, visits, 0, at, at)
            return LivenessReport(LivenessStatus.PROGRESS, stage_id, visits, 0)

        no_progress = previous.no_progress + 1
        elapsed = (at - previous.last_progress_at).total_seconds()
        if elapsed >= self._policy.max_stall_seconds:
            raise LivenessViolation(LivenessStatus.STALLED)
        if no_progress >= self._policy.max_no_progress_observations:
            raise LivenessViolation(LivenessStatus.NO_PROGRESS_LIMIT)
        self._observations[stage_id] = _Observation(
            progress_token, visits, no_progress, previous.last_progress_at, at
        )
        return LivenessReport(LivenessStatus.NO_PROGRESS, stage_id, visits, no_progress)


def require_instruction_authority(trust: InstructionTrust) -> None:
    """Reject prompt-like content obtained from external project data."""

    if not can_supply_instructions(trust):
        raise WorkflowError("external data cannot supply workflow instructions")
