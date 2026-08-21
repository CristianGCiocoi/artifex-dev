"""Claude standalone integration over the agent-neutral execution boundary.

The adapter deliberately separates planning from launching Claude.  Core can be
installed and all project state can be inspected when the vendor executable is
absent; a caller must explicitly execute a returned :class:`ClaudeExecutionPlan`.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from artifex.compilation._util import model_fingerprint
from artifex.integrations.contracts import (
    Capability,
    CompatibilityRange,
    ConfigurationProvenance,
    ExecutionPacket,
    ExecutionResult,
    HealthReport,
    HealthStatus,
    IntegrationError,
    IntegrationMetadata,
    IntegrationRole,
)
from artifex.integrations.manual import ManualIntegration
from artifex.policy import AcceptanceAuthority
from artifex.project.changeset import ChangeSet, ChangeSetRepository
from artifex.project.git import GitRepository
from artifex.project.model import ProjectLifecycle, WorkflowDepth
from artifex.project.paths import normalize_relative_path, resolve_inside
from artifex.project.repository import ProjectRepository
from artifex.validation import (
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
from artifex.workflow import (
    ExecutionBaseline,
    ExecutionStatus,
    StageContract,
    StageState,
    WorkflowEngine,
)

_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")
_SEMANTIC_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_EPHEMERAL_STATE_DIRECTORIES = frozenset(
    {
        "cache",
        "caches",
        "locks",
        "logs",
        "native-memory",
        "native_memory",
        "pids",
        "run",
        "runs",
        "runtime",
        "scratch",
        "sessions",
        "telemetry",
        "temp",
        "tmp",
        "worktrees",
    }
)
_CLAUDE_VALIDATOR_ID = "VAL-CLAUDE-STANDARD"
_CLAUDE_VALIDATOR_VERSION = "1"
_STATUS_ALIASES = {
    "success": ExecutionStatus.SUCCESS,
    "succeeded": ExecutionStatus.SUCCESS,
    "complete": ExecutionStatus.SUCCESS,
    "completed": ExecutionStatus.SUCCESS,
    "pass": ExecutionStatus.SUCCESS,
    "passed": ExecutionStatus.SUCCESS,
    "fail": ExecutionStatus.FAIL,
    "failed": ExecutionStatus.FAIL,
    "failure": ExecutionStatus.FAIL,
    "error": ExecutionStatus.FAIL,
    "blocked": ExecutionStatus.BLOCKED,
    "cancel": ExecutionStatus.CANCELLED,
    "canceled": ExecutionStatus.CANCELLED,
    "cancelled": ExecutionStatus.CANCELLED,
    "interrupted": ExecutionStatus.CANCELLED,
    "rebase_required": ExecutionStatus.REBASE_REQUIRED,
    "stale": ExecutionStatus.REBASE_REQUIRED,
}


@dataclass(frozen=True, slots=True)
class ClaudeDetection:
    """Non-throwing observation of the locally available Claude executable."""

    installed: bool
    executable: str | None = None
    version: str | None = None
    detail: str = ""

    @property
    def supports_mcp(self) -> bool:
        return self.installed and self.version is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "installed": self.installed,
            "executable": self.executable,
            "version": self.version,
            "supports_mcp": self.supports_mcp,
            "detail": self.detail,
        }


def detect_claude(executable: str = "claude", *, timeout: float = 3.0) -> ClaudeDetection:
    """Detect Claude Code without making it a Core dependency.

    Missing executables, timeouts, non-zero exits, and unrecognised version
    output are represented as data instead of escaping across the adapter.
    """

    resolved = shutil.which(executable)
    if resolved is None:
        return ClaudeDetection(False, detail=f"{executable} executable was not found")
    try:
        result = subprocess.run(
            [resolved, "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ClaudeDetection(False, resolved, detail=f"version detection failed: {exc}")
    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0:
        detail = output or f"version command exited with {result.returncode}"
        return ClaudeDetection(False, resolved, detail=detail)
    match = _VERSION_PATTERN.search(output)
    if match is None:
        return ClaudeDetection(True, resolved, detail=output or "version was not reported")
    return ClaudeDetection(True, resolved, match.group(1), output)


@dataclass(frozen=True, slots=True)
class ClaudeExecutionPlan:
    """A non-mutating, worktree-bound description of a possible Claude run."""

    packet: ExecutionPacket
    project_root: str
    worktree_root: str
    command: tuple[str, ...]
    prompt: str

    def to_dict(self) -> dict[str, object]:
        return {
            "packet": self.packet.to_dict(),
            "project_root": self.project_root,
            "worktree_root": self.worktree_root,
            "command": list(self.command),
            "prompt": self.prompt,
            "mutating": False,
        }


ClaudeHarnessRunner = Callable[[ClaudeExecutionPlan], Mapping[str, Any] | str | None]


@dataclass(frozen=True, slots=True)
class ClaudeWorkflowOutcome:
    """Core-classified outcome of one adapter-led STANDARD workflow."""

    execution_result: ExecutionResult
    stage_state: StageState
    gate_state: GateState
    evidence: EvidenceEntry
    evidence_journal: str
    changeset_status: str | None = None

    @property
    def accepted(self) -> bool:
        return self.stage_state is StageState.ACCEPTED and self.gate_state is GateState.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_result": self.execution_result.to_dict(),
            "stage_state": self.stage_state.value,
            "gate_state": self.gate_state.value,
            "evidence_id": self.evidence.evidence_id,
            "evidence_outcome": self.evidence.outcome.value,
            "evidence_journal": self.evidence_journal,
            "changeset_status": self.changeset_status,
            "accepted": self.accepted,
            "canonical_authority": "CORE",
        }


@dataclass(frozen=True, slots=True)
class ContinuitySnapshot:
    """Portable semantic state sufficient to resume without vendor memory."""

    semantic_state: tuple[Mapping[str, Any], ...]
    semantic_fingerprint: str
    execution_packet: Mapping[str, Any] | None = None
    schema_version: str = "1.0"
    kind: str = "ARTIFEX_CONTINUITY_SNAPSHOT"

    def __post_init__(self) -> None:
        expected = _semantic_fingerprint(self.semantic_state, self.execution_packet)
        if self.schema_version != "1.0" or self.kind != "ARTIFEX_CONTINUITY_SNAPSHOT":
            raise ValueError("unsupported continuity snapshot contract")
        if self.semantic_fingerprint != expected:
            raise ValueError("continuity snapshot fingerprint does not match content")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "semantic_state": [dict(item) for item in self.semantic_state],
            "semantic_fingerprint": self.semantic_fingerprint,
        }
        if self.execution_packet is not None:
            value["execution_packet"] = dict(self.execution_packet)
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ContinuitySnapshot:
        states = value.get("semantic_state")
        if not isinstance(states, Sequence) or isinstance(states, (str, bytes, bytearray)):
            raise ValueError("semantic_state must be an array")
        normalized: list[Mapping[str, Any]] = []
        for state in states:
            if not isinstance(state, Mapping):
                raise ValueError("semantic_state entries must be objects")
            normalized.append(dict(state))
        packet = value.get("execution_packet")
        if packet is not None and not isinstance(packet, Mapping):
            raise ValueError("execution_packet must be an object")
        return cls(
            tuple(normalized),
            str(value.get("semantic_fingerprint", "")),
            dict(packet) if packet is not None else None,
            str(value.get("schema_version", "")),
            str(value.get("kind", "")),
        )


class ClaudeIntegration:
    """First-class Claude interface, harness, and implementer adapter."""

    def __init__(self, detection: ClaudeDetection | None = None) -> None:
        self.detection = detect_claude() if detection is None else detection
        self._portable = ManualIntegration()

    @property
    def metadata(self) -> IntegrationMetadata:
        capabilities = {
            Capability.INTERACTIVE.value,
            Capability.HEADLESS.value,
            Capability.SKILLS.value,
            Capability.WORKTREES.value,
            Capability.STRUCTURED_OUTPUT.value,
            Capability.REPOSITORY_READ.value,
            Capability.REPOSITORY_WRITE.value,
            Capability.TEST_EXECUTION.value,
        }
        if self.detection.supports_mcp:
            capabilities.add(Capability.MCP.value)
        return IntegrationMetadata(
            integration_id="claude",
            name="Claude",
            version="1.0.0",
            compatibility=CompatibilityRange("0.1.0", "1.0.0"),
            tested_external_versions=(self.detection.version or "not-detected",),
            roles=frozenset(
                {
                    IntegrationRole.INTERFACE,
                    IntegrationRole.HARNESS,
                    IntegrationRole.IMPLEMENTER,
                }
            ),
            capabilities=frozenset(capabilities),
            configuration=ConfigurationProvenance("interface-pack", "interface_packs/claude"),
        )

    def health(self) -> HealthReport:
        if not self.detection.installed:
            return HealthReport(
                HealthStatus.DEGRADED,
                "Claude is unavailable; Core and portable state remain usable",
                {
                    "core_independence": HealthStatus.PASS,
                    "claude_executable": HealthStatus.DEGRADED,
                },
            )
        version_status = (
            HealthStatus.PASS if self.detection.version is not None else HealthStatus.UNKNOWN
        )
        return HealthReport(
            HealthStatus.PASS,
            f"Claude {self.detection.version or 'version unknown'} is available",
            {"core_independence": HealthStatus.PASS, "claude_executable": version_status},
        )

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]:
        return self._portable.read_project_status(project_root)

    read_context = read_project_status

    def prepare_execution(
        self,
        *,
        task_contract: Mapping[str, Any],
        context: Mapping[str, Any],
        base_commit: str,
        project_model_fingerprint: str,
        acceptance_criteria: Sequence[Any],
        ownership: Mapping[str, Any],
        expected_result: Mapping[str, Any],
        interfaces: Sequence[str] = (),
        invariants: Sequence[str] = (),
    ) -> ExecutionPacket:
        return self._portable.prepare_execution(
            task_contract=task_contract,
            context=context,
            base_commit=base_commit,
            project_model_fingerprint=project_model_fingerprint,
            acceptance_criteria=acceptance_criteria,
            ownership=ownership,
            expected_result=expected_result,
            interfaces=interfaces,
            invariants=invariants,
        )

    create_execution_packet = prepare_execution

    def plan_stage_execution(
        self,
        packet: ExecutionPacket,
        *,
        project_root: str | Path,
        worktree_root: str | Path | None = None,
    ) -> ClaudeExecutionPlan:
        """Validate baseline/worktree binding and return a launch plan only."""

        if not self.detection.installed or self.detection.executable is None:
            raise RuntimeError("Claude execution is unavailable; install or configure Claude Code")
        project = Path(project_root).resolve()
        worktree = project if worktree_root is None else Path(worktree_root).resolve()
        if not (project / ".artifex").is_dir():
            raise ValueError(f"ARTIFEX project metadata not found at {project}")
        if _git_common_dir(project) != _git_common_dir(worktree):
            raise ValueError("execution worktree is not attached to the ARTIFEX project repository")
        if not (worktree / ".artifex").is_dir():
            raise ValueError(f"ARTIFEX project metadata not found in worktree {worktree}")
        observed = GitRepository(worktree).inspect()
        if not observed.initialized or observed.current_commit is None:
            raise ValueError(f"execution worktree has no Git commit: {worktree}")
        if observed.current_commit != packet.base_commit:
            raise ValueError(
                "execution worktree does not match packet base commit: "
                f"expected {packet.base_commit}, observed {observed.current_commit}"
            )
        observed_model_fingerprint = model_fingerprint(
            ProjectRepository(worktree).load().to_dict()
        )
        if observed_model_fingerprint != packet.project_model_fingerprint:
            raise IntegrationError(
                "canonical Project Model fingerprint does not match packet: "
                f"expected {packet.project_model_fingerprint}, "
                f"observed {observed_model_fingerprint}"
            )
        packet_json = json.dumps(packet.to_dict(), sort_keys=True, ensure_ascii=False)
        prompt = (
            "Execute the following ARTIFEX Execution Packet in the selected worktree. "
            "Use repository state rather than conversation memory, stay within ownership, "
            "run the acceptance checks, and return one structured ARTIFEX result object.\n\n"
            f"{packet_json}"
        )
        command = (
            self.detection.executable,
            "--print",
            "--output-format",
            "json",
        )
        return ClaudeExecutionPlan(packet, str(project), str(worktree), command, prompt)

    prepare_stage_execution = plan_stage_execution
    prepare_worktree_execution = plan_stage_execution

    def execute_stage(
        self,
        plan: ClaudeExecutionPlan,
        runner: ClaudeHarnessRunner,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        """Execute only through an explicit injected runner and ingest its bound result."""

        self.plan_stage_execution(
            plan.packet,
            project_root=plan.project_root,
            worktree_root=plan.worktree_root,
        )
        raw_result = runner(plan)
        self.plan_stage_execution(
            plan.packet,
            project_root=plan.project_root,
            worktree_root=plan.worktree_root,
        )
        normalized = self.normalize_result(plan.packet, raw_result)
        return self.submit_result(
            plan.packet, normalized, current_baseline=current_baseline
        )

    def mcp_entry(self, *, python_command: str = "python") -> Mapping[str, Any] | None:
        """Return an opt-in Claude MCP entry; never alter desktop configuration."""

        if not self.detection.supports_mcp:
            return None
        return {
            "mcpServers": {
                "artifex": {
                    "command": python_command,
                    "args": ["-m", "artifex.mcp"],
                    "transport": "stdio",
                }
            }
        }

    mcp_desktop_entry = mcp_entry

    def submit_result(
        self,
        packet: ExecutionPacket,
        result: ExecutionResult,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        packet_bound = result.classified(packet.baseline)
        if packet_bound.status is ExecutionStatus.REBASE_REQUIRED:
            return packet_bound
        current = packet.baseline if current_baseline is None else current_baseline
        return result.classified(current)

    ingest_result = submit_result

    def normalize_result(
        self, packet: ExecutionPacket, raw_result: Mapping[str, Any] | str | None
    ) -> ExecutionResult:
        """Map Claude/tool outcomes into the frozen executor result vocabulary."""

        raw_result = _unwrap_result(raw_result)
        if not isinstance(raw_result, Mapping):
            raise IntegrationError("Claude result must be a bound structured object")
        identities = _result_identity(raw_result)
        if "status" in raw_result or "outcome" in raw_result:
            raw_status = raw_result.get("status", raw_result.get("outcome"))
        elif raw_result.get("is_error") is True:
            raw_status = "fail"
        else:
            raw_status = raw_result.get("subtype", "fail")
        message = str(raw_result.get("message", ""))
        artifacts_value = raw_result.get("artifacts", ())
        validation_value = raw_result.get("validation", {})
        normalized_name = re.sub(r"[\s-]+", "_", str(raw_status).strip().casefold())
        status = _STATUS_ALIASES.get(normalized_name, ExecutionStatus.FAIL)
        if normalized_name not in _STATUS_ALIASES and not message:
            message = f"unrecognized Claude result status: {raw_status!r}"
        artifacts, artifact_error = _mapping_items(artifacts_value)
        if artifact_error:
            status = ExecutionStatus.FAIL
            message = message or artifact_error
        if isinstance(validation_value, Mapping):
            validation = dict(validation_value)
        else:
            validation = {}
            status = ExecutionStatus.FAIL
            message = message or "Claude result validation must be an object"
        result = ExecutionResult(
            status,
            identities.base_commit,
            identities.contract_hash,
            identities.project_model_fingerprint,
            artifacts,
            validation,
            message,
        )
        return result.classified(packet.baseline)

    @staticmethod
    def submit_validation(validation: Mapping[str, Any]) -> Mapping[str, Any]:
        return ManualIntegration.submit_validation(validation)

    def cancel(
        self, packet: ExecutionPacket, *, message: str = "cancelled by Claude harness"
    ) -> ExecutionResult:
        return self._portable.cancel(packet, message=message)

    def initialize_greenfield(
        self, root: str | Path, *, project_id: str, name: str, description: str = ""
    ) -> ProjectRepository:
        repository = ProjectRepository.initialize(
            root,
            project_id=project_id,
            name=name,
            description=description,
            workflow_depth=WorkflowDepth.STANDARD,
        )
        if repository.load().project.lifecycle is not ProjectLifecycle.GREENFIELD:
            raise ValueError("greenfield initialization found pre-existing project content")
        return repository

    initialize_standard_project = initialize_greenfield

    def adopt_brownfield(
        self, root: str | Path, *, project_id: str, name: str, description: str = ""
    ) -> ProjectRepository:
        repository = ProjectRepository.adopt(
            root,
            project_id=project_id,
            name=name,
            description=description,
            workflow_depth=WorkflowDepth.STANDARD,
        )
        if repository.load().project.lifecycle is not ProjectLifecycle.BROWNFIELD:
            raise ValueError("brownfield adoption did not preserve lifecycle")
        return repository

    adopt_standard_project = adopt_brownfield

    @staticmethod
    def save_changeset(repository: ProjectRepository, changeset: ChangeSet) -> str:
        return ChangeSetRepository(repository.store).save(changeset)

    def run_greenfield_standard_workflow(
        self,
        plan: ClaudeExecutionPlan,
        runner: ClaudeHarnessRunner,
        *,
        evidence_id: str,
        recorded_at: datetime,
    ) -> ClaudeWorkflowOutcome:
        repository = ProjectRepository(plan.worktree_root)
        project = repository.load().project
        if project.lifecycle is not ProjectLifecycle.GREENFIELD:
            raise IntegrationError("greenfield STANDARD workflow requires a greenfield project")
        if project.workflow_depth is not WorkflowDepth.STANDARD:
            raise IntegrationError("greenfield workflow depth must be STANDARD")
        return self._run_standard_workflow(
            plan,
            runner,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
            forbidden_artifacts=(".artifex/project-model.json",),
        )

    def run_brownfield_changeset_workflow(
        self,
        plan: ClaudeExecutionPlan,
        runner: ClaudeHarnessRunner,
        *,
        changeset_id: str,
        evidence_id: str,
        recorded_at: datetime,
    ) -> ClaudeWorkflowOutcome:
        repository = ProjectRepository(plan.worktree_root)
        project = repository.load().project
        if project.lifecycle is not ProjectLifecycle.BROWNFIELD:
            raise IntegrationError("brownfield ChangeSet workflow requires a brownfield project")
        if project.workflow_depth is not WorkflowDepth.STANDARD:
            raise IntegrationError("brownfield workflow depth must be STANDARD")
        changesets = ChangeSetRepository(repository.store)
        changeset = changesets.load(changeset_id)
        if changeset.baseline_commit not in (None, plan.packet.base_commit):
            raise IntegrationError("ChangeSet baseline does not match the execution packet")
        if changeset.status.value not in {"PROPOSED", "IMPLEMENTING"}:
            raise IntegrationError("ChangeSet must be PROPOSED or IMPLEMENTING")

        outcome = self._run_standard_workflow(
            plan,
            runner,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
            forbidden_artifacts=(".artifex/project-model.json", changesets.path_for(changeset.id)),
        )
        if outcome.accepted:
            if changeset.status.value == "PROPOSED":
                changeset = changeset.transition(
                    "ACCEPTED", actor="artifex-core", commit=plan.packet.base_commit
                )
                changeset = changeset.transition(
                    "IMPLEMENTING", actor="artifex-core", commit=plan.packet.base_commit
                )
            changeset = changeset.transition(
                "VERIFIED", actor="artifex-core", commit=plan.packet.base_commit
            )
            changesets.save(changeset)
        return replace(outcome, changeset_status=changeset.status.value)

    def _run_standard_workflow(
        self,
        plan: ClaudeExecutionPlan,
        runner: ClaudeHarnessRunner,
        *,
        evidence_id: str,
        recorded_at: datetime,
        forbidden_artifacts: Sequence[str],
    ) -> ClaudeWorkflowOutcome:
        packet = plan.packet
        task_id = str(packet.task_contract.get("id", "CLAUDE-STANDARD"))
        claim = str(packet.acceptance_criteria[0])
        workflow = WorkflowEngine()
        stage = StageContract(
            stage_id=f"STG-{task_id}",
            requires=("project-model",),
            produces=("bound-executor-result",),
            capabilities=frozenset({Capability.REPOSITORY_READ.value}),
            validators=(_CLAUDE_VALIDATOR_ID,),
        )
        workflow.register(stage)
        workflow.transition(stage.stage_id, StageState.READY)
        workflow.start(
            stage.stage_id,
            available_inputs={"project-model"},
            available_capabilities={Capability.REPOSITORY_READ.value},
            baseline=packet.baseline,
        )
        before_artifacts = _snapshot_owned_artifacts(Path(plan.worktree_root), packet)
        execution_result = self.execute_stage(plan, runner)
        artifacts_valid = _artifacts_are_owned_changed_and_present(
            Path(plan.worktree_root),
            packet,
            execution_result,
            before_artifacts,
            forbidden_artifacts=frozenset(
                normalize_relative_path(path) for path in forbidden_artifacts
            ),
        )
        if execution_result.status is not ExecutionStatus.SUCCESS:
            raise IntegrationError(
                "Claude STANDARD workflow requires a bound SUCCESS result before evidence"
            )
        if not artifacts_valid:
            raise IntegrationError(
                "Claude SUCCESS result must contain only safe, owned artifacts changed "
                "by this invocation"
            )
        workflow.claim_complete(stage.stage_id, outputs={"bound-executor-result"})
        workflow.transition(stage.stage_id, StageState.VALIDATING)

        binding = EvidenceBinding(
            packet.base_commit,
            packet.contract_fingerprint,
            (packet.project_model_fingerprint,),
        )
        validation = StructuredInspectionValidator(
            _CLAUDE_VALIDATOR_ID, _CLAUDE_VALIDATOR_VERSION
        ).validate(
            ValidationContext(claim, "claude", binding),
            inspector_id="artifex-core",
            passed=True,
            facts=(
                MeasuredFact("bound_result", execution_result.baseline == packet.baseline),
                MeasuredFact("owned_artifacts_present", artifacts_valid),
            ),
        )
        evidence = EvidenceEntry.create(
            evidence_id, validation, binding, recorded_at=recorded_at
        )
        journal = (
            Path(plan.worktree_root)
            / ".artifex"
            / "validation"
            / "evidence"
            / "claude-standard.jsonl"
        )
        ledger = EvidenceLedger(
            {_CLAUDE_VALIDATOR_ID: _CLAUDE_VALIDATOR_VERSION}, journal_path=journal
        )
        ledger.append(evidence)
        gate = GateGraph(
            (
                GateDefinition(
                    f"G-{task_id}",
                    GateLevel.TASK,
                    (
                        EvidenceRequirement(
                            claim,
                            frozenset({_CLAUDE_VALIDATOR_ID}),
                            frozenset({ValidatorKind.STRUCTURED_INSPECTION}),
                            require_independent=True,
                        ),
                    ),
                ),
            )
        )
        gate_state = gate.evaluate(
            f"G-{task_id}",
            ledger=ledger,
            binding=binding,
            authority=AcceptanceAuthority.CORE,
            at=recorded_at,
        )
        runtime = workflow.get(stage.stage_id)
        if runtime.state is StageState.VALIDATING:
            workflow.transition(
                stage.stage_id,
                StageState.ACCEPTED if gate_state is GateState.PASS else StageState.FAILED,
                authority=(
                    AcceptanceAuthority.CORE if gate_state is GateState.PASS else None
                ),
            )
        return ClaudeWorkflowOutcome(
            execution_result,
            workflow.get(stage.stage_id).state,
            gate_state,
            evidence,
            journal.relative_to(Path(plan.worktree_root)).as_posix(),
        )

    @staticmethod
    def continuity_snapshot(
        project_root: str | Path, *, packet: ExecutionPacket | None = None
    ) -> ContinuitySnapshot:
        root = Path(project_root).resolve()
        state_root = root / ".artifex"
        if not state_root.is_dir():
            raise FileNotFoundError(f"ARTIFEX project metadata not found at {root}")
        state: list[Mapping[str, Any]] = []
        for path in sorted(item for item in state_root.rglob("*") if item.is_file()):
            if path.suffix.casefold() not in _SEMANTIC_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if _is_ephemeral_state_path(relative):
                continue
            try:
                parsed = (
                    json.loads(path.read_text(encoding="utf-8"))
                    if path.suffix.casefold() == ".json"
                    else yaml.safe_load(path.read_text(encoding="utf-8"))
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
                raise ValueError(f"cannot snapshot semantic state {relative}: {exc}") from exc
            state.append({"path": relative, "value": _json_value(parsed)})
        if not state:
            raise ValueError("ARTIFEX project contains no portable semantic state")
        packet_value = packet.to_dict() if packet is not None else None
        frozen_state = tuple(state)
        return ContinuitySnapshot(
            frozen_state,
            _semantic_fingerprint(frozen_state, packet_value),
            packet_value,
        )

    create_continuity_snapshot = continuity_snapshot


def _unwrap_result(value: Mapping[str, Any] | str | None) -> Mapping[str, Any] | str | None:
    if not isinstance(value, Mapping) or "result" not in value:
        return value
    nested = value["result"]
    if isinstance(nested, Mapping):
        merged = dict(value)
        merged.pop("result", None)
        merged.update(nested)
        return merged
    if isinstance(nested, str):
        try:
            decoded = json.loads(nested)
        except json.JSONDecodeError:
            return value
        if isinstance(decoded, Mapping):
            merged = dict(value)
            merged.pop("result", None)
            merged.update(decoded)
            return merged
        return value
    return value


def _result_identity(value: Mapping[str, Any]) -> ExecutionBaseline:
    names = (
        "base_commit",
        "execution_contract_fingerprint",
        "project_model_fingerprint",
    )
    observed: list[str] = []
    for name in names:
        item = value.get(name)
        if not isinstance(item, str) or not item.strip():
            raise IntegrationError(f"Claude result is missing bound identity: {name}")
        observed.append(item)
    return ExecutionBaseline(observed[0], observed[1], observed[2])


def _mapping_items(value: Any) -> tuple[tuple[Mapping[str, Any], ...], str | None]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return (), "Claude result artifacts must be an array"
    if not all(isinstance(item, Mapping) for item in value):
        return (), "Claude result artifacts must contain objects"
    return tuple(dict(item) for item in value), None


def _snapshot_owned_artifacts(root: Path, packet: ExecutionPacket) -> dict[str, str]:
    ownership = packet.ownership.get("paths")
    if not isinstance(ownership, Sequence) or isinstance(ownership, (str, bytes, bytearray)):
        raise IntegrationError("execution packet ownership paths must be an array")
    snapshot: dict[str, str] = {}
    try:
        owned = tuple(normalize_relative_path(str(item)) for item in ownership)
    except (TypeError, ValueError):
        raise IntegrationError("execution packet contains an unsafe ownership path") from None
    if not owned:
        raise IntegrationError("execution packet must own at least one artifact path")
    for path in owned:
        _, target = resolve_inside(root, path)
        candidate = root.joinpath(*path.split("/"))
        if candidate.is_symlink():
            raise IntegrationError(f"owned artifact path cannot be a symlink: {path}")
        if target.is_file():
            snapshot[path] = _file_fingerprint(target)
        elif target.is_dir():
            for child in sorted(item for item in target.rglob("*") if item.is_file()):
                if child.is_symlink():
                    raise IntegrationError("owned artifact directory contains a symlink")
                normalized = normalize_relative_path(child.relative_to(root).as_posix())
                snapshot[normalized] = _file_fingerprint(child)
    return snapshot


def _artifacts_are_owned_changed_and_present(
    root: Path,
    packet: ExecutionPacket,
    result: ExecutionResult,
    before: Mapping[str, str],
    *,
    forbidden_artifacts: frozenset[str],
) -> bool:
    ownership = packet.ownership.get("paths")
    if not isinstance(ownership, Sequence) or isinstance(ownership, (str, bytes, bytearray)):
        return False
    try:
        owned = tuple(normalize_relative_path(str(item)) for item in ownership)
    except (TypeError, ValueError):
        return False
    if not owned or not result.artifacts:
        return False
    observed_paths: set[str] = set()
    for artifact in result.artifacts:
        path = artifact.get("path")
        if not isinstance(path, str):
            return False
        try:
            normalized, target = resolve_inside(root, path)
        except ValueError:
            return False
        candidate = root.joinpath(*normalized.split("/"))
        if candidate.is_symlink() or normalized in forbidden_artifacts:
            return False
        if normalized in observed_paths:
            return False
        observed_paths.add(normalized)
        if not any(
            normalized == allowed or normalized.startswith(allowed.rstrip("/") + "/")
            for allowed in owned
        ):
            return False
        if not target.is_file():
            return False
        if before.get(normalized) == _file_fingerprint(target):
            return False
    return True


def _file_fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_ephemeral_state_path(relative: str) -> bool:
    parts = tuple(part.casefold() for part in Path(relative).parts)
    filename = parts[-1]
    return any(part in _EPHEMERAL_STATE_DIRECTORIES for part in parts[1:-1]) or (
        filename.startswith((".", "~"))
        or ".tmp." in filename
        or filename.endswith((".bak.json", ".bak.yaml", ".bak.yml"))
    )


def _git_common_dir(root: Path) -> Path:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--git-common-dir"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise ValueError(f"cannot inspect execution repository: {exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError(f"execution path is not a Git repository: {root}")
    observed = Path(result.stdout.strip())
    return (root / observed).resolve() if not observed.is_absolute() else observed.resolve()


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


def _semantic_fingerprint(
    semantic_state: Sequence[Mapping[str, Any]], packet: Mapping[str, Any] | None
) -> str:
    payload: dict[str, Any] = {"semantic_state": [dict(item) for item in semantic_state]}
    if packet is not None:
        payload["execution_packet"] = dict(packet)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ClaudeDetection",
    "ClaudeExecutionPlan",
    "ClaudeHarnessRunner",
    "ClaudeIntegration",
    "ClaudeWorkflowOutcome",
    "ContinuitySnapshot",
    "detect_claude",
]
