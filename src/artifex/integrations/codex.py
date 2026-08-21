"""First-class, standalone Codex integration behind the M04 contracts.

The adapter deliberately separates discovery from execution.  Discovery only
invokes ``codex --version`` and Git inspection commands.  Stage execution is
driven by an explicitly supplied fixture/runner result; this module never
starts a live, mutating Codex session by itself.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml  # type: ignore[import-untyped]

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
from artifex.workflow import ExecutionBaseline, ExecutionStatus

CODEX_INTEGRATION_VERSION = "1.0.0"
CODEX_CAPABILITIES = frozenset(
    {
        Capability.INTERACTIVE.value,
        Capability.HEADLESS.value,
        Capability.RESUME.value,
        Capability.SKILLS.value,
        Capability.MCP.value,
        Capability.WORKTREES.value,
        Capability.SUBAGENTS.value,
        Capability.STRUCTURED_OUTPUT.value,
        Capability.REPOSITORY_READ.value,
        Capability.REPOSITORY_WRITE.value,
        Capability.TEST_EXECUTION.value,
        Capability.BACKGROUND_JOBS.value,
    }
)
CODEX_OPERATION_NAMES = (
    "codex.continuity.snapshot",
    "codex.detect",
    "codex.packet.create",
    "codex.result.submit",
    "codex.worktree.inspect",
)

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class ApplicationLike(Protocol):
    """Minimal M04 Application registration seam used without a hard import cycle."""

    def register(self, name: str, operation: Callable[[Any], Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class CodexDetection:
    """Secret-free result of read-only local Codex discovery."""

    available: bool
    executable: str | None
    version: str | None
    raw_version: str = ""
    capabilities: frozenset[str] = CODEX_CAPABILITIES
    error: str | None = None

    def __post_init__(self) -> None:
        if self.available and (not self.executable or not self.version):
            raise IntegrationError("available Codex detection requires executable and version")
        if not self.available and self.version is not None:
            raise IntegrationError("unavailable Codex detection cannot report a version")

    @property
    def status(self) -> HealthStatus:
        return HealthStatus.PASS if self.available else HealthStatus.DEGRADED

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "executable": self.executable,
            "version": self.version,
            "raw_version": self.raw_version,
            "capabilities": sorted(self.capabilities),
            "error": self.error,
            "discovery_mode": "read-only",
        }


def detect_codex(
    executable: str = "codex",
    *,
    which: Callable[[str], str | None] = shutil.which,
    runner: CommandRunner | None = None,
) -> CodexDetection:
    """Detect Codex with the sole external probe ``codex --version``.

    ``which`` and ``runner`` are injectable so conformance fixtures remain
    deterministic and do not depend on a developer workstation installation.
    """

    resolved = which(executable)
    if resolved is None:
        return CodexDetection(False, None, None, error=f"{executable} was not found on PATH")
    command_runner = _read_only_runner if runner is None else runner
    try:
        completed = command_runner((resolved, "--version"))
    except (OSError, subprocess.SubprocessError) as exc:
        return CodexDetection(
            False,
            resolved,
            None,
            error=f"Codex version probe failed: {type(exc).__name__}: {exc}",
        )
    output = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0:
        return CodexDetection(
            False,
            resolved,
            None,
            raw_version=output,
            error=f"Codex version probe exited with {completed.returncode}",
        )
    version = _parse_codex_version(output)
    if version is None:
        return CodexDetection(
            False,
            resolved,
            None,
            raw_version=output,
            error="Codex version output did not contain a semantic version",
        )
    return CodexDetection(True, resolved, version, raw_version=output)


@dataclass(frozen=True, slots=True)
class AgentInstructionLayer:
    """One effective Codex instruction file, ordered from broad to narrow scope."""

    directory: str
    path: str
    content: str
    override: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "path": self.path,
            "content": self.content,
            "override": self.override,
        }


def discover_agents_hierarchy(
    project_root: str | Path,
    target: str | Path = ".",
) -> tuple[AgentInstructionLayer, ...]:
    """Read the effective ``AGENTS.md`` hierarchy for a target path.

    At each directory ``AGENTS.override.md`` takes precedence over ``AGENTS.md``.
    Deeper layers follow broader layers, matching Codex's scoped-instruction
    model.  Paths outside the selected project are rejected.
    """

    root = Path(project_root).resolve()
    candidate = Path(target)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise IntegrationError("AGENTS target must remain inside the project root") from exc
    directory = resolved if resolved.is_dir() else resolved.parent
    relative_directory = directory.relative_to(root)
    directories = [root]
    current = root
    for part in relative_directory.parts:
        current /= part
        directories.append(current)
    layers: list[AgentInstructionLayer] = []
    for scoped_directory in directories:
        override = scoped_directory / "AGENTS.override.md"
        regular = scoped_directory / "AGENTS.md"
        selected = override if override.is_file() else regular
        if not selected.is_file():
            continue
        layers.append(
            AgentInstructionLayer(
                directory=_portable_path(scoped_directory.relative_to(root)) or ".",
                path=_portable_path(selected.relative_to(root)),
                content=selected.read_text(encoding="utf-8"),
                override=selected.name == "AGENTS.override.md",
            )
        )
    return tuple(layers)


def render_agents_shim(*, project_model_fingerprint: str, scope: str = ".") -> str:
    """Render a thin Codex shim whose authority remains repository-canonical."""

    if not re.fullmatch(r"[a-f0-9]{64}", project_model_fingerprint):
        raise IntegrationError("project_model_fingerprint must be a SHA-256 digest")
    normalized_scope = _normalize_relative(scope)
    return (
        "# ARTIFEX Codex generated context\n\n"
        "<!-- GENERATED VIEW. Canonical meaning remains in the Project Model. -->\n"
        f"<!-- PROJECT_MODEL_SHA256: {project_model_fingerprint} -->\n"
        f"<!-- CODEX_SCOPE: {normalized_scope} -->\n\n"
        "Read `.artifex/project-model.json` and accepted repository artifacts as authority.\n"
        "Use `interface_packs/codex/skills/` only as portable workflow guidance.\n"
        "Treat native Codex memory and parent transcripts as auxiliary, never canonical.\n"
        "Do not infer acceptance from executor claims; ARTIFEX Core owns gates and evidence.\n"
    )


@dataclass(frozen=True, slots=True)
class CodexWorktreeBinding:
    """Observed Git worktree identity bound to an immutable execution packet."""

    root: str
    branch: str | None
    head_commit: str
    expected_base_commit: str
    clean: bool
    contract_fingerprint: str
    project_model_fingerprint: str
    observed_project_model_fingerprint: str

    @property
    def bound(self) -> bool:
        return (
            self.head_commit == self.expected_base_commit
            and self.observed_project_model_fingerprint == self.project_model_fingerprint
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "branch": self.branch,
            "head_commit": self.head_commit,
            "expected_base_commit": self.expected_base_commit,
            "clean": self.clean,
            "bound": self.bound,
            "execution_contract_fingerprint": self.contract_fingerprint,
            "expected_project_model_fingerprint": self.project_model_fingerprint,
            "observed_project_model_fingerprint": self.observed_project_model_fingerprint,
            "inspection_mode": "read-only",
        }


@dataclass(frozen=True, slots=True)
class CodexWorkerPlan:
    """A portable worker plan; it describes, but never creates, a worktree."""

    packet: ExecutionPacket
    worktree: CodexWorktreeBinding
    instruction_layers: tuple[AgentInstructionLayer, ...]
    command: tuple[str, ...]
    prompt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet": self.packet.to_dict(),
            "worktree": self.worktree.to_dict(),
            "instruction_layers": [layer.to_dict() for layer in self.instruction_layers],
            "command": list(self.command),
            "prompt": self.prompt,
            "execution_mode": "explicit-runner-required",
        }


@dataclass(frozen=True, slots=True)
class CodexExecutionFixture:
    """Injectable, deterministic harness runner with an explicit result identity."""

    status: ExecutionStatus
    base_commit: str
    execution_contract_fingerprint: str
    project_model_fingerprint: str
    artifacts: tuple[Mapping[str, Any], ...] = ()
    validation: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""

    @classmethod
    def bound(
        cls,
        packet: ExecutionPacket,
        status: ExecutionStatus,
        *,
        artifacts: tuple[Mapping[str, Any], ...] = (),
        validation: Mapping[str, Any] | None = None,
        message: str = "",
    ) -> CodexExecutionFixture:
        return cls(
            status,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            artifacts,
            {} if validation is None else validation,
            message,
        )

    def __call__(self, plan: CodexWorkerPlan) -> Mapping[str, Any]:
        packet = plan.packet
        expected = (
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
        )
        observed = (
            self.base_commit,
            self.execution_contract_fingerprint,
            self.project_model_fingerprint,
        )
        if observed != expected:
            raise IntegrationError("deterministic harness fixture is not bound to the worker plan")
        return {
            "status": self.status.value,
            "base_commit": self.base_commit,
            "execution_contract_fingerprint": self.execution_contract_fingerprint,
            "project_model_fingerprint": self.project_model_fingerprint,
            "artifacts": [_copy_json(item) for item in self.artifacts],
            "validation": _copy_json(self.validation),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ContinuitySnapshot:
    """Portable semantic-state fingerprint independent of Codex native memory."""

    project_root: str
    source: str
    state: Mapping[str, Any]
    files: tuple[Mapping[str, str], ...]
    base_commit: str | None = None
    execution_contract_fingerprint: str | None = None
    project_model_fingerprint: str | None = None
    schema_version: str = "1.0"
    kind: str = "ARTIFEX_CONTINUITY_SNAPSHOT"

    @property
    def semantic_fingerprint(self) -> str:
        return _fingerprint(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "source": self.source,
            "state": _copy_json(self.state),
            "files": [_copy_json(item) for item in self.files],
            "base_commit": self.base_commit,
            "execution_contract_fingerprint": self.execution_contract_fingerprint,
            "project_model_fingerprint": self.project_model_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self._semantic_dict()
        value["project_root"] = self.project_root
        value["semantic_fingerprint"] = self.semantic_fingerprint
        value["native_memory_required"] = False
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ContinuitySnapshot:
        files_value = value.get("files", ())
        if not isinstance(files_value, Sequence) or isinstance(files_value, (str, bytes)):
            raise IntegrationError("continuity snapshot files must be an array")
        files = tuple(_string_mapping(item, "continuity file") for item in files_value)
        snapshot = cls(
            project_root=str(value.get("project_root", "")),
            source=str(value.get("source", "")),
            state=_mapping(value.get("state"), "state"),
            files=files,
            base_commit=_optional_string(value.get("base_commit")),
            execution_contract_fingerprint=_optional_string(
                value.get("execution_contract_fingerprint")
            ),
            project_model_fingerprint=_optional_string(
                value.get("project_model_fingerprint")
            ),
            schema_version=str(value.get("schema_version", "")),
            kind=str(value.get("kind", "")),
        )
        if snapshot.schema_version != "1.0" or snapshot.kind != "ARTIFEX_CONTINUITY_SNAPSHOT":
            raise IntegrationError("unsupported continuity snapshot contract")
        supplied = value.get("semantic_fingerprint")
        if supplied is not None and supplied != snapshot.semantic_fingerprint:
            raise IntegrationError("continuity snapshot fingerprint does not match content")
        return snapshot


class CodexIntegration:
    """Standalone Codex interface, harness and implementer adapter."""

    def __init__(self, detection: CodexDetection | None = None) -> None:
        self.detection = detect_codex() if detection is None else detection

    @property
    def metadata(self) -> IntegrationMetadata:
        observed = self.detection.version or "unavailable"
        return IntegrationMetadata(
            integration_id="codex",
            name="OpenAI Codex",
            version=CODEX_INTEGRATION_VERSION,
            compatibility=CompatibilityRange("0.1.0", "1.0.0"),
            tested_external_versions=(observed,),
            roles=frozenset(
                {
                    IntegrationRole.INTERFACE,
                    IntegrationRole.HARNESS,
                    IntegrationRole.IMPLEMENTER,
                }
            ),
            capabilities=self.detection.capabilities,
            configuration=ConfigurationProvenance("local-read-only-detection", "codex --version"),
        )

    def health(self) -> HealthReport:
        summary = (
            f"Codex {self.detection.version} is available"
            if self.detection.available
            else (self.detection.error or "Codex is unavailable")
        )
        return HealthReport(
            self.detection.status,
            summary,
            {
                "executable": self.detection.status,
                "version": self.detection.status,
                "packet_execution": HealthStatus.PASS,
            },
        )

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]:
        root = Path(project_root).resolve()
        candidates = (
            (root / ".artifex" / "status.yaml", "yaml"),
            (root / ".artifex" / "project-model.json", "json"),
            (root / ".artifex" / "project.yaml", "yaml"),
        )
        for source, encoding in candidates:
            if not source.is_file():
                continue
            text = source.read_text(encoding="utf-8")
            value = json.loads(text) if encoding == "json" else yaml.safe_load(text)
            if not isinstance(value, Mapping):
                raise IntegrationError(f"project state is not an object: {source}")
            return {
                "source": _portable_path(source.relative_to(root)),
                "state": _copy_json(value),
            }
        raise FileNotFoundError(f"no ARTIFEX project state found under {root}")

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
        return ExecutionPacket(
            task_contract=task_contract,
            context=context,
            base_commit=base_commit,
            project_model_fingerprint=project_model_fingerprint,
            acceptance_criteria=tuple(acceptance_criteria),
            ownership=ownership,
            expected_result=expected_result,
            interfaces=tuple(interfaces),
            invariants=tuple(invariants),
        )

    create_execution_packet = prepare_execution

    def inspect_worktree(
        self,
        packet: ExecutionPacket,
        project_root: str | Path,
        *,
        runner: CommandRunner | None = None,
        require_clean: bool = False,
    ) -> CodexWorktreeBinding:
        root = Path(project_root).resolve()
        command_runner = _read_only_runner if runner is None else runner
        observed_root = _git_value(command_runner, root, "rev-parse", "--show-toplevel")
        if Path(observed_root).resolve() != root:
            raise IntegrationError("selected project root is not the Git worktree root")
        head = _git_value(command_runner, root, "rev-parse", "HEAD")
        observed_model_fingerprint = _canonical_project_model_fingerprint(root)
        branch_result = command_runner(
            ("git", "-C", str(root), "symbolic-ref", "--quiet", "--short", "HEAD")
        )
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
        status = _git_value(command_runner, root, "status", "--porcelain=v1", allow_empty=True)
        binding = CodexWorktreeBinding(
            root=str(root),
            branch=branch,
            head_commit=head,
            expected_base_commit=packet.base_commit,
            clean=not bool(status),
            contract_fingerprint=packet.contract_fingerprint,
            project_model_fingerprint=packet.project_model_fingerprint,
            observed_project_model_fingerprint=observed_model_fingerprint,
        )
        if binding.head_commit != binding.expected_base_commit:
            raise IntegrationError(
                f"worktree HEAD {binding.head_commit} does not match packet base "
                f"{binding.expected_base_commit}"
            )
        if (
            binding.observed_project_model_fingerprint
            != binding.project_model_fingerprint
        ):
            raise IntegrationError(
                "canonical Project Model fingerprint "
                f"{binding.observed_project_model_fingerprint} does not match packet fingerprint "
                f"{binding.project_model_fingerprint}"
            )
        if require_clean and not binding.clean:
            raise IntegrationError("worker execution requires a clean Git worktree")
        return binding

    bind_worktree = inspect_worktree

    def prepare_stage(
        self,
        packet: ExecutionPacket,
        project_root: str | Path,
        *,
        runner: CommandRunner | None = None,
        require_clean: bool = False,
    ) -> CodexWorkerPlan:
        binding = self.inspect_worktree(
            packet, project_root, runner=runner, require_clean=require_clean
        )
        layers = discover_agents_hierarchy(project_root)
        prompt = (
            f"Execute task {packet.task_contract.get('id', 'UNKNOWN')} from the supplied "
            "ARTIFEX Execution Packet. Preserve its base commit, Project Model fingerprint, "
            "ownership, acceptance criteria, and Core acceptance boundary."
        )
        return CodexWorkerPlan(
            packet=packet,
            worktree=binding,
            instruction_layers=layers,
            command=("codex", "exec", "--json", "-C", str(Path(project_root).resolve()), prompt),
            prompt=prompt,
        )

    def execute_stage(
        self,
        plan: CodexWorkerPlan,
        runner: Callable[[CodexWorkerPlan], Mapping[str, Any]],
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        """Execute a prepared plan only through an injected non-mutating harness boundary."""

        # Re-read both Git and canonical semantic identity immediately before
        # handing the packet to a runner.  Preparing a plan cannot freeze a
        # repository that changed afterward.
        self.inspect_worktree(plan.packet, plan.worktree.root)
        root = Path(plan.worktree.root).resolve()
        owned_paths, before = _snapshot_owned_artifacts(root, plan.packet)
        raw_result = runner(plan)
        if not isinstance(raw_result, Mapping):
            raise IntegrationError("Codex harness runner must return an object")
        result = self.normalize_result(plan.packet, raw_result)
        observed_baseline = _observed_repository_baseline(root, plan.packet)
        classified = self.submit_result(
            plan.packet, result, current_baseline=observed_baseline
        )
        if classified.status is ExecutionStatus.SUCCESS and current_baseline is not None:
            classified = self.submit_result(
                plan.packet, classified, current_baseline=current_baseline
            )
        if classified.status is ExecutionStatus.SUCCESS:
            _verify_success_artifacts(root, classified, owned_paths, before)
        return classified

    def normalize_result(
        self, packet: ExecutionPacket, value: Mapping[str, Any]
    ) -> ExecutionResult:
        raw_status = str(value.get("status", "")).strip().casefold().replace("-", "_")
        status_map = {
            "success": ExecutionStatus.SUCCESS,
            "succeeded": ExecutionStatus.SUCCESS,
            "completed": ExecutionStatus.SUCCESS,
            "fail": ExecutionStatus.FAIL,
            "failed": ExecutionStatus.FAIL,
            "error": ExecutionStatus.FAIL,
            "blocked": ExecutionStatus.BLOCKED,
            "cancelled": ExecutionStatus.CANCELLED,
            "canceled": ExecutionStatus.CANCELLED,
            "rebase_required": ExecutionStatus.REBASE_REQUIRED,
            "stale": ExecutionStatus.REBASE_REQUIRED,
        }
        if raw_status not in status_map:
            raise IntegrationError(f"unsupported Codex result status: {value.get('status')!r}")
        artifacts_value = value.get("artifacts", ())
        if not isinstance(artifacts_value, Sequence) or isinstance(
            artifacts_value, (str, bytes, bytearray)
        ):
            raise IntegrationError("Codex result artifacts must be an array")
        artifacts = tuple(_mapping(item, "artifact") for item in artifacts_value)
        validation = _mapping(value.get("validation", {}), "validation")
        result = ExecutionResult(
            status_map[raw_status],
            _required_string(value, "base_commit"),
            _required_string(value, "execution_contract_fingerprint"),
            _required_string(value, "project_model_fingerprint"),
            artifacts=artifacts,
            validation=validation,
            message=str(value.get("message", "")),
        )
        return result.classified(packet.baseline)

    def submit_result(
        self,
        packet: ExecutionPacket,
        result: ExecutionResult,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        current = packet.baseline if current_baseline is None else current_baseline
        # First bind the result to the immutable packet, then compare the packet
        # basis with current Core state.  Either mismatch requires a rebase.
        packet_bound = result.classified(packet.baseline)
        if packet_bound.status is ExecutionStatus.REBASE_REQUIRED:
            return packet_bound
        return result.classified(current)

    ingest_result = submit_result

    @staticmethod
    def submit_validation(validation: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "canonical": False,
            "authority": "executor-claim",
            "integration": "codex",
            "validation": _copy_json(validation),
        }

    def cancel(self, packet: ExecutionPacket, *, message: str = "cancelled") -> ExecutionResult:
        return ExecutionResult(
            ExecutionStatus.CANCELLED,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            message=message,
        )

    def continuity_snapshot(
        self,
        project_root: str | Path,
        *,
        packet: ExecutionPacket | None = None,
    ) -> ContinuitySnapshot:
        root = Path(project_root).resolve()
        status = self.read_project_status(root)
        files = _semantic_file_manifest(root)
        return ContinuitySnapshot(
            project_root=str(root),
            source=str(status["source"]),
            state=_mapping(status["state"], "state"),
            files=files,
            base_commit=packet.base_commit if packet is not None else _state_base_commit(status),
            execution_contract_fingerprint=(
                packet.contract_fingerprint if packet is not None else None
            ),
            project_model_fingerprint=(
                packet.project_model_fingerprint if packet is not None else None
            ),
        )

    def register_application_operations(self, application: ApplicationLike) -> None:
        """Bridge Codex through the existing M04 API, hence CLI and MCP transports."""

        operation_result = importlib.import_module("artifex." + "application").OperationResult

        def detect(_: Any) -> Any:
            return operation_result(ok=True, value={"detection": self.detection.to_dict()})

        def packet_create(request: Any) -> Any:
            arguments = _mapping(request.arguments, "arguments")
            packet = self.prepare_execution(
                task_contract=_required_mapping(arguments, "task_contract"),
                context=_optional_mapping(arguments, "context"),
                base_commit=_required_string(arguments, "base_commit"),
                project_model_fingerprint=_required_string(
                    arguments, "project_model_fingerprint"
                ),
                acceptance_criteria=_required_sequence(arguments, "acceptance_criteria"),
                ownership=_optional_mapping(arguments, "ownership"),
                expected_result=_required_mapping(arguments, "expected_result"),
                interfaces=_string_sequence(arguments, "interfaces"),
                invariants=_string_sequence(arguments, "invariants"),
            )
            return operation_result(ok=True, value={"packet": packet.to_dict()})

        def result_submit(request: Any) -> Any:
            arguments = _mapping(request.arguments, "arguments")
            packet = ExecutionPacket.from_dict(_required_mapping(arguments, "packet"))
            result = self.normalize_result(packet, _required_mapping(arguments, "result"))
            classified = self.submit_result(packet, result)
            return operation_result(
                ok=True,
                value={"result": classified.to_dict(), "canonical_acceptance": False},
            )

        def worktree_inspect(request: Any) -> Any:
            arguments = _mapping(request.arguments, "arguments")
            packet = ExecutionPacket.from_dict(_required_mapping(arguments, "packet"))
            project_root = _project_root(request, arguments)
            binding = self.inspect_worktree(
                packet,
                project_root,
                require_clean=_optional_bool(arguments, "require_clean", False),
            )
            return operation_result(ok=True, value={"worktree": binding.to_dict()})

        def snapshot(request: Any) -> Any:
            arguments = _mapping(request.arguments, "arguments")
            project_root = _project_root(request, arguments)
            packet_value = arguments.get("packet")
            packet = (
                ExecutionPacket.from_dict(_mapping(packet_value, "packet"))
                if packet_value is not None
                else None
            )
            value = self.continuity_snapshot(project_root, packet=packet)
            return operation_result(ok=True, value={"snapshot": value.to_dict()})

        operations = {
            "codex.detect": detect,
            "codex.packet.create": packet_create,
            "codex.result.submit": result_submit,
            "codex.worktree.inspect": worktree_inspect,
            "codex.continuity.snapshot": snapshot,
        }
        for name in CODEX_OPERATION_NAMES:
            application.register(name, operations[name])


def create_codex_application(
    integration: CodexIntegration | None = None,
) -> Any:
    """Create the M04 Application with Codex registered for CLI/MCP consumers."""

    from artifex.integrations.manual import ManualIntegration
    from artifex.integrations.registry import IntegrationRegistry

    adapter = CodexIntegration() if integration is None else integration
    application_type = importlib.import_module("artifex." + "application").Application
    application = application_type(IntegrationRegistry((ManualIntegration(), adapter)))
    adapter.register_application_operations(application)
    return application


def _read_only_runner(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )


def _parse_codex_version(output: str) -> str | None:
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)(?!\d)", output)
    return match.group(1) if match is not None else None


def _git_value(
    runner: CommandRunner,
    root: Path,
    *arguments: str,
    allow_empty: bool = False,
) -> str:
    completed = runner(("git", "-C", str(root), *arguments))
    value = completed.stdout.strip()
    if completed.returncode != 0 or (not value and not allow_empty):
        detail = completed.stderr.strip() or value or "unknown Git failure"
        raise IntegrationError(f"read-only Git inspection failed: {detail}")
    return value


def _canonical_project_model_fingerprint(root: Path) -> str:
    model_path = root / ".artifex" / "project-model.json"
    try:
        value = json.loads(model_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError(
            f"cannot read canonical Project Model at {model_path}"
        ) from exc
    if not isinstance(value, Mapping):
        raise IntegrationError("canonical Project Model must be an object")
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _observed_repository_baseline(
    root: Path, packet: ExecutionPacket
) -> ExecutionBaseline:
    return ExecutionBaseline(
        _git_value(_read_only_runner, root, "rev-parse", "HEAD"),
        packet.contract_fingerprint,
        _canonical_project_model_fingerprint(root),
    )


def _snapshot_owned_artifacts(
    root: Path, packet: ExecutionPacket
) -> tuple[tuple[str, ...], Mapping[str, str]]:
    paths = _required_sequence(packet.ownership, "paths")
    if not all(isinstance(item, str) and item.strip() for item in paths):
        raise IntegrationError("ownership paths must contain non-empty strings")
    owned = tuple(dict.fromkeys(_safe_artifact_path(root, str(item))[0] for item in paths))
    snapshot: dict[str, str] = {}
    for relative in owned:
        target = _safe_artifact_path(root, relative)[1]
        if target.is_file():
            snapshot[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
        elif target.is_dir():
            for candidate in target.rglob("*"):
                if not candidate.is_file():
                    continue
                candidate_relative, resolved = _safe_artifact_path(
                    root, _portable_path(candidate.relative_to(root))
                )
                snapshot[candidate_relative] = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return owned, snapshot


def _verify_success_artifacts(
    root: Path,
    result: ExecutionResult,
    owned_paths: Sequence[str],
    before: Mapping[str, str],
) -> None:
    if not result.artifacts:
        raise IntegrationError("Codex SUCCESS must claim at least one produced artifact")
    seen: set[str] = set()
    for artifact in result.artifacts:
        raw_path = _required_string(artifact, "path")
        relative, target = _safe_artifact_path(root, raw_path)
        if relative in seen:
            raise IntegrationError(f"duplicate Codex result artifact: {relative}")
        seen.add(relative)
        if not any(
            relative == owner or relative.startswith(f"{owner}/")
            for owner in owned_paths
        ):
            raise IntegrationError(f"Codex result artifact is outside packet ownership: {relative}")
        if not target.is_file():
            raise IntegrationError(f"Codex SUCCESS artifact does not exist: {relative}")
        after = hashlib.sha256(target.read_bytes()).hexdigest()
        if before.get(relative) == after:
            raise IntegrationError(
                f"Codex SUCCESS artifact was not created or content-changed: {relative}"
            )


def _safe_artifact_path(root: Path, value: str) -> tuple[str, Path]:
    candidate = Path(value)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise IntegrationError(f"artifact path escapes project root: {value!r}")
    relative = _portable_path(candidate)
    target = (root / candidate).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise IntegrationError(f"artifact path escapes project root: {value!r}") from exc
    return relative, target


def _semantic_file_manifest(root: Path) -> tuple[Mapping[str, str], ...]:
    candidates: set[Path] = set()
    state_root = root / ".artifex"
    if state_root.is_dir():
        candidates.update(path for path in state_root.rglob("*") if path.is_file())
    for name in (
        "README.md",
        "USER_GUIDE.md",
        "ADMIN_GUIDE.md",
        "DEVELOPER_GUIDE.md",
        "AGENTS.md",
        "CLAUDE.md",
    ):
        path = root / name
        if path.is_file():
            candidates.add(path)
    manifest: list[Mapping[str, str]] = []
    for path in sorted(candidates, key=lambda item: _portable_path(item.relative_to(root))):
        relative = _portable_path(path.relative_to(root))
        # Native/harness caches are explicitly auxiliary and must not affect
        # cross-interface continuity.
        if relative.startswith((".artifex/native-memory/", ".artifex/runs/")):
            continue
        manifest.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return tuple(manifest)


def _state_base_commit(status: Mapping[str, Any]) -> str | None:
    state = status.get("state")
    if not isinstance(state, Mapping):
        return None
    git = state.get("git")
    if isinstance(git, Mapping):
        value = git.get("baseline_commit") or git.get("current_commit")
        return str(value) if value is not None else None
    value = state.get("base_commit")
    return str(value) if value is not None else None


def _project_root(request: Any, arguments: Mapping[str, Any]) -> str:
    value = arguments.get("project_root", getattr(request.context, "project_root", None))
    if not isinstance(value, str) or not value:
        raise IntegrationError("project_root is required")
    return value


def _copy_json(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise IntegrationError("Codex contracts must be JSON-serializable") from exc


def _fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrationError(f"{name} must be an object")
    return value


def _string_mapping(value: Any, name: str) -> Mapping[str, str]:
    mapping = _mapping(value, name)
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in mapping.items()):
        raise IntegrationError(f"{name} must contain string keys and values")
    return {str(key): str(item) for key, item in mapping.items()}


def _required_mapping(arguments: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = _mapping(arguments.get(name), name)
    if not value:
        raise IntegrationError(f"{name} is required")
    return value


def _optional_mapping(arguments: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _mapping(arguments.get(name, {}), name)


def _required_string(arguments: Mapping[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise IntegrationError(f"{name} is required and must be a string")
    return value


def _required_sequence(arguments: Mapping[str, Any], name: str) -> Sequence[Any]:
    value = arguments.get(name)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)) or not value:
        raise IntegrationError(f"{name} is required and must be a non-empty array")
    return value


def _string_sequence(arguments: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = arguments.get(name, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise IntegrationError(f"{name} must be an array")
    if not all(isinstance(item, str) and item for item in value):
        raise IntegrationError(f"{name} must contain strings")
    return tuple(value)


def _optional_bool(arguments: Mapping[str, Any], name: str, default: bool) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise IntegrationError(f"{name} must be a boolean")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IntegrationError("expected a string or null")
    return value


def _normalize_relative(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise IntegrationError("scope must be a safe relative path")
    return _portable_path(path) or "."


def _portable_path(path: Path) -> str:
    return path.as_posix().removeprefix("./")


__all__ = [
    "CODEX_CAPABILITIES",
    "CODEX_INTEGRATION_VERSION",
    "CODEX_OPERATION_NAMES",
    "AgentInstructionLayer",
    "CodexDetection",
    "CodexExecutionFixture",
    "CodexIntegration",
    "CodexWorkerPlan",
    "CodexWorktreeBinding",
    "ContinuitySnapshot",
    "create_codex_application",
    "detect_codex",
    "discover_agents_hierarchy",
    "render_agents_shim",
]
