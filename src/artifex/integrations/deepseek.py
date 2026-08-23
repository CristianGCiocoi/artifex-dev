"""Optional DeepSeek headless harness over the agent-neutral execution contract.

Detection is read-only and all product-specific behavior stays in this module.
Unknown, preview, or incomplete command surfaces fail closed: they are reported
but are never exposed as executable ARTIFEX integrations.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

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
from artifex.workflow import ExecutionBaseline, ExecutionStatus

_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)(?!\d)")
_PREVIEW_PATTERN = re.compile(r"(?:^|[-+.])(alpha|beta|preview|rc|dev)(?:[.\d-]|$)", re.I)
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
    "stale": ExecutionStatus.REBASE_REQUIRED,
    "rebase_required": ExecutionStatus.REBASE_REQUIRED,
}


class DeepSeekCompatibility(StrEnum):
    STABLE = "STABLE"
    PREVIEW = "PREVIEW"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class DeepSeekDetection:
    """Non-throwing observation produced only by version/help probes."""

    installed: bool
    executable: str | None = None
    version: str | None = None
    capabilities: frozenset[str] = frozenset()
    compatibility: DeepSeekCompatibility = DeepSeekCompatibility.UNKNOWN
    detail: str = ""

    @property
    def stable_headless(self) -> bool:
        required = {Capability.HEADLESS.value, Capability.STRUCTURED_OUTPUT.value}
        return self.compatibility is DeepSeekCompatibility.STABLE and required.issubset(
            self.capabilities
        )

    @property
    def stable_interface(self) -> bool:
        return self.stable_headless and Capability.INTERACTIVE.value in self.capabilities

    def to_dict(self) -> dict[str, object]:
        return {
            "installed": self.installed,
            "executable": self.executable,
            "version": self.version,
            "capabilities": sorted(self.capabilities),
            "compatibility": self.compatibility.value,
            "stable_headless": self.stable_headless,
            "stable_interface": self.stable_interface,
            "detail": self.detail,
        }


def detect_deepseek(executable: str = "deepseek", *, timeout: float = 3.0) -> DeepSeekDetection:
    """Probe an optional DeepSeek CLI without writing configuration or project data."""

    resolved = shutil.which(executable)
    if resolved is None:
        return DeepSeekDetection(False, detail=f"{executable} executable was not found")
    version_result = _probe((resolved, "--version"), timeout)
    if isinstance(version_result, str):
        return DeepSeekDetection(False, resolved, detail=version_result)
    version_output = (version_result.stdout or version_result.stderr).strip()
    if version_result.returncode != 0:
        return DeepSeekDetection(
            False,
            resolved,
            detail=version_output or f"version command exited with {version_result.returncode}",
        )
    match = _VERSION_PATTERN.search(version_output)
    version = match.group(1) if match else None

    help_result = _probe((resolved, "run", "--help"), timeout)
    help_succeeded = not isinstance(help_result, str) and help_result.returncode == 0
    help_output = (
        f"{help_result.stdout}\n{help_result.stderr}".lower()
        if help_succeeded and not isinstance(help_result, str)
        else ""
    )
    capabilities = {Capability.REPOSITORY_READ.value}
    headless = "--headless" in help_output or "non-interactive" in help_output
    structured = any(flag in help_output for flag in ("--json", "--format", "structured"))
    if headless:
        capabilities.add(Capability.HEADLESS.value)
    if structured:
        capabilities.add(Capability.STRUCTURED_OUTPUT.value)
    interactive = "--interactive" in help_output or bool(
        re.search(r"(?<!non-)interactive mode", help_output)
    )
    if interactive:
        capabilities.add(Capability.INTERACTIVE.value)
    if any(token in help_output for token in ("write", "edit", "apply")):
        capabilities.add(Capability.REPOSITORY_WRITE.value)
    if any(token in help_output for token in ("test", "command", "shell")):
        capabilities.add(Capability.TEST_EXECUTION.value)

    compatibility = _classify_compatibility(
        version,
        probes_succeeded=help_succeeded,
        headless=headless,
        structured=structured,
    )
    detail_parts = [version_output or "version was not reported"]
    if isinstance(help_result, str):
        detail_parts.append(help_result)
    elif help_result.returncode != 0:
        detail_parts.append(f"headless help exited with {help_result.returncode}")
    return DeepSeekDetection(
        True,
        resolved,
        version,
        frozenset(capabilities),
        compatibility,
        "; ".join(detail_parts),
    )


def _classify_compatibility(
    version: str | None,
    *,
    probes_succeeded: bool,
    headless: bool,
    structured: bool,
) -> DeepSeekCompatibility:
    if version is None:
        return DeepSeekCompatibility.UNKNOWN
    if _PREVIEW_PATTERN.search(version):
        return DeepSeekCompatibility.PREVIEW
    match = _VERSION_PATTERN.fullmatch(version)
    if match is None:
        return DeepSeekCompatibility.UNKNOWN
    major = int(version.split(".", 1)[0])
    if major != 1:
        return DeepSeekCompatibility.INCOMPATIBLE
    if not (probes_succeeded and headless and structured):
        return DeepSeekCompatibility.UNKNOWN
    return DeepSeekCompatibility.STABLE


def _probe(command: tuple[str, ...], timeout: float) -> subprocess.CompletedProcess[str] | str:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"read-only capability detection failed: {exc}"


@dataclass(frozen=True, slots=True)
class DeepSeekExecutionPlan:
    packet: ExecutionPacket
    worktree_root: str
    command: tuple[str, ...]
    stdin: str

    def to_dict(self) -> dict[str, object]:
        return {
            "packet": self.packet.to_dict(),
            "worktree_root": self.worktree_root,
            "command": list(self.command),
            "stdin": self.stdin,
            "mutating": False,
        }


Runner = Callable[..., subprocess.CompletedProcess[str]]


class DeepSeekHarnessAdapter:
    """Optional harness/implementer enabled only for a stable product boundary."""

    def __init__(
        self,
        detection: DeepSeekDetection | None = None,
        *,
        runner: Runner = subprocess.run,
    ) -> None:
        self.detection = detect_deepseek() if detection is None else detection
        self._manual = ManualIntegration()
        self._runner = runner

    @property
    def metadata(self) -> IntegrationMetadata:
        roles = {IntegrationRole.HARNESS, IntegrationRole.IMPLEMENTER}
        if self.detection.stable_interface:
            roles.add(IntegrationRole.INTERFACE)
        return IntegrationMetadata(
            integration_id="deepseek",
            name="DeepSeek Harness",
            version="1.0.0",
            compatibility=CompatibilityRange("0.1.0", "2.0.0"),
            tested_external_versions=(self.detection.version or "not-detected",),
            roles=frozenset(roles),
            capabilities=self.detection.capabilities,
            configuration=ConfigurationProvenance("read-only PATH detection"),
        )

    def health(self) -> HealthReport:
        if not self.detection.installed:
            return HealthReport(
                HealthStatus.DEGRADED,
                "optional DeepSeek executable is unavailable",
                {"installed": HealthStatus.DEGRADED, "stable_boundary": HealthStatus.UNKNOWN},
            )
        if not self.detection.stable_headless:
            return HealthReport(
                HealthStatus.FAIL,
                "DeepSeek product boundary is preview, incompatible, or unverified; "
                "execution disabled",
                {"installed": HealthStatus.PASS, "stable_boundary": HealthStatus.FAIL},
            )
        return HealthReport(
            HealthStatus.PASS,
            "stable DeepSeek headless structured-output boundary is available",
            {"installed": HealthStatus.PASS, "stable_boundary": HealthStatus.PASS},
        )

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]:
        return self._manual.read_project_status(project_root)

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
        if not self.detection.stable_headless:
            raise IntegrationError("DeepSeek stable headless boundary is unavailable")
        return self._manual.prepare_execution(
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

    def plan_execution(
        self, packet: ExecutionPacket, *, worktree_root: str | Path
    ) -> DeepSeekExecutionPlan:
        if not self.detection.stable_headless or self.detection.executable is None:
            raise IntegrationError(
                "DeepSeek execution fails closed without a stable headless boundary"
            )
        worktree = Path(worktree_root).resolve()
        if not worktree.is_dir():
            raise IntegrationError("DeepSeek worktree root must be an existing directory")
        command = (
            self.detection.executable,
            "run",
            "--headless",
            "--format",
            "json",
            "--input",
            "-",
        )
        return DeepSeekExecutionPlan(
            packet,
            str(worktree),
            command,
            json.dumps(packet.to_dict(), sort_keys=True, separators=(",", ":")),
        )

    def execute(
        self, plan: DeepSeekExecutionPlan, *, timeout: float = 300.0
    ) -> ExecutionResult:
        """Explicitly run a previously inspected plan and normalize the vendor result."""

        try:
            completed = self._runner(
                plan.command,
                cwd=plan.worktree_root,
                input=plan.stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return self.cancel(plan.packet, message="DeepSeek execution timed out")
        except OSError as exc:
            return _failed_result(plan.packet, f"DeepSeek launch failed: {exc}")
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout).strip()
            return _failed_result(
                plan.packet,
                message or f"DeepSeek exited with status {completed.returncode}",
            )
        try:
            value = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            return _failed_result(plan.packet, f"DeepSeek returned invalid JSON: {exc}")
        if not isinstance(value, Mapping):
            return _failed_result(plan.packet, "DeepSeek result must be a JSON object")
        try:
            return normalize_deepseek_result(value, plan.packet)
        except (IntegrationError, ValueError) as exc:
            return _failed_result(plan.packet, f"DeepSeek result rejected: {exc}")

    def submit_result(
        self,
        packet: ExecutionPacket,
        result: ExecutionResult,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        return self._manual.submit_result(packet, result, current_baseline=current_baseline)

    @staticmethod
    def submit_validation(validation: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "canonical": False,
            "authority": "deepseek-executor-claim",
            "validation": dict(validation),
        }

    def cancel(
        self, packet: ExecutionPacket, *, message: str = "cancelled by DeepSeek harness"
    ) -> ExecutionResult:
        return ExecutionResult(
            ExecutionStatus.CANCELLED,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            message=message,
        )


DeepSeekIntegration = DeepSeekHarnessAdapter


def normalize_deepseek_result(
    value: Mapping[str, Any], packet: ExecutionPacket
) -> ExecutionResult:
    """Map vendor status aliases while enforcing the immutable execution baseline."""

    raw_status = str(value.get("status", "")).lower()
    try:
        status = _STATUS_ALIASES[raw_status]
    except KeyError as exc:
        raise IntegrationError(f"unknown DeepSeek result status: {raw_status!r}") from exc
    baseline_fields: dict[str, str] = {}
    for name in (
        "base_commit",
        "execution_contract_fingerprint",
        "project_model_fingerprint",
    ):
        supplied = value.get(name)
        if not isinstance(supplied, str) or not supplied.strip():
            raise IntegrationError(f"DeepSeek result requires explicit {name}")
        baseline_fields[name] = supplied
    artifacts_value = value.get("artifacts", ())
    if not isinstance(artifacts_value, Sequence) or isinstance(
        artifacts_value, (str, bytes, bytearray)
    ):
        raise IntegrationError("DeepSeek artifacts must be an array")
    artifacts: list[Mapping[str, Any]] = []
    for artifact in artifacts_value:
        if not isinstance(artifact, Mapping):
            raise IntegrationError("DeepSeek artifact entries must be objects")
        artifacts.append(dict(artifact))
    validation = value.get("validation", {})
    if not isinstance(validation, Mapping):
        raise IntegrationError("DeepSeek validation must be an object")
    result = ExecutionResult(
        status,
        baseline_fields["base_commit"],
        baseline_fields["execution_contract_fingerprint"],
        baseline_fields["project_model_fingerprint"],
        tuple(artifacts),
        dict(validation),
        str(value.get("message", "")),
    )
    return result.classified(packet.baseline)


def _failed_result(packet: ExecutionPacket, message: str) -> ExecutionResult:
    return ExecutionResult(
        ExecutionStatus.FAIL,
        packet.base_commit,
        packet.contract_fingerprint,
        packet.project_model_fingerprint,
        message=message,
    )


__all__ = [
    "DeepSeekCompatibility",
    "DeepSeekDetection",
    "DeepSeekExecutionPlan",
    "DeepSeekHarnessAdapter",
    "DeepSeekIntegration",
    "detect_deepseek",
    "normalize_deepseek_result",
]
