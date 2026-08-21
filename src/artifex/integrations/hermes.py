"""Hermes-preferred integration behind the agent-neutral M04 contracts.

The adapter deliberately stops at an inspectable dispatch boundary.  Local
Hermes discovery may execute only the documented, read-only ``--version``
probe; stage, task, and research operations are represented as deterministic
packets for a Hermes harness to consume.  No conversation or Hermes-native
memory is canonical ARTIFEX state.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
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
from artifex.integrations.manual import ManualIntegration
from artifex.integrations.research import ResearchBundle, ResearchRequest
from artifex.workflow import ExecutionBaseline, ExecutionStatus

_VERSION_PATTERN = re.compile(r"(?<![A-Za-z0-9])v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)")
_SAFE_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_STAGE_SKILLS = {
    "idea": "idea",
    "research": "research",
    "architecture": "architecture",
    "implementation-plan": "implementation-plan",
    "implementation": "router",
    "review": "review",
    "learn": "learn",
}
_STAGE_TASK_PROFILES = {
    "idea": "product-analyst",
    "research": "researcher",
    "architecture": "architect",
    "implementation-plan": "planner",
    "implementation": "software-engineer",
    "review": "reviewer",
    "learn": "knowledge-curator",
}
_NATIVE_STATUS = {
    "success": ExecutionStatus.SUCCESS,
    "succeeded": ExecutionStatus.SUCCESS,
    "completed": ExecutionStatus.SUCCESS,
    "complete": ExecutionStatus.SUCCESS,
    "fail": ExecutionStatus.FAIL,
    "failed": ExecutionStatus.FAIL,
    "error": ExecutionStatus.FAIL,
    "blocked": ExecutionStatus.BLOCKED,
    "cancelled": ExecutionStatus.CANCELLED,
    "canceled": ExecutionStatus.CANCELLED,
    "interrupted": ExecutionStatus.CANCELLED,
}


class VersionProbe(Protocol):
    def __call__(self, executable: str) -> tuple[int, str]: ...


@dataclass(frozen=True, slots=True)
class HermesDetection:
    """Secret-free result of read-only local Hermes discovery."""

    status: HealthStatus
    executable: str | None
    version: str | None
    summary: str
    probe: str = "PATH + --version (read-only)"

    @classmethod
    def available(
        cls, version: str = "0.0.0-simulated", *, executable: str = "hermes"
    ) -> HermesDetection:
        """Build deterministic fixture evidence without invoking a process."""

        return cls(HealthStatus.PASS, executable, version, f"Hermes {version} is available")

    @classmethod
    def unavailable(cls, summary: str = "Hermes executable was not found") -> HermesDetection:
        return cls(HealthStatus.DEGRADED, None, None, summary)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "status": self.status.value,
            "executable": self.executable,
            "version": self.version,
            "summary": self.summary,
            "probe": self.probe,
        }


@dataclass(frozen=True, slots=True)
class HermesDispatch:
    """Inspectable stage/task handoff; it never grants acceptance authority."""

    packet: ExecutionPacket
    stage: str
    skill: str
    task_profile: str
    mode: str = "packet"
    canonical_acceptance: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "HERMES_DISPATCH",
            "mode": self.mode,
            "stage": self.stage,
            "skill": self.skill,
            "task_profile": self.task_profile,
            "canonical_acceptance": self.canonical_acceptance,
            "packet": self.packet.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class HermesResearchDispatch:
    request: ResearchRequest
    skill: str = "research"
    task_profile: str = "researcher"
    canonical_decision: bool = False
    native_memory_policy: str = "auxiliary-only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "HERMES_RESEARCH_DISPATCH",
            "skill": self.skill,
            "task_profile": self.task_profile,
            "canonical_decision": self.canonical_decision,
            "native_memory_policy": self.native_memory_policy,
            "request": self.request.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class AuxiliaryMemoryObservation:
    """A harness-memory observation with no canonical or promotion authority."""

    content: str
    provenance: str
    canonical: bool = False
    scope: str = "HERMES_NATIVE_AUXILIARY"
    promotion: str = "REQUIRES_ARTIFEX_KNOWLEDGE_POLICY"

    def __post_init__(self) -> None:
        if not self.content.strip() or not self.provenance.strip():
            raise IntegrationError("auxiliary memory content and provenance are required")

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "content": self.content,
            "provenance": self.provenance,
            "canonical": self.canonical,
            "scope": self.scope,
            "promotion": self.promotion,
        }


@dataclass(frozen=True, slots=True)
class InterfacePackInstallation:
    destination: str
    installed_files: tuple[str, ...]
    manifest_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination,
            "installed_files": list(self.installed_files),
            "manifest_fingerprint": self.manifest_fingerprint,
        }


def detect_local_hermes(
    executable_names: Sequence[str] = ("hermes", "hermes-agent"),
    *,
    which: Callable[[str], str | None] = shutil.which,
    version_probe: VersionProbe | None = None,
) -> HermesDetection:
    """Detect a local Hermes CLI without reading configuration or changing state."""

    probe = _read_only_version_probe if version_probe is None else version_probe
    for name in executable_names:
        if not _SAFE_EXECUTABLE.fullmatch(name):
            raise IntegrationError("Hermes executable candidates must be safe command names")
        executable = which(name)
        if executable is None:
            continue
        try:
            return_code, output = probe(executable)
        except (OSError, subprocess.SubprocessError, TimeoutError) as exc:
            return HermesDetection(
                HealthStatus.DEGRADED,
                executable,
                None,
                f"Hermes version probe failed safely ({type(exc).__name__})",
            )
        if return_code != 0:
            return HermesDetection(
                HealthStatus.DEGRADED,
                executable,
                None,
                "Hermes executable was found but the read-only version probe failed",
            )
        match = _VERSION_PATTERN.search(output[:4096])
        if match is None:
            return HermesDetection(
                HealthStatus.DEGRADED,
                executable,
                None,
                "Hermes executable was found but returned no parseable version",
            )
        version = match.group(1)
        return HermesDetection(
            HealthStatus.PASS,
            executable,
            version,
            f"Hermes {version} is available",
        )
    return HermesDetection.unavailable()


class HermesIntegration:
    """Preferred Hermes adapter with no dependency on live session state."""

    def __init__(
        self,
        detection: HermesDetection | None = None,
        *,
        interface_pack_root: str | Path | None = None,
    ) -> None:
        self._detection = detect_local_hermes() if detection is None else detection
        self._manual = ManualIntegration()
        self._interface_pack_root = (
            Path(__file__).resolve().parents[3] / "interface_packs" / "hermes"
            if interface_pack_root is None
            else Path(interface_pack_root).resolve()
        )

    @classmethod
    def simulated(cls, version: str = "0.0.0-simulated") -> HermesIntegration:
        """Construct a deterministic, process-free conformance fixture."""

        return cls(HermesDetection.available(version))

    @property
    def detection(self) -> HermesDetection:
        return self._detection

    @property
    def metadata(self) -> IntegrationMetadata:
        return IntegrationMetadata(
            integration_id="hermes",
            name="Hermes",
            version="1.0.0",
            compatibility=CompatibilityRange("0.1.0", "1.0.0"),
            tested_external_versions=(self._detection.version or "not-detected",),
            roles=frozenset(IntegrationRole),
            capabilities=frozenset(
                {
                    capability.value
                    for capability in (
                        Capability.INTERACTIVE,
                        Capability.HEADLESS,
                        Capability.RESUME,
                        Capability.SKILLS,
                        Capability.MCP,
                        Capability.WORKTREES,
                        Capability.SUBAGENTS,
                        Capability.STRUCTURED_OUTPUT,
                        Capability.REPOSITORY_READ,
                        Capability.REPOSITORY_WRITE,
                        Capability.TEST_EXECUTION,
                        Capability.BACKGROUND_JOBS,
                    )
                }
            ),
            configuration=ConfigurationProvenance(
                "read-only local detection", self._detection.probe
            ),
        )

    def health(self) -> HealthReport:
        pack_status = (
            HealthStatus.PASS if self._pack_manifest_path().is_file() else HealthStatus.FAIL
        )
        statuses = (self._detection.status, pack_status)
        if HealthStatus.FAIL in statuses:
            overall = HealthStatus.FAIL
        elif HealthStatus.DEGRADED in statuses or HealthStatus.UNKNOWN in statuses:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.PASS
        return HealthReport(
            overall,
            self._detection.summary,
            {"local_detection": self._detection.status, "interface_pack": pack_status},
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

    create_execution_packet = prepare_execution

    def prepare_stage_execution(self, stage: str, **packet_fields: Any) -> HermesDispatch:
        normalized = stage.strip().lower()
        if normalized not in _STAGE_SKILLS:
            raise IntegrationError(f"unsupported Hermes stage mapping: {stage!r}")
        packet = self.prepare_execution(**packet_fields)
        return HermesDispatch(
            packet,
            normalized,
            _STAGE_SKILLS[normalized],
            _STAGE_TASK_PROFILES[normalized],
        )

    def prepare_implementation_task(self, **packet_fields: Any) -> HermesDispatch:
        """Map an M04 task packet to the Hermes software-engineer profile."""

        return self.prepare_stage_execution("implementation", **packet_fields)

    @staticmethod
    def stage_mapping() -> Mapping[str, Mapping[str, str]]:
        return {
            stage: {"skill": skill, "task_profile": _STAGE_TASK_PROFILES[stage]}
            for stage, skill in _STAGE_SKILLS.items()
        }

    @staticmethod
    def prepare_research(request: ResearchRequest) -> HermesResearchDispatch:
        return HermesResearchDispatch(request)

    @staticmethod
    def submit_research_result(
        request: ResearchRequest, value: Mapping[str, Any]
    ) -> ResearchBundle:
        bundle = ResearchBundle.from_dict(value)
        if bundle.request_id != request.request_id:
            raise IntegrationError("Hermes research result does not match its request")
        return bundle

    @staticmethod
    def observe_native_memory(content: str, *, provenance: str) -> AuxiliaryMemoryObservation:
        return AuxiliaryMemoryObservation(content, provenance)

    @staticmethod
    def promote_native_memory(_: AuxiliaryMemoryObservation) -> None:
        raise IntegrationError(
            "Hermes native memory is auxiliary; use ARTIFEX knowledge promotion policy"
        )

    def normalize_result(
        self,
        packet: ExecutionPacket,
        native_result: Mapping[str, Any],
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        raw_status = native_result.get("status")
        if not isinstance(raw_status, str):
            raise IntegrationError("Hermes result status must be a string")
        base_commit = _required_native_binding(native_result, "base_commit")
        contract_fingerprint = _required_native_binding(
            native_result, "execution_contract_fingerprint"
        )
        model_fingerprint = _required_native_binding(
            native_result, "project_model_fingerprint"
        )
        status = _NATIVE_STATUS.get(raw_status.strip().lower(), ExecutionStatus.FAIL)
        artifacts_value = native_result.get("artifacts", ())
        if not isinstance(artifacts_value, Sequence) or isinstance(
            artifacts_value, (str, bytes, bytearray)
        ):
            raise IntegrationError("Hermes result artifacts must be an array")
        artifacts: list[Mapping[str, Any]] = []
        for artifact in artifacts_value:
            if not isinstance(artifact, Mapping):
                raise IntegrationError("Hermes result artifacts must be objects")
            artifacts.append(artifact)
        validation = native_result.get("validation", {})
        if not isinstance(validation, Mapping):
            raise IntegrationError("Hermes result validation must be an object")
        message = native_result.get("message", "")
        if not isinstance(message, str):
            raise IntegrationError("Hermes result message must be a string")
        normalized = ExecutionResult(
            status,
            base_commit,
            contract_fingerprint,
            model_fingerprint,
            tuple(artifacts),
            validation,
            message,
        )
        return self.submit_result(packet, normalized, current_baseline=current_baseline)

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
            "authority": "hermes-executor-claim",
            "validation": dict(validation),
        }

    def cancel(
        self, packet: ExecutionPacket, *, message: str = "cancelled by Hermes"
    ) -> ExecutionResult:
        return ExecutionResult(
            ExecutionStatus.CANCELLED,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            message=message,
        )

    def install_interface_pack(
        self, target_root: str | Path, *, replace: bool = False
    ) -> InterfacePackInstallation:
        """Install the bundled pack into ``target_root/artifex`` after hash checks.

        Installation is explicit and is never called by detection, health, or
        execution.  The manifest is the complete write allowlist.
        """

        manifest_path = self._pack_manifest_path()
        manifest_bytes = manifest_path.read_bytes()
        manifest = yaml.safe_load(manifest_bytes)
        if not isinstance(manifest, Mapping) or manifest.get("schema_version") != "1.0":
            raise IntegrationError("invalid Hermes interface pack manifest")
        file_values = manifest.get("files")
        if not isinstance(file_values, Sequence) or isinstance(file_values, (str, bytes)):
            raise IntegrationError("Hermes interface pack manifest files must be an array")

        target = Path(target_root).resolve()
        target.mkdir(parents=True, exist_ok=True)
        destination = (target / "artifex").resolve()
        if target not in destination.parents:
            raise IntegrationError("interface pack destination escapes target root")
        if destination.exists() and not destination.is_dir():
            raise IntegrationError("interface pack destination is not a directory")

        checked: list[tuple[str, bytes]] = []
        for entry in file_values:
            if not isinstance(entry, Mapping):
                raise IntegrationError("interface pack file entries must be objects")
            relative = _safe_relative(str(entry.get("path", "")))
            expected_hash = str(entry.get("sha256", ""))
            source = (self._interface_pack_root / relative).resolve()
            if self._interface_pack_root.resolve() not in source.parents or not source.is_file():
                raise IntegrationError(f"interface pack source is missing: {relative}")
            if source.is_symlink():
                raise IntegrationError("interface pack sources may not be symlinks")
            content = source.read_bytes()
            if _pack_content_fingerprint(content) != expected_hash:
                raise IntegrationError(f"interface pack hash mismatch: {relative}")
            checked.append((relative, content))

        installed: list[str] = []
        for relative, content in checked:
            output = (destination / relative).resolve()
            if destination not in output.parents:
                raise IntegrationError("interface pack file escapes destination")
            if output.exists() and output.read_bytes() != content and not replace:
                raise IntegrationError(f"interface pack file already differs: {relative}")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
            installed.append(relative)
        return InterfacePackInstallation(
            str(destination),
            tuple(installed),
            hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def _pack_manifest_path(self) -> Path:
        return self._interface_pack_root / "manifest.yaml"


def _read_only_version_probe(executable: str) -> tuple[int, str]:
    completed = subprocess.run(
        [executable, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
        shell=False,
    )
    return completed.returncode, f"{completed.stdout}\n{completed.stderr}"


def _safe_relative(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or ":" in value:
        raise IntegrationError("interface pack paths must be safe relative paths")
    return path.as_posix()


def _pack_content_fingerprint(content: bytes) -> str:
    """Keep signed text-pack hashes stable across Git LF/CRLF checkouts."""

    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def _required_native_binding(value: Mapping[str, Any], name: str) -> str:
    binding = value.get(name)
    if not isinstance(binding, str) or not binding.strip() or binding != binding.strip():
        raise IntegrationError(f"Hermes result binding {name} is required and must be normalized")
    return binding
