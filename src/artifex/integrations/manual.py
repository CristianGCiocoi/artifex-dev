"""Reference integration that needs no external agent or harness."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from artifex.integrations.contracts import (
    Capability,
    CompatibilityRange,
    ConfigurationProvenance,
    ExecutionPacket,
    ExecutionResult,
    HealthReport,
    HealthStatus,
    IntegrationMetadata,
    IntegrationRole,
)
from artifex.workflow import ExecutionBaseline, ExecutionStatus


class ManualIntegration:
    """Produce portable work packets and classify manually supplied results."""

    @property
    def metadata(self) -> IntegrationMetadata:
        return IntegrationMetadata(
            integration_id="manual",
            name="Manual",
            version="1.0.0",
            compatibility=CompatibilityRange("0.1.0", "3.0.0"),
            tested_external_versions=("not-applicable",),
            roles=frozenset(
                {
                    IntegrationRole.INTERFACE,
                    IntegrationRole.HARNESS,
                    IntegrationRole.IMPLEMENTER,
                }
            ),
            capabilities=frozenset(
                {Capability.STRUCTURED_OUTPUT.value, Capability.REPOSITORY_READ.value}
            ),
            configuration=ConfigurationProvenance("built-in"),
        )

    def health(self) -> HealthReport:
        return HealthReport(
            HealthStatus.PASS,
            "manual packet exchange is available",
            {"packet_exchange": HealthStatus.PASS},
        )

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]:
        """Read inspectable project state without requiring conversation history."""

        root = Path(project_root).resolve()
        status_path = root / ".artifex" / "status.yaml"
        model_path = root / ".artifex" / "project-model.json"
        project_path = root / ".artifex" / "project.yaml"
        if status_path.is_file():
            value = yaml.safe_load(status_path.read_text(encoding="utf-8"))
            source = status_path
        elif model_path.is_file():
            value = json.loads(model_path.read_text(encoding="utf-8"))
            source = model_path
        elif project_path.is_file():
            value = yaml.safe_load(project_path.read_text(encoding="utf-8"))
            source = project_path
        else:
            raise FileNotFoundError(f"no ARTIFEX project state found under {root}")
        if not isinstance(value, Mapping):
            raise ValueError(f"project state is not an object: {source}")
        return {"source": str(source.relative_to(root)).replace("\\", "/"), "state": value}

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

    def submit_result(
        self,
        packet: ExecutionPacket,
        result: ExecutionResult,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult:
        """Ingest a result without granting it canonical acceptance authority."""

        current = packet.baseline if current_baseline is None else current_baseline
        return result.classified(current)

    ingest_result = submit_result

    @staticmethod
    def submit_validation(validation: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return executor validation as a claim; Core still owns acceptance."""

        return {"canonical": False, "authority": "executor-claim", "validation": dict(validation)}

    def cancel(
        self, packet: ExecutionPacket, *, message: str = "cancelled manually"
    ) -> ExecutionResult:
        return ExecutionResult(
            ExecutionStatus.CANCELLED,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            message=message,
        )
