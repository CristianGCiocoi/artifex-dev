from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from artifex.integrations import (
    ConformanceSuite,
    ExecutionPacket,
    ExecutionResult,
    HealthStatus,
    IntegrationError,
    IntegrationRegistry,
    IntegrationRole,
    ManualIntegration,
    ResearchBundle,
    ResearchClaim,
    ResearchRequest,
    ResearchSource,
    SelectionPolicy,
    SelectionRequest,
    run_doctor,
    select_integration,
)
from artifex.integrations.hermes import HermesDetection, HermesIntegration
from artifex.workflow import ExecutionBaseline, ExecutionStatus


def _packet() -> ExecutionPacket:
    return ManualIntegration().prepare_execution(
        task_contract={"id": "M04-T03"},
        context={"relevant": ["INV-002"]},
        base_commit="a" * 40,
        project_model_fingerprint="b" * 64,
        acceptance_criteria=("manual PASS",),
        ownership={"paths": ["owned.txt"]},
        expected_result={"status": [status.value for status in ExecutionStatus]},
        interfaces=("Application API",),
        invariants=("INV-002",),
    )


@pytest.mark.unit
def test_registry_metadata_health_schema_and_capability_policy() -> None:
    manual = ManualIntegration()
    registry = IntegrationRegistry((manual,))
    metadata = manual.metadata.to_dict(core_version="0.1.0")
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "integration.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(metadata)

    assert registry.report()[0]["health"]["status"] == "PASS"  # type: ignore[index]
    decision = select_integration(
        registry,
        SelectionRequest(IntegrationRole.IMPLEMENTER, frozenset({"structured_output"})),
    )
    assert decision.integration.metadata.integration_id == "manual"
    with pytest.raises(IntegrationError, match="already registered"):
        registry.register(manual)
    with pytest.raises(IntegrationError, match="no integration"):
        select_integration(
            registry,
            SelectionRequest(IntegrationRole.RESEARCH_PROVIDER, frozenset()),
        )


@pytest.mark.unit
def test_builtin_manual_integration_reports_core_2x_compatibility() -> None:
    compatibility = ManualIntegration().metadata.compatibility

    assert compatibility.supports("2.0.0")
    assert compatibility.supports("2.99.0")
    assert not compatibility.supports("3.0.0")


@pytest.mark.unit
def test_manual_packet_result_ingest_and_stale_mapping() -> None:
    manual = ManualIntegration()
    packet = _packet()
    assert ExecutionPacket.from_dict(packet.to_dict()) == packet
    result = ExecutionResult(
        ExecutionStatus.SUCCESS,
        packet.base_commit,
        packet.contract_fingerprint,
        packet.project_model_fingerprint,
        artifacts=({"path": "owned.txt"},),
    )
    assert manual.submit_result(packet, result).status is ExecutionStatus.SUCCESS
    stale = ExecutionBaseline(
        "c" * 40, packet.contract_fingerprint, packet.project_model_fingerprint
    )
    assert (
        manual.submit_result(packet, result, current_baseline=stale).status
        is ExecutionStatus.REBASE_REQUIRED
    )
    assert manual.cancel(packet).status is ExecutionStatus.CANCELLED
    assert manual.submit_validation({"outcome": "PASS"})["canonical"] is False

    tampered = packet.to_dict()
    tampered["base_commit"] = "d" * 40
    with pytest.raises(IntegrationError, match="fingerprint"):
        ExecutionPacket.from_dict(tampered)


@pytest.mark.conformance
def test_manual_integration_conformance_suite_passes() -> None:
    report = ConformanceSuite().run(ManualIntegration())
    assert report.status is HealthStatus.PASS
    assert {check.check_id for check in report.checks} == {
        "compatibility-reporting",
        "health",
        "project-status-context-read",
        "stage-execution-packet",
        "artifact-result-submission",
        "validation-interaction",
        "failure-mapping",
        "cancellation-mapping",
        "stale-result-mapping",
    }


@pytest.mark.unit
def test_research_contracts_round_trip_and_validate_schema() -> None:
    request = ResearchRequest(
        request_id="RSR-M04-001",
        purpose="choose a transport",
        stage="architecture",
        questions=("Which local transport is inspectable?",),
        project_constraints=("no daemon",),
        required_freshness="current major version",
        required_source_quality="primary sources",
        resource_envelope={"max_sources": 5},
    )
    source = ResearchSource(
        "SRC-1",
        "https://example.invalid/spec",
        "Specification",
        "2026-08-21T12:00:00+00:00",
        "primary",
    )
    bundle = ResearchBundle(
        bundle_id="RSB-M04-001",
        request_id=request.request_id,
        findings=("stdio is local and inspectable",),
        alternatives=({"name": "network", "risk": "control plane"},),
        claims=(ResearchClaim("stdio is local", (source.source_id,), 0.95),),
        unresolved_questions=(),
        source_manifest=(source,),
        generation_metadata={"provider": "manual"},
    )
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "research.schema.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(request.to_dict())
    validator.validate(bundle.to_dict())
    assert ResearchRequest.from_dict(request.to_dict()) == request
    assert ResearchBundle.from_dict(bundle.to_dict()) == bundle

    missing_source = bundle.to_dict()
    missing_source["source_manifest"] = []
    with pytest.raises(IntegrationError, match="missing sources"):
        ResearchBundle.from_dict(missing_source)


@pytest.mark.unit
def test_doctor_is_non_mutating_and_reports_project_health(tmp_path: Path) -> None:
    (tmp_path / ".artifex").mkdir()
    report = run_doctor(IntegrationRegistry((ManualIntegration(),)), project_root=tmp_path)
    assert report.status is HealthStatus.PASS
    assert {check.check_id for check in report.checks} >= {
        "python",
        "git",
        "project",
        "integration:manual",
    }


@pytest.mark.conformance
def test_canonical_skill_bundles_are_portable_and_reference_themselves() -> None:
    root = Path(__file__).parents[1] / "skills"
    expected = {
        "router",
        "idea",
        "research",
        "architecture",
        "implementation-plan",
        "review",
        "learn",
    }
    assert {path.name for path in root.iterdir() if path.is_dir()} == expected
    for skill_name in expected:
        skill_root = root / skill_name
        instructions = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        shim = yaml.safe_load(
            (skill_root / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        prompt = shim["interface"]["default_prompt"]
        assert f"${skill_name}" in prompt
        assert "ARTIFEX" in instructions
        assert "canonical" in instructions.lower() or "authority" in instructions.lower()


@pytest.mark.adversarial
def test_selection_never_prefers_or_explicitly_returns_an_unhealthy_integration() -> None:
    manual = ManualIntegration()
    hermes = HermesIntegration(HermesDetection.unavailable("fixture unavailable"))
    registry = IntegrationRegistry((hermes, manual))
    policy = SelectionPolicy(preferred_integrations=("hermes", "manual"))

    decision = select_integration(
        registry,
        SelectionRequest(IntegrationRole.IMPLEMENTER),
        policy,
    )
    assert decision.integration.metadata.integration_id == "manual"
    with pytest.raises(IntegrationError, match="unhealthy"):
        select_integration(
            registry,
            SelectionRequest(IntegrationRole.IMPLEMENTER, integration_id="hermes"),
            policy,
        )
