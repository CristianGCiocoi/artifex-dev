from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from artifex.integrations.conformance import IntegrationConformanceSuite
from artifex.integrations.contracts import (
    Capability,
    ExecutionPacket,
    HealthStatus,
    IntegrationError,
    IntegrationRole,
)
from artifex.integrations.hermes import (
    HermesDetection,
    HermesIntegration,
    detect_local_hermes,
)
from artifex.integrations.manual import ManualIntegration
from artifex.integrations.registry import IntegrationRegistry
from artifex.integrations.research import (
    ResearchBundle,
    ResearchClaim,
    ResearchRequest,
    ResearchSource,
)
from artifex.integrations.selection import (
    SelectionPolicy,
    SelectionRequest,
    select_integration,
)
from artifex.workflow import ExecutionBaseline, ExecutionStatus


def _packet_fields(task_id: str = "M05-FIXTURE") -> dict[str, object]:
    return {
        "task_contract": {"id": task_id},
        "context": {"relevant": ["INV-003", "INV-013"]},
        "base_commit": "a" * 40,
        "project_model_fingerprint": "b" * 64,
        "acceptance_criteria": ("deterministic fixture passes",),
        "ownership": {"paths": ["owned.txt"]},
        "expected_result": {"status": [item.value for item in ExecutionStatus]},
        "interfaces": ("Integration Contract v1",),
        "invariants": ("INV-003", "INV-013", "INV-024"),
    }


def _research_request() -> ResearchRequest:
    return ResearchRequest(
        request_id="RSR-M05-001",
        purpose="choose a deterministic fixture transport",
        stage="research",
        questions=("Which transport remains inspectable?",),
        project_constraints=("no live mutation",),
        required_freshness="fixture",
        required_source_quality="primary",
        resource_envelope={"max_sources": 2},
    )


def _research_bundle(request: ResearchRequest) -> ResearchBundle:
    source = ResearchSource(
        "SRC-M05-1",
        "https://example.invalid/hermes-fixture",
        "Hermes fixture specification",
        "2026-08-21T00:00:00+00:00",
        "primary",
    )
    return ResearchBundle(
        "RSB-M05-001",
        request.request_id,
        ("packet exchange is inspectable",),
        ({"name": "session-only", "risk": "semantic loss"},),
        (ResearchClaim("packets survive sessions", (source.source_id,), 1.0),),
        (),
        (source,),
        {"provider": "hermes-simulated", "fixture": True},
    )


@pytest.mark.unit
def test_m05_t01_read_only_detection_and_doctor_health() -> None:
    calls: list[str] = []

    def probe(executable: str) -> tuple[int, str]:
        calls.append(executable)
        return 0, "Hermes Agent v0.20.4\n"

    detection = detect_local_hermes(
        ("hermes",), which=lambda _: "C:/fixture/hermes.exe", version_probe=probe
    )
    integration = HermesIntegration(detection)

    assert calls == ["C:/fixture/hermes.exe"]
    assert detection.status is HealthStatus.PASS
    assert detection.version == "0.20.4"
    assert detection.probe == "PATH + --version (read-only)"
    assert integration.health().status is HealthStatus.PASS
    assert integration.health().checks == {
        "local_detection": HealthStatus.PASS,
        "interface_pack": HealthStatus.PASS,
    }
    assert "0.20.4" in integration.metadata.tested_external_versions

    missing = detect_local_hermes(("hermes",), which=lambda _: None, version_probe=probe)
    assert missing.status is HealthStatus.DEGRADED
    assert calls == ["C:/fixture/hermes.exe"]
    with pytest.raises(IntegrationError, match="safe command names"):
        detect_local_hermes(("../hermes",), which=lambda _: None, version_probe=probe)


@pytest.mark.integration
def test_m05_t02_interface_pack_is_hash_verified_installable_and_idempotent(
    tmp_path: Path,
) -> None:
    integration = HermesIntegration.simulated("0.20.4")
    installation = integration.install_interface_pack(tmp_path / "hermes-skills")
    destination = Path(installation.destination)

    assert installation.installed_files == ("README.md", "skills/artifex/SKILL.md")
    assert (destination / "skills" / "artifex" / "SKILL.md").is_file()
    assert "auxiliary" in (destination / "README.md").read_text(encoding="utf-8")
    assert integration.install_interface_pack(tmp_path / "hermes-skills") == installation

    (destination / "README.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(IntegrationError, match="already differs"):
        integration.install_interface_pack(tmp_path / "hermes-skills")


@pytest.mark.unit
def test_m05_t03_t04_stage_and_implementation_task_mapping() -> None:
    integration = HermesIntegration.simulated()
    expected = {
        "idea": ("idea", "product-analyst"),
        "research": ("research", "researcher"),
        "architecture": ("architecture", "architect"),
        "implementation-plan": ("implementation-plan", "planner"),
        "implementation": ("router", "software-engineer"),
        "review": ("review", "reviewer"),
        "learn": ("learn", "knowledge-curator"),
    }

    assert {
        stage: (mapping["skill"], mapping["task_profile"])
        for stage, mapping in integration.stage_mapping().items()
    } == expected
    for stage, (skill, profile) in expected.items():
        dispatch = integration.prepare_stage_execution(stage, **_packet_fields(stage))
        assert ExecutionPacket.from_dict(dispatch.to_dict()["packet"]) == dispatch.packet
        assert (dispatch.skill, dispatch.task_profile) == (skill, profile)
        assert dispatch.canonical_acceptance is False

    implementation = integration.prepare_implementation_task(**_packet_fields("M05-T04"))
    assert implementation.stage == "implementation"
    assert implementation.task_profile == "software-engineer"
    with pytest.raises(IntegrationError, match="unsupported Hermes stage"):
        integration.prepare_stage_execution("deploy-production", **_packet_fields())


@pytest.mark.unit
def test_m05_t05_research_role_and_bundle_normalization() -> None:
    integration = HermesIntegration.simulated()
    request = _research_request()
    dispatch = integration.prepare_research(request)
    bundle = _research_bundle(request)

    assert IntegrationRole.RESEARCH_PROVIDER in integration.metadata.roles
    assert dispatch.native_memory_policy == "auxiliary-only"
    assert dispatch.to_dict()["canonical_decision"] is False
    assert integration.submit_research_result(request, bundle.to_dict()) == bundle

    wrong_request = _research_request().to_dict()
    wrong_request["request_id"] = "RSR-M05-OTHER"
    with pytest.raises(IntegrationError, match="does not match"):
        integration.submit_research_result(
            ResearchRequest.from_dict(wrong_request), bundle.to_dict()
        )


@pytest.mark.adversarial
def test_m05_t06_native_memory_is_auxiliary_and_cannot_self_promote() -> None:
    integration = HermesIntegration.simulated()
    observation = integration.observe_native_memory(
        "a possible lesson", provenance="Hermes fixture session (disposable)"
    )

    assert observation.canonical is False
    assert observation.scope == "HERMES_NATIVE_AUXILIARY"
    assert observation.promotion == "REQUIRES_ARTIFEX_KNOWLEDGE_POLICY"
    with pytest.raises(IntegrationError, match="ARTIFEX knowledge promotion"):
        integration.promote_native_memory(observation)
    with pytest.raises(IntegrationError, match="content and provenance"):
        integration.observe_native_memory(" ", provenance="session")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("native", "expected"),
    [
        ("completed", ExecutionStatus.SUCCESS),
        ("failed", ExecutionStatus.FAIL),
        ("blocked", ExecutionStatus.BLOCKED),
        ("interrupted", ExecutionStatus.CANCELLED),
        ("future-unknown-status", ExecutionStatus.FAIL),
    ],
)
def test_m05_t07_normalizes_native_results_fail_closed(
    native: str, expected: ExecutionStatus
) -> None:
    integration = HermesIntegration.simulated()
    packet = integration.prepare_execution(**_packet_fields())
    result = integration.normalize_result(
        packet,
        {
            "status": native,
            "artifacts": [{"path": "owned.txt"}],
            "validation": {"outcome": "PASS"},
            "message": "fixture",
        },
    )
    assert result.status is expected
    assert integration.submit_validation({"outcome": "PASS"})["canonical"] is False
    assert integration.cancel(packet).status is ExecutionStatus.CANCELLED

    stale = ExecutionBaseline(
        "c" * 40, packet.contract_fingerprint, packet.project_model_fingerprint
    )
    assert (
        integration.normalize_result(
            packet, {"status": "completed"}, current_baseline=stale
        ).status
        is ExecutionStatus.REBASE_REQUIRED
    )


@pytest.mark.integration
def test_m05_t08_end_to_end_hermes_fixture_is_deterministic_and_non_mutating(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".artifex"
    state.mkdir()
    canonical = {
        "schema_version": "1.0",
        "project": {"id": "M05-FIXTURE"},
        "stage": "idea",
    }
    status_path = state / "status.yaml"
    status_path.write_text(yaml.safe_dump(canonical, sort_keys=True), encoding="utf-8")
    before = status_path.read_bytes()
    integration = HermesIntegration.simulated("0.20.4")

    stages = ("idea", "research", "architecture", "implementation-plan")
    dispatches = [
        integration.prepare_stage_execution(stage, **_packet_fields(f"FIX-{stage}"))
        for stage in stages
    ]
    research = integration.prepare_research(_research_request())

    assert tuple(item.stage for item in dispatches) == stages
    assert all(item.mode == "packet" for item in dispatches)
    assert research.request.request_id == "RSR-M05-001"
    assert integration.read_project_status(tmp_path)["state"] == canonical
    assert status_path.read_bytes() == before
    assert list(tmp_path.rglob("*")) == [state, status_path]


@pytest.mark.integration
def test_m05_t09_shutdown_reopen_reconstructs_without_session_or_native_memory(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".artifex"
    state.mkdir()
    canonical = {
        "schema_version": "1.0",
        "project": {"id": "CONTINUITY", "name": "Continuity fixture"},
        "artifacts": [{"id": "ART-001", "status": "CURRENT"}],
    }
    (state / "project-model.json").write_text(
        json.dumps(canonical, sort_keys=True), encoding="utf-8"
    )

    session = HermesIntegration.simulated("0.20.4")
    before = session.read_project_status(tmp_path)
    ephemeral = session.observe_native_memory("session hint", provenance="session-1")
    del session

    reopened = HermesIntegration(HermesDetection.unavailable("session is gone"))
    after = reopened.read_project_status(tmp_path)
    manual = ManualIntegration().read_project_status(tmp_path)

    assert before == after == manual
    assert after["state"] == canonical
    assert ephemeral.content not in json.dumps(after)
    assert reopened.health().status is HealthStatus.DEGRADED


@pytest.mark.conformance
def test_m05_t10_hermes_conformance_and_preferred_capability_selection_pass() -> None:
    hermes = HermesIntegration.simulated("0.20.4")
    report = IntegrationConformanceSuite().run(hermes)
    registry = IntegrationRegistry((ManualIntegration(), hermes))
    decision = select_integration(
        registry,
        SelectionRequest(
            IntegrationRole.IMPLEMENTER,
            frozenset(
                {
                    Capability.STRUCTURED_OUTPUT.value,
                    Capability.SUBAGENTS.value,
                    Capability.WORKTREES.value,
                }
            ),
        ),
        SelectionPolicy(preferred_integrations=("hermes", "manual")),
    )

    assert report.status is HealthStatus.PASS
    assert len(report.checks) == 9
    assert decision.integration.metadata.integration_id == "hermes"
    assert decision.reason == "first compatible policy preference"


@pytest.mark.adversarial
def test_m05_t10_security_boundaries_reject_pack_escape_and_malformed_results(
    tmp_path: Path,
) -> None:
    source = tmp_path / "pack"
    source.mkdir()
    (source / "manifest.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "files": [{"path": "../escape", "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    integration = HermesIntegration.simulated()
    untrusted_pack = HermesIntegration(integration.detection, interface_pack_root=source)

    with pytest.raises(IntegrationError, match="safe relative"):
        untrusted_pack.install_interface_pack(tmp_path / "target")

    packet = integration.prepare_execution(**_packet_fields())
    with pytest.raises(IntegrationError, match="status must be a string"):
        integration.normalize_result(packet, {"status": ["completed"]})
    with pytest.raises(IntegrationError, match="artifacts must be objects"):
        integration.normalize_result(packet, {"status": "completed", "artifacts": ["bad"]})
