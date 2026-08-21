from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
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
    DEFAULT_HERMES_PROBE_TIMEOUT_SECONDS,
    HermesDetection,
    HermesDispatch,
    HermesIntegration,
    canonical_project_model_fingerprint,
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
from artifex.policy import AcceptanceAuthority
from artifex.project.store import FileSystemProjectStore
from artifex.validation import (
    EvidenceBinding,
    EvidenceEntry,
    EvidenceLedger,
    MeasuredFact,
    StructuredInspectionValidator,
    ValidationContext,
)
from artifex.workflow import (
    ExecutionBaseline,
    ExecutionStatus,
    StageContract,
    StageState,
    WorkflowEngine,
)


def _packet_fields(
    task_id: str = "M05-FIXTURE",
    *,
    model_fingerprint: str = "b" * 64,
    owned_path: str = "owned.txt",
) -> dict[str, object]:
    return {
        "task_contract": {"id": task_id},
        "context": {"relevant": ["INV-003", "INV-013"]},
        "base_commit": "a" * 40,
        "project_model_fingerprint": model_fingerprint,
        "acceptance_criteria": ("deterministic fixture passes",),
        "ownership": {"paths": [owned_path]},
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


def _native_result(
    packet: ExecutionPacket, status: str = "completed", **values: object
) -> dict[str, object]:
    return {
        "status": status,
        "base_commit": packet.base_commit,
        "execution_contract_fingerprint": packet.contract_fingerprint,
        "project_model_fingerprint": packet.project_model_fingerprint,
        **values,
    }


def _write_valid_project_model(root: Path, *, description: str = "fixture") -> str:
    model = {
        "schema_version": "1.0",
        "project": {
            "id": "M05-FIXTURE",
            "name": "M05 fixture",
            "description": description,
            "lifecycle": "greenfield",
            "workflow_depth": "STANDARD",
        },
        "git": {
            "initialized": False,
            "branch": None,
            "baseline_commit": None,
            "current_commit": None,
            "dirty": None,
            "remotes": [],
        },
        "artifacts": [],
        "entities": [],
    }
    path = root / ".artifex" / "project-model.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return canonical_project_model_fingerprint(root)


@pytest.mark.unit
def test_m05_t01_read_only_detection_and_doctor_health() -> None:
    calls: list[tuple[str, float]] = []

    def probe(executable: str, timeout_seconds: float) -> tuple[int, str]:
        calls.append((executable, timeout_seconds))
        return 0, "Hermes Agent v0.20.4\n"

    detection = detect_local_hermes(
        ("hermes",), which=lambda _: "C:/fixture/hermes.exe", version_probe=probe
    )
    integration = HermesIntegration(detection)

    assert calls == [("C:/fixture/hermes.exe", DEFAULT_HERMES_PROBE_TIMEOUT_SECONDS)]
    assert DEFAULT_HERMES_PROBE_TIMEOUT_SECONDS >= 10
    assert detection.status is HealthStatus.PASS
    assert detection.version == "0.20.4"
    assert detection.probe == "PATH + --version (read-only, timeout=15s)"
    assert integration.health().status is HealthStatus.PASS
    assert integration.health().checks == {
        "local_detection": HealthStatus.PASS,
        "interface_pack": HealthStatus.PASS,
    }
    assert "0.20.4" in integration.metadata.tested_external_versions

    missing = detect_local_hermes(("hermes",), which=lambda _: None, version_probe=probe)
    assert missing.status is HealthStatus.DEGRADED
    assert calls == [("C:/fixture/hermes.exe", DEFAULT_HERMES_PROBE_TIMEOUT_SECONDS)]
    with pytest.raises(IntegrationError, match="safe command names"):
        detect_local_hermes(("../hermes",), which=lambda _: None, version_probe=probe)


@pytest.mark.unit
def test_m05_t01_detection_timeout_is_configurable_bounded_and_fails_safely() -> None:
    observed: list[float] = []

    def timeout_probe(_: str, timeout_seconds: float) -> tuple[int, str]:
        observed.append(timeout_seconds)
        raise subprocess.TimeoutExpired("hermes --version", timeout_seconds)

    detection = detect_local_hermes(
        ("hermes",),
        which=lambda _: "C:/fixture/hermes.exe",
        version_probe=timeout_probe,
        timeout_seconds=12.0,
    )

    assert observed == [12.0]
    assert detection.status is HealthStatus.DEGRADED
    assert "TimeoutExpired" in detection.summary
    for invalid in (0.0, -1.0, float("inf"), 60.1):
        with pytest.raises(IntegrationError, match="timeout must be within"):
            detect_local_hermes(timeout_seconds=invalid)


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
        _native_result(
            packet,
            native,
            artifacts=[{"path": "owned.txt"}],
            validation={"outcome": "PASS"},
            message="fixture",
        ),
    )
    assert result.status is expected
    assert integration.submit_validation({"outcome": "PASS"})["canonical"] is False
    assert integration.cancel(packet).status is ExecutionStatus.CANCELLED

    stale = ExecutionBaseline(
        "c" * 40, packet.contract_fingerprint, packet.project_model_fingerprint
    )
    assert (
        integration.normalize_result(
            packet, _native_result(packet), current_baseline=stale
        ).status
        is ExecutionStatus.REBASE_REQUIRED
    )


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "binding",
    ("base_commit", "execution_contract_fingerprint", "project_model_fingerprint"),
)
def test_m05_t07_preserves_native_binding_and_classifies_forgery_as_stale(
    binding: str,
) -> None:
    integration = HermesIntegration.simulated()
    packet = integration.prepare_execution(**_packet_fields())
    native = _native_result(packet)
    native[binding] = "f" * (40 if binding == "base_commit" else 64)

    result = integration.normalize_result(packet, native)

    assert result.status is ExecutionStatus.REBASE_REQUIRED
    assert result.to_dict()[binding] == native[binding]


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "binding",
    ("base_commit", "execution_contract_fingerprint", "project_model_fingerprint"),
)
def test_m05_t07_rejects_missing_native_binding_as_malformed(binding: str) -> None:
    integration = HermesIntegration.simulated()
    packet = integration.prepare_execution(**_packet_fields())
    native = _native_result(packet)
    del native[binding]

    with pytest.raises(IntegrationError, match=rf"binding {binding} is required"):
        integration.normalize_result(packet, native)


@pytest.mark.integration
def test_m05_t08_durable_runner_workflow_reopens_without_hermes_session(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".artifex"
    state.mkdir()
    model_fingerprint = _write_valid_project_model(tmp_path)
    canonical_status = {
        "schema_version": "1.0",
        "project": {"id": "M05-FIXTURE"},
        "stages": {
            stage: "PENDING"
            for stage in ("idea", "research", "architecture", "implementation-plan")
        },
    }
    store = FileSystemProjectStore(tmp_path)
    store.write_atomic(
        ".artifex/status.yaml",
        yaml.safe_dump(canonical_status, sort_keys=True).encode("utf-8"),
    )
    evidence_path = state / "validation" / "evidence" / "ledger.jsonl"
    ledger = EvidenceLedger({"VAL-M05-STAGE": "1"}, journal_path=evidence_path)
    integration = HermesIntegration.simulated("0.20.4")
    native_memory = integration.observe_native_memory(
        "disposable session hint", provenance="M05 deterministic runner"
    )
    engine = WorkflowEngine()
    contracts = (
        StageContract("idea", ("request",), ("idea",), frozenset(), ("core",)),
        StageContract("research", ("idea",), ("research-bundle",), frozenset(), ("core",)),
        StageContract(
            "architecture",
            ("idea", "research-bundle"),
            ("architecture",),
            frozenset(),
            ("core",),
        ),
        StageContract(
            "implementation-plan",
            ("architecture",),
            ("plan",),
            frozenset(),
            ("core",),
        ),
    )
    for contract in contracts:
        engine.register(contract)

    def runner(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        relative = f"artifacts/{dispatch.stage}.md"
        target = project_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"# {dispatch.stage}\n\nProduced from {dispatch.packet.task_contract['id']}.\n",
            encoding="utf-8",
        )
        return _native_result(
            dispatch.packet,
            artifacts=[{"path": relative, "stage": dispatch.stage}],
            validation={"outcome": "PASS", "authority": "hermes-executor-claim"},
        )

    available_outputs = {"request"}
    executions = []
    for index, contract in enumerate(contracts, start=1):
        artifact_path = f"artifacts/{contract.stage_id}.md"
        dispatch = integration.prepare_stage_execution(
            contract.stage_id,
            **_packet_fields(
                f"FIX-{contract.stage_id}",
                model_fingerprint=model_fingerprint,
                owned_path=artifact_path,
            ),
        )
        engine.transition(contract.stage_id, StageState.READY)
        engine.start(
            contract.stage_id,
            available_inputs=available_outputs,
            available_capabilities=set(),
            baseline=dispatch.packet.baseline,
        )
        execution = integration.execute_stage(
            dispatch, project_root=tmp_path, runner=runner
        )
        executions.append(execution)
        assert execution.result.status is ExecutionStatus.SUCCESS
        assert execution.changed_artifacts == (artifact_path,)
        assert execution.project_model_fingerprint_before == model_fingerprint
        assert execution.project_model_fingerprint_after == model_fingerprint
        assert integration.submit_validation(execution.result.validation)["canonical"] is False

        binding = EvidenceBinding(
            dispatch.packet.base_commit,
            dispatch.packet.contract_fingerprint,
            (model_fingerprint,),
        )
        context = ValidationContext(
            f"{contract.stage_id} artifact delta is independently verified",
            "hermes",
            binding,
        )
        validator_result = StructuredInspectionValidator("VAL-M05-STAGE", "1").validate(
            context,
            inspector_id="core-fixture-validator",
            passed=store.exists(artifact_path),
            facts=(MeasuredFact("changed_artifact", artifact_path),),
            output="owned artifact delta verified",
        )
        evidence = EvidenceEntry.create(
            f"EVD-M05-STAGE-{index}",
            validator_result,
            binding,
            recorded_at=datetime(2026, 8, 21, index, tzinfo=UTC),
        )
        assert evidence.independent_of_executor
        ledger.append(evidence)

        claimed = engine.claim_complete(contract.stage_id, outputs=set(contract.produces))
        assert claimed.state is StageState.CLAIMED_COMPLETE
        engine.transition(contract.stage_id, StageState.VALIDATING)
        accepted = engine.transition(
            contract.stage_id,
            StageState.ACCEPTED,
            authority=AcceptanceAuthority.CORE,
        )
        assert accepted.state is StageState.ACCEPTED
        available_outputs.update(contract.produces)
        canonical_status["stages"][contract.stage_id] = accepted.state.value  # type: ignore[index]
        store.write_atomic(
            ".artifex/status.yaml",
            yaml.safe_dump(canonical_status, sort_keys=True).encode("utf-8"),
        )

    request = _research_request()
    research = integration.prepare_research(request)
    bundle = integration.submit_research_result(request, _research_bundle(request).to_dict())

    assert tuple(item.dispatch.stage for item in executions) == tuple(
        contract.stage_id for contract in contracts
    )
    assert research.request.request_id == bundle.request_id
    assert all(engine.get(contract.stage_id).state is StageState.ACCEPTED for contract in contracts)
    assert canonical_project_model_fingerprint(tmp_path) == model_fingerprint

    del integration
    del engine
    reopened_state = ManualIntegration().read_project_status(tmp_path)["state"]
    reopened_ledger = EvidenceLedger({"VAL-M05-STAGE": "1"}, journal_path=evidence_path)
    assert reopened_state == canonical_status
    assert set(reopened_state["stages"].values()) == {"ACCEPTED"}
    assert len(reopened_ledger.entries) == 4
    assert all(entry.independent_of_executor for entry in reopened_ledger.entries)
    assert native_memory.content not in json.dumps(reopened_state)
    assert all(store.exists(f"artifacts/{contract.stage_id}.md") for contract in contracts)


@pytest.mark.adversarial
def test_m05_runner_rejects_successful_noop(tmp_path: Path) -> None:
    model_fingerprint = _write_valid_project_model(tmp_path)
    integration = HermesIntegration.simulated()
    dispatch = integration.prepare_stage_execution(
        "idea",
        **_packet_fields(
            model_fingerprint=model_fingerprint, owned_path="artifacts/idea.md"
        ),
    )

    def noop(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        del project_root
        return _native_result(dispatch.packet, artifacts=[{"path": "artifacts/idea.md"}])

    execution = integration.execute_stage(dispatch, project_root=tmp_path, runner=noop)

    assert execution.result.status is ExecutionStatus.FAIL
    assert execution.changed_artifacts == ()
    assert "unchanged" in execution.result.message


@pytest.mark.integration
def test_m05_runner_accepts_owned_content_change(tmp_path: Path) -> None:
    model_fingerprint = _write_valid_project_model(tmp_path)
    target = tmp_path / "artifacts" / "idea.md"
    target.parent.mkdir(parents=True)
    target.write_text("before", encoding="utf-8")
    integration = HermesIntegration.simulated()
    dispatch = integration.prepare_stage_execution(
        "idea",
        **_packet_fields(
            model_fingerprint=model_fingerprint, owned_path="artifacts/idea.md"
        ),
    )

    def changed(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        (project_root / "artifacts" / "idea.md").write_text("after", encoding="utf-8")
        return _native_result(dispatch.packet, artifacts=[{"path": "artifacts/idea.md"}])

    execution = integration.execute_stage(dispatch, project_root=tmp_path, runner=changed)

    assert execution.result.status is ExecutionStatus.SUCCESS
    assert execution.changed_artifacts == ("artifacts/idea.md",)


@pytest.mark.adversarial
def test_m05_runner_preserves_forged_identity_and_requires_rebase(tmp_path: Path) -> None:
    model_fingerprint = _write_valid_project_model(tmp_path)
    integration = HermesIntegration.simulated()
    dispatch = integration.prepare_stage_execution(
        "idea",
        **_packet_fields(
            model_fingerprint=model_fingerprint, owned_path="artifacts/idea.md"
        ),
    )

    def forged(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        target = project_root / "artifacts" / "idea.md"
        target.parent.mkdir(parents=True)
        target.write_text("forged baseline fixture", encoding="utf-8")
        native = _native_result(dispatch.packet, artifacts=[{"path": "artifacts/idea.md"}])
        native["base_commit"] = "f" * 40
        return native

    execution = integration.execute_stage(dispatch, project_root=tmp_path, runner=forged)

    assert execution.result.status is ExecutionStatus.REBASE_REQUIRED
    assert execution.result.base_commit == "f" * 40
    assert execution.changed_artifacts == ()


@pytest.mark.adversarial
def test_m05_runner_detects_post_run_project_model_drift(tmp_path: Path) -> None:
    model_fingerprint = _write_valid_project_model(tmp_path)
    integration = HermesIntegration.simulated()
    dispatch = integration.prepare_stage_execution(
        "idea",
        **_packet_fields(
            model_fingerprint=model_fingerprint, owned_path="artifacts/idea.md"
        ),
    )

    def drifting(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        target = project_root / "artifacts" / "idea.md"
        target.parent.mkdir(parents=True)
        target.write_text("valid artifact with invalid model drift", encoding="utf-8")
        _write_valid_project_model(project_root, description="changed during runner")
        return _native_result(dispatch.packet, artifacts=[{"path": "artifacts/idea.md"}])

    execution = integration.execute_stage(dispatch, project_root=tmp_path, runner=drifting)

    assert execution.result.status is ExecutionStatus.REBASE_REQUIRED
    assert execution.project_model_fingerprint_before == model_fingerprint
    assert execution.project_model_fingerprint_after != model_fingerprint
    assert execution.changed_artifacts == ()


@pytest.mark.adversarial
def test_m05_runner_maps_corrupt_post_run_project_model_to_rebase(tmp_path: Path) -> None:
    model_fingerprint = _write_valid_project_model(tmp_path)
    integration = HermesIntegration.simulated()
    dispatch = integration.prepare_stage_execution(
        "idea",
        **_packet_fields(
            model_fingerprint=model_fingerprint, owned_path="artifacts/idea.md"
        ),
    )

    def corrupting(*, dispatch: HermesDispatch, project_root: Path) -> dict[str, object]:
        target = project_root / "artifacts" / "idea.md"
        target.parent.mkdir(parents=True)
        target.write_text("artifact before corrupting model", encoding="utf-8")
        (project_root / ".artifex" / "project-model.json").write_text(
            "not-json", encoding="utf-8"
        )
        return _native_result(dispatch.packet, artifacts=[{"path": "artifacts/idea.md"}])

    execution = integration.execute_stage(dispatch, project_root=tmp_path, runner=corrupting)

    assert execution.result.status is ExecutionStatus.REBASE_REQUIRED
    assert execution.project_model_fingerprint_before == model_fingerprint
    assert execution.project_model_fingerprint_after is None


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
        integration.normalize_result(
            packet, _native_result(packet, artifacts=["bad"])
        )
