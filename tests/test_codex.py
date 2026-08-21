from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from artifex.application import OperationRequest
from artifex.cli import app as cli_app
from artifex.compilation import compile_human_documentation, generation_manifest
from artifex.ids import StableId
from artifex.integrations.codex import (
    CODEX_OPERATION_NAMES,
    CodexDetection,
    CodexExecutionFixture,
    CodexIntegration,
    CodexWorkerPlan,
    ContinuitySnapshot,
    create_codex_application,
    detect_codex,
    discover_agents_hierarchy,
    render_agents_shim,
)
from artifex.integrations.conformance import IntegrationConformanceSuite
from artifex.integrations.contracts import (
    ExecutionPacket,
    ExecutionResult,
    HealthStatus,
    IntegrationError,
)
from artifex.mcp import LocalMCPServer
from artifex.policy import AcceptanceAuthority
from artifex.project import (
    ChangeSet,
    ChangeSetRepository,
    ChangeSetStatus,
    ProjectLifecycle,
    ProjectRepository,
    WorkflowDepth,
)
from artifex.validation import (
    AcceptanceContract,
    AcceptanceCriterion,
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


def _successful_detection() -> CodexDetection:
    return CodexDetection(True, "/fixture/codex", "1.2.3", "codex-cli 1.2.3")


def _completed(
    arguments: tuple[str, ...] | list[str],
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _commit_all(root: Path, message: str) -> str:
    _git(root, "config", "user.name", "ARTIFEX Codex Fixture")
    _git(root, "config", "user.email", "artifex-codex@local.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _packet(
    integration: CodexIntegration,
    *,
    base_commit: str = "a" * 40,
    model_fingerprint: str = "b" * 64,
    task_id: str = "M06-T04",
) -> ExecutionPacket:
    return integration.prepare_execution(
        task_contract={"id": task_id, "stage": "execution"},
        context={"relevant": ["INV-024"]},
        base_commit=base_commit,
        project_model_fingerprint=model_fingerprint,
        acceptance_criteria=("Codex result is portable",),
        ownership={"paths": ["owned.txt"]},
        expected_result={"status": [status.value for status in ExecutionStatus]},
        interfaces=("Application API", "MCP"),
        invariants=("INV-013", "INV-024"),
    )


def _model_fingerprint(repository: ProjectRepository) -> str:
    return str(
        generation_manifest(repository.load().to_dict())["project_model_fingerprint"]
    )


def _execute_and_accept(
    root: Path,
    integration: CodexIntegration,
    packet: ExecutionPacket,
    *,
    stage_id: str,
    output: str,
    evidence_id: str,
) -> tuple[ExecutionResult, EvidenceLedger, WorkflowEngine]:
    acceptance = AcceptanceContract(
        contract_id=f"VAL-{stage_id}",
        deliverable=output,
        requirements=("REQ-F-043",),
        interfaces=("Codex",),
        invariants=("INV-013", "INV-024"),
        criteria=(AcceptanceCriterion(f"AC-{stage_id}", "adapter result is bound"),),
        validators=("VAL-CODEX-INDEPENDENT",),
        base_commit=packet.base_commit,
        project_model_fingerprint=packet.project_model_fingerprint,
    ).start()
    binding = EvidenceBinding(
        acceptance.base_commit,
        acceptance.fingerprint,
        (acceptance.project_model_fingerprint,),
    )
    workflow = WorkflowEngine()
    workflow.register(
        StageContract(
            stage_id=stage_id,
            requires=("project-model",),
            produces=(output,),
            capabilities=frozenset({"repository_read", "repository_write"}),
            validators=("VAL-CODEX-INDEPENDENT",),
        )
    )
    workflow.transition(stage_id, StageState.READY)
    workflow.start(
        stage_id,
        available_inputs={"project-model"},
        available_capabilities={"repository_read", "repository_write"},
        baseline=packet.baseline,
    )
    plan = integration.prepare_stage(packet, root)
    fixture = CodexExecutionFixture.bound(
        packet,
        ExecutionStatus.SUCCESS,
        artifacts=({"path": output, "state": "produced"},),
        validation={"adapter_boundary": "PASS"},
    )
    result = integration.execute_stage(plan, fixture)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.validation == {"adapter_boundary": "PASS"}
    workflow.claim_complete(stage_id, outputs={output})
    workflow.transition(stage_id, StageState.VALIDATING)

    validator_result = StructuredInspectionValidator(
        "VAL-CODEX-INDEPENDENT", "1"
    ).validate(
        ValidationContext("bound adapter execution", "codex", binding),
        inspector_id="independent-fixture",
        passed=result.status is ExecutionStatus.SUCCESS,
        facts=(MeasuredFact("artifact_count", len(result.artifacts)),),
    )
    entry = EvidenceEntry.create(
        evidence_id,
        validator_result,
        binding,
        recorded_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    ledger = EvidenceLedger(
        {"VAL-CODEX-INDEPENDENT": "1"},
        journal_path=root / ".artifex" / "validation" / "evidence" / "ledger.jsonl",
    )
    ledger.append(entry)
    gate = GateGraph(
        (
            GateDefinition(
                f"G-{stage_id}",
                GateLevel.TASK,
                (
                    EvidenceRequirement(
                        "bound adapter execution",
                        frozenset({"VAL-CODEX-INDEPENDENT"}),
                        frozenset({ValidatorKind.STRUCTURED_INSPECTION}),
                        require_independent=True,
                    ),
                ),
            ),
        )
    )
    assert (
        gate.evaluate(
            f"G-{stage_id}",
            ledger=ledger,
            binding=binding,
            authority=AcceptanceAuthority.CORE,
        )
        is GateState.PASS
    )
    workflow.transition(stage_id, StageState.ACCEPTED, authority=AcceptanceAuthority.CORE)
    return result, ledger, workflow


@pytest.mark.unit
def test_m06_t01_detection_is_versioned_capability_rich_and_read_only() -> None:
    observed: list[tuple[str, ...]] = []

    def runner(arguments: object) -> subprocess.CompletedProcess[str]:
        command = tuple(str(item) for item in arguments)  # type: ignore[arg-type]
        observed.append(command)
        return _completed(command, stdout="codex-cli 1.2.3\n")

    detection = detect_codex(
        which=lambda _: "/fixture/codex",
        runner=runner,  # type: ignore[arg-type]
    )
    assert detection.available is True
    assert detection.version == "1.2.3"
    assert {"skills", "MCP", "worktrees", "structured_output"} <= detection.capabilities
    assert observed == [("/fixture/codex", "--version")]
    assert detection.to_dict()["discovery_mode"] == "read-only"

    missing = detect_codex(which=lambda _: None)
    assert missing.status is HealthStatus.DEGRADED
    assert missing.version is None
    failed = detect_codex(
        which=lambda _: "/fixture/codex",
        runner=lambda arguments: _completed(
            list(arguments), returncode=7, stderr="probe denied"
        ),
    )
    assert failed.available is False
    assert "exited with 7" in str(failed.error)
    malformed = detect_codex(
        which=lambda _: "/fixture/codex",
        runner=lambda arguments: _completed(list(arguments), stdout="codex unknown"),
    )
    assert "semantic version" in str(malformed.error)


@pytest.mark.conformance
def test_m06_t02_interface_pack_has_all_portable_agent_skills() -> None:
    root = Path(__file__).parents[1] / "interface_packs" / "codex"
    manifest = yaml.safe_load((root / "pack.yaml").read_text(encoding="utf-8"))
    assert manifest["id"] == "codex"
    assert set(manifest["roles"]) == {"interface", "harness", "implementer"}
    assert manifest["authority"]["native_memory"] == "auxiliary_only"
    expected = {
        "router",
        "idea",
        "research",
        "architecture",
        "implementation-plan",
        "review",
        "learn",
    }
    skills_root = root / "skills"
    assert {path.name for path in skills_root.iterdir() if path.is_dir()} == expected
    for name in expected:
        content = (skills_root / name / "SKILL.md").read_text(encoding="utf-8")
        assert f"skills/{name}/SKILL.md" in content
        assert "canonical" in content.casefold() or "authority" in content.casefold()
    assert "native codex memory" in (root / "AGENTS.md").read_text(
        encoding="utf-8"
    ).casefold()
    assert json.loads((root / "mcp.json").read_text(encoding="utf-8"))["mcpServers"]


@pytest.mark.unit
def test_m06_t03_agents_hierarchy_is_scoped_and_override_aware(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "feature"
    nested.mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("root\n", encoding="utf-8")
    (tmp_path / "src" / "AGENTS.md").write_text("ignored\n", encoding="utf-8")
    (tmp_path / "src" / "AGENTS.override.md").write_text("override\n", encoding="utf-8")
    (nested / "AGENTS.md").write_text("feature\n", encoding="utf-8")

    layers = discover_agents_hierarchy(tmp_path, nested / "worker.py")
    assert [layer.content for layer in layers] == ["root\n", "override\n", "feature\n"]
    assert [layer.override for layer in layers] == [False, True, False]
    shim = render_agents_shim(project_model_fingerprint="f" * 64, scope="src/feature")
    assert "PROJECT_MODEL_SHA256: " + "f" * 64 in shim
    assert "native Codex memory" in shim
    with pytest.raises(IntegrationError, match="inside"):
        discover_agents_hierarchy(tmp_path, tmp_path.parent / "outside")


@pytest.mark.conformance
def test_m06_t04_injectable_harness_consumes_bound_plan_without_live_mutation(
    tmp_path: Path,
) -> None:
    integration = CodexIntegration(_successful_detection())
    report = IntegrationConformanceSuite().run(integration)
    assert report.status is HealthStatus.PASS
    assert {check.check_id for check in report.checks} >= {
        "stage-execution-packet",
        "artifact-result-submission",
        "failure-mapping",
        "cancellation-mapping",
        "stale-result-mapping",
    }
    root = tmp_path / "harness"
    repository = ProjectRepository.initialize(root, project_id="HARNESS", name="Harness")
    head = _commit_all(root, "harness baseline")
    packet = _packet(
        integration,
        base_commit=head,
        model_fingerprint=_model_fingerprint(repository),
    )
    plan = integration.prepare_stage(packet, root, require_clean=True)
    consumed: list[str] = []

    def runner(observed_plan: CodexWorkerPlan) -> dict[str, object]:
        assert observed_plan is plan
        consumed.append(plan.packet.contract_fingerprint)
        return {
            "status": "completed",
            "base_commit": packet.base_commit,
            "execution_contract_fingerprint": packet.contract_fingerprint,
            "project_model_fingerprint": packet.project_model_fingerprint,
            "artifacts": [{"path": "owned.txt", "state": "produced"}],
            "validation": {"tests": "PASS"},
        }

    result = integration.execute_stage(plan, runner)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.validation == {"tests": "PASS"}
    assert consumed == [packet.contract_fingerprint]
    assert _git(root, "status", "--porcelain=v1") == ""
    assert integration.submit_validation(result.validation)["canonical"] is False


@pytest.mark.integration
def test_m06_t05_worker_is_bound_to_exact_worktree_and_baseline(tmp_path: Path) -> None:
    root = tmp_path / "worker"
    repository = ProjectRepository.initialize(root, project_id="WORKER", name="Worker")
    (root / "AGENTS.md").write_text("worker scope\n", encoding="utf-8")
    (root / "owned.txt").write_text("baseline\n", encoding="utf-8")
    head = _commit_all(root, "baseline")
    integration = CodexIntegration(_successful_detection())
    model_fingerprint = _model_fingerprint(repository)
    packet = _packet(
        integration, base_commit=head, model_fingerprint=model_fingerprint
    )
    binding = integration.inspect_worktree(packet, root, require_clean=True)
    assert binding.bound is True
    assert binding.clean is True
    assert binding.observed_project_model_fingerprint == model_fingerprint
    plan = integration.prepare_stage(packet, root, require_clean=True)
    assert plan.worktree.head_commit == head
    assert plan.instruction_layers[0].path == "AGENTS.md"
    assert plan.to_dict()["execution_mode"] == "explicit-runner-required"

    stale = _packet(
        integration,
        base_commit="0" * 40,
        model_fingerprint=model_fingerprint,
    )
    with pytest.raises(IntegrationError, match="does not match"):
        integration.inspect_worktree(stale, root)
    forged_model = _packet(
        integration,
        base_commit=head,
        model_fingerprint="0" * 64,
    )
    with pytest.raises(IntegrationError, match="Project Model fingerprint"):
        integration.inspect_worktree(forged_model, root)

    model_path = root / ".artifex" / "project-model.json"
    changed_model = json.loads(model_path.read_text(encoding="utf-8"))
    changed_model["project"]["name"] = "Semantic drift"
    model_path.write_text(json.dumps(changed_model), encoding="utf-8")
    with pytest.raises(IntegrationError, match="Project Model fingerprint"):
        integration.prepare_stage(packet, root)


@pytest.mark.conformance
def test_m06_t06_application_cli_and_mcp_share_codex_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    integration = CodexIntegration(_successful_detection())
    application = create_codex_application(integration)
    operations = application.dispatch(OperationRequest("system.operations"))
    assert set(CODEX_OPERATION_NAMES) <= set(operations.value["operations"])
    direct = application.dispatch(OperationRequest("codex.detect")).to_dict()
    packet_result = application.dispatch(
        OperationRequest(
            "codex.packet.create",
            {
                "task_contract": {"id": "M06-T06"},
                "context": {"transport": "shared"},
                "base_commit": "a" * 40,
                "project_model_fingerprint": "b" * 64,
                "acceptance_criteria": ["CLI MCP parity"],
                "ownership": {"paths": ["owned.txt"]},
                "expected_result": {"status": ["SUCCESS"]},
            },
        )
    )
    assert packet_result.ok is True
    submitted = application.dispatch(
        OperationRequest(
            "codex.result.submit",
            {
                "packet": packet_result.value["packet"],
                "result": {
                    "status": "completed",
                    "base_commit": packet_result.value["packet"]["base_commit"],
                    "execution_contract_fingerprint": packet_result.value["packet"][
                        "execution_contract_fingerprint"
                    ],
                    "project_model_fingerprint": packet_result.value["packet"][
                        "project_model_fingerprint"
                    ],
                    "validation": {"parity": "PASS"},
                },
            },
        )
    )
    assert submitted.value["result"]["status"] == "SUCCESS"
    assert submitted.value["canonical_acceptance"] is False

    server = LocalMCPServer(application)
    mcp = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "codex.detect", "arguments": {}},
        }
    )
    assert mcp is not None
    assert mcp["result"]["structuredContent"] == direct

    monkeypatch.setattr("artifex.cli.Application", lambda: application)
    cli = CliRunner().invoke(cli_app, ["call", "codex.detect"])
    assert cli.exit_code == 0
    assert json.loads(cli.stdout) == direct


@pytest.mark.integration
def test_m06_t07_codex_only_greenfield_standard_preserves_state_evidence_and_docs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "greenfield"
    repository = ProjectRepository.initialize(
        root,
        project_id="CODEX-GREEN",
        name="Codex Greenfield",
        workflow_depth=WorkflowDepth.STANDARD,
    )
    head = _commit_all(root, "greenfield baseline")
    model = repository.load()
    assert model.project.lifecycle is ProjectLifecycle.GREENFIELD
    assert model.project.workflow_depth is WorkflowDepth.STANDARD
    integration = CodexIntegration(_successful_detection())
    packet = _packet(
        integration,
        base_commit=head,
        model_fingerprint=_model_fingerprint(repository),
        task_id="M06-T07",
    )
    result, ledger, workflow = _execute_and_accept(
        root,
        integration,
        packet,
        stage_id="STG-CODEX-GREEN",
        output="standard-implementation",
        evidence_id="EVD-CODEX-GREEN",
    )
    assert workflow.get("STG-CODEX-GREEN").state is StageState.ACCEPTED
    assert len(ledger.entries) == 1
    assert result.artifacts == ({"path": "standard-implementation", "state": "produced"},)

    documents = compile_human_documentation(repository.load().to_dict())
    for name, content in documents.items():
        (root / name).write_text(content, encoding="utf-8")
    after = integration.continuity_snapshot(root, packet=packet)
    assert result.status is ExecutionStatus.SUCCESS
    assert {"README.md", "USER_GUIDE.md", "ADMIN_GUIDE.md", "DEVELOPER_GUIDE.md"} <= {
        item["path"] for item in after.files
    }
    assert any(item["path"].endswith("ledger.jsonl") for item in after.files)
    assert ContinuitySnapshot.from_dict(after.to_dict()) == after


@pytest.mark.integration
def test_m06_t08_codex_only_brownfield_changeset_preserves_existing_content(
    tmp_path: Path,
) -> None:
    root = tmp_path / "brownfield"
    root.mkdir()
    readme = root / "README.md"
    readme.write_text("# Existing system\n", encoding="utf-8")
    repository = ProjectRepository.adopt(root, project_id="CODEX-BROWN", name="Brownfield")
    head = _commit_all(root, "brownfield baseline")
    model = repository.load()
    assert model.project.lifecycle is ProjectLifecycle.BROWNFIELD

    changesets = ChangeSetRepository(repository.store)
    changeset = ChangeSet(
        StableId.parse("CHG-CODEX-M06"),
        "Codex change",
        "Exercise a portable brownfield delta",
        (StableId.parse("ART-EXISTING"),),
        baseline_commit=head,
    )
    changeset = changeset.transition(ChangeSetStatus.ACCEPTED, actor="core", commit=head)
    change_path = changesets.save(changeset)
    head = _commit_all(root, "accept brownfield changeset")
    changeset = changeset.transition(
        ChangeSetStatus.IMPLEMENTING, actor="core", commit=head
    )
    changesets.save(changeset)

    integration = CodexIntegration(_successful_detection())
    packet = _packet(
        integration,
        base_commit=head,
        model_fingerprint=_model_fingerprint(repository),
        task_id="M06-T08",
    )
    assert changesets.load(changeset.id).status is ChangeSetStatus.IMPLEMENTING
    result, ledger, workflow = _execute_and_accept(
        root,
        integration,
        packet,
        stage_id="STG-CODEX-BROWN",
        output=change_path,
        evidence_id="EVD-CODEX-BROWN",
    )
    assert workflow.get("STG-CODEX-BROWN").state is StageState.ACCEPTED
    assert len(ledger.entries) == 1
    changeset = changeset.transition(ChangeSetStatus.VERIFIED, actor="core", commit=head)
    changeset = changeset.transition(ChangeSetStatus.APPLIED, actor="core", commit=head)
    changesets.save(changeset)
    snapshot = integration.continuity_snapshot(root, packet=packet)
    assert result.status is ExecutionStatus.SUCCESS
    assert changesets.load(changeset.id).status is ChangeSetStatus.APPLIED
    assert readme.read_text(encoding="utf-8") == "# Existing system\n"
    assert any(item["path"] == change_path for item in snapshot.files)


@pytest.mark.adversarial
def test_m06_t09_failure_cancel_and_stale_result_mapping_fail_closed() -> None:
    integration = CodexIntegration(_successful_detection())
    packet = _packet(integration)

    def raw(status: str, **overrides: str) -> dict[str, str]:
        value = {
            "status": status,
            "base_commit": packet.base_commit,
            "execution_contract_fingerprint": packet.contract_fingerprint,
            "project_model_fingerprint": packet.project_model_fingerprint,
        }
        value.update(overrides)
        return value

    assert integration.normalize_result(packet, raw("failed")).status is ExecutionStatus.FAIL
    assert (
        integration.normalize_result(packet, raw("blocked")).status
        is ExecutionStatus.BLOCKED
    )
    assert integration.cancel(packet).status is ExecutionStatus.CANCELLED

    stale = ExecutionBaseline(
        "c" * 40, packet.contract_fingerprint, packet.project_model_fingerprint
    )
    success = integration.normalize_result(packet, raw("success"))
    assert (
        integration.submit_result(packet, success, current_baseline=stale).status
        is ExecutionStatus.REBASE_REQUIRED
    )
    forged = integration.normalize_result(
        packet,
        raw("success", base_commit="d" * 40),
    )
    assert forged.status is ExecutionStatus.REBASE_REQUIRED
    for missing in (
        "base_commit",
        "execution_contract_fingerprint",
        "project_model_fingerprint",
    ):
        incomplete = raw("success")
        incomplete.pop(missing)
        with pytest.raises(IntegrationError, match=missing):
            integration.normalize_result(packet, incomplete)
    with pytest.raises(IntegrationError, match="unsupported"):
        integration.normalize_result(packet, raw("mysterious"))


@pytest.mark.conformance
def test_m06_t10_continuity_snapshot_is_portable_round_trippable_and_memory_free(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".artifex"
    state.mkdir()
    (state / "status.yaml").write_text(
        "schema_version: '1.0'\nproject: {id: CONTINUITY}\nbase_commit: abc123\n",
        encoding="utf-8",
    )
    native = state / "native-memory"
    native.mkdir()
    (native / "codex.json").write_text('{"remembered":true}\n', encoding="utf-8")
    integration = CodexIntegration(_successful_detection())
    snapshot = integration.continuity_snapshot(tmp_path)
    portable = ContinuitySnapshot.from_dict(snapshot.to_dict())
    assert portable.semantic_fingerprint == snapshot.semantic_fingerprint
    assert portable.to_dict()["native_memory_required"] is False
    assert not any("native-memory" in item["path"] for item in portable.files)

    moved = ContinuitySnapshot(
        project_root="/different/machine/path",
        source=portable.source,
        state=portable.state,
        files=portable.files,
        base_commit=portable.base_commit,
        execution_contract_fingerprint=portable.execution_contract_fingerprint,
        project_model_fingerprint=portable.project_model_fingerprint,
    )
    assert moved.semantic_fingerprint == portable.semantic_fingerprint

    application = create_codex_application(integration)
    bridged = application.dispatch(
        OperationRequest(
            "codex.continuity.snapshot",
            {"project_root": str(tmp_path)},
        )
    )
    assert bridged.value["snapshot"]["semantic_fingerprint"] == snapshot.semantic_fingerprint

    tampered = snapshot.to_dict()
    tampered["state"] = {"project": {"id": "TAMPERED"}}
    with pytest.raises(IntegrationError, match="fingerprint"):
        ContinuitySnapshot.from_dict(tampered)
