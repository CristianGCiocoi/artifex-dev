from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from artifex.ids import StableId
from artifex.integrations.claude import (
    ClaudeDetection,
    ClaudeIntegration,
    ContinuitySnapshot,
    detect_claude,
)
from artifex.integrations.conformance import ConformanceSuite
from artifex.integrations.contracts import Capability, ExecutionPacket, HealthStatus
from artifex.project.changeset import ChangeSet, ChangeSetStatus
from artifex.project.model import ProjectLifecycle, WorkflowDepth
from artifex.workflow import ExecutionBaseline, ExecutionStatus


def _available() -> ClaudeIntegration:
    return ClaudeIntegration(ClaudeDetection(True, "claude", "2.1.3", "2.1.3"))


def _packet(adapter: ClaudeIntegration, base_commit: str = "a" * 40) -> ExecutionPacket:
    return adapter.prepare_execution(
        task_contract={"id": "M07-T04", "stage": "implementation"},
        context={"requirements": ["REQ-F-044"]},
        base_commit=base_commit,
        project_model_fingerprint="b" * 64,
        acceptance_criteria=("standalone pass",),
        ownership={"paths": ["owned.txt"]},
        expected_result={"status": [status.value for status in ExecutionStatus]},
        interfaces=("Application API",),
        invariants=("INV-013", "INV-024"),
    )


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


@pytest.mark.unit
def test_detection_absence_and_version_failures_are_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("artifex.integrations.claude.shutil.which", lambda _: None)
    absent = detect_claude()
    assert absent.installed is False
    assert absent.version is None
    assert absent.to_dict()["supports_mcp"] is False
    assert ClaudeIntegration(absent).health().status is HealthStatus.DEGRADED

    monkeypatch.setattr("artifex.integrations.claude.shutil.which", lambda _: "claude")

    def timeout(*_: object, **__: object) -> object:
        raise subprocess.TimeoutExpired("claude", 1)

    monkeypatch.setattr("artifex.integrations.claude.subprocess.run", timeout)
    failed = detect_claude(timeout=0.1)
    assert failed.installed is False
    assert "failed" in failed.detail

    nonzero = subprocess.CompletedProcess(["claude"], 2, "", "bad version call")
    monkeypatch.setattr("artifex.integrations.claude.subprocess.run", lambda *a, **k: nonzero)
    assert detect_claude().detail == "bad version call"

    unknown = subprocess.CompletedProcess(["claude"], 0, "Claude development build", "")
    monkeypatch.setattr("artifex.integrations.claude.subprocess.run", lambda *a, **k: unknown)
    unknown_detection = detect_claude()
    assert unknown_detection.installed is True
    assert unknown_detection.version is None
    unknown_adapter = ClaudeIntegration(unknown_detection)
    assert unknown_adapter.health().checks["claude_executable"] is HealthStatus.UNKNOWN
    assert Capability.MCP.value not in unknown_adapter.metadata.capabilities


@pytest.mark.unit
def test_detection_metadata_health_and_optional_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = subprocess.CompletedProcess(["claude"], 0, "Claude Code 2.1.3\n", "")
    monkeypatch.setattr("artifex.integrations.claude.shutil.which", lambda _: "claude")
    monkeypatch.setattr("artifex.integrations.claude.subprocess.run", lambda *a, **k: completed)
    detection = detect_claude()
    adapter = ClaudeIntegration(detection)

    assert detection.version == "2.1.3"
    assert detection.to_dict()["supports_mcp"] is True
    assert adapter.health().status is HealthStatus.PASS
    assert Capability.MCP.value in adapter.metadata.capabilities
    assert adapter.mcp_entry(python_command="python3") == {
        "mcpServers": {
            "artifex": {
                "command": "python3",
                "args": ["-m", "artifex.mcp"],
                "transport": "stdio",
            }
        }
    }
    assert ClaudeIntegration(ClaudeDetection(False)).mcp_entry() is None


@pytest.mark.conformance
def test_claude_contract_conformance_and_normalized_results() -> None:
    adapter = _available()
    assert ConformanceSuite().run(adapter).status is HealthStatus.PASS
    packet = _packet(adapter)

    completed = adapter.normalize_result(packet, {"status": "completed"})
    assert completed.status is ExecutionStatus.SUCCESS
    assert adapter.normalize_result(packet, "blocked").status is ExecutionStatus.BLOCKED
    assert adapter.normalize_result(packet, "interrupted").status is ExecutionStatus.CANCELLED
    unknown = adapter.normalize_result(packet, {"status": "vendor-surprise"})
    assert unknown.status is ExecutionStatus.FAIL
    assert "unrecognized" in unknown.message
    malformed = adapter.normalize_result(packet, None)
    assert malformed.status is ExecutionStatus.FAIL
    assert malformed.message
    wrapped = adapter.normalize_result(
        packet,
        {"type": "result", "result": '{"status":"passed","artifacts":[]}'},
    )
    assert wrapped.status is ExecutionStatus.SUCCESS
    native_failure = adapter.normalize_result(packet, {"is_error": True})
    assert native_failure.status is ExecutionStatus.FAIL
    invalid_artifacts = adapter.normalize_result(
        packet, {"status": "success", "artifacts": "not-an-array"}
    )
    assert invalid_artifacts.status is ExecutionStatus.FAIL
    invalid_item = adapter.normalize_result(
        packet, {"status": "success", "artifacts": ["not-an-object"]}
    )
    assert invalid_item.status is ExecutionStatus.FAIL
    invalid_validation = adapter.normalize_result(
        packet, {"status": "success", "validation": []}
    )
    assert invalid_validation.status is ExecutionStatus.FAIL
    nested = adapter.normalize_result(packet, {"result": {"status": "complete"}})
    assert nested.status is ExecutionStatus.SUCCESS
    unstructured = adapter.normalize_result(packet, {"result": "ordinary prose"})
    assert unstructured.status is ExecutionStatus.FAIL

    success = adapter.normalize_result(packet, "success")
    stale = ExecutionBaseline("c" * 40, packet.contract_fingerprint, "b" * 64)
    classified = adapter.submit_result(packet, success, current_baseline=stale)
    assert classified.status is ExecutionStatus.REBASE_REQUIRED
    assert adapter.cancel(packet).status is ExecutionStatus.CANCELLED
    assert adapter.submit_validation({"outcome": "PASS"})["canonical"] is False


@pytest.mark.integration
def test_greenfield_standard_and_worktree_binding_without_live_execution(tmp_path: Path) -> None:
    adapter = _available()
    root = tmp_path / "green"
    repository = adapter.initialize_greenfield(root, project_id="green", name="Green")
    model = repository.load()
    assert model.project.lifecycle is ProjectLifecycle.GREENFIELD
    assert model.project.workflow_depth is WorkflowDepth.STANDARD

    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "ARTIFEX Test")
    _git(root, "add", ".artifex")
    _git(root, "commit", "-m", "baseline")
    head = _git(root, "rev-parse", "HEAD")
    packet = _packet(adapter, head)
    before = _git(root, "status", "--porcelain=v1")
    plan = adapter.plan_stage_execution(packet, project_root=root)
    after = _git(root, "status", "--porcelain=v1")

    assert plan.worktree_root == str(root.resolve())
    assert plan.command[-1] == "json"
    assert head in plan.prompt
    assert before == after == ""
    assert plan.to_dict()["mutating"] is False

    stale = _packet(adapter, "f" * 40)
    with pytest.raises(ValueError, match="does not match packet base"):
        adapter.plan_stage_execution(stale, project_root=root)

    with pytest.raises(RuntimeError, match="unavailable"):
        ClaudeIntegration(ClaudeDetection(False)).plan_stage_execution(
            packet, project_root=root
        )
    with pytest.raises(ValueError, match="metadata not found"):
        adapter.plan_stage_execution(packet, project_root=tmp_path / "missing")

    linked = tmp_path / "linked"
    _git(root, "worktree", "add", "--detach", str(linked), head)
    linked_plan = adapter.plan_stage_execution(
        packet, project_root=root, worktree_root=linked
    )
    assert linked_plan.worktree_root == str(linked.resolve())

    unrelated = tmp_path / "unrelated"
    subprocess.run(
        ["git", "clone", "--quiet", str(root), str(unrelated)],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ValueError, match="not attached"):
        adapter.plan_stage_execution(packet, project_root=root, worktree_root=unrelated)


@pytest.mark.integration
def test_brownfield_changeset_and_portable_continuity_snapshot(tmp_path: Path) -> None:
    adapter = _available()
    root = tmp_path / "brown"
    root.mkdir()
    source = root / "existing.txt"
    source.write_text("preserve me", encoding="utf-8")
    repository = adapter.adopt_brownfield(root, project_id="brown", name="Brown")
    model = repository.load()
    assert model.project.lifecycle is ProjectLifecycle.BROWNFIELD
    assert model.project.workflow_depth is WorkflowDepth.STANDARD
    assert source.read_text(encoding="utf-8") == "preserve me"

    changeset = ChangeSet(
        StableId.parse("CHG-M07-LOGIN"),
        "Adjust login",
        "Bounded existing-system change.",
        (),
        ChangeSetStatus.PROPOSED,
    )
    path = adapter.save_changeset(repository, changeset)
    assert path == ".artifex/changesets/CHG-M07-LOGIN.json"

    packet = _packet(adapter)
    snapshot = adapter.continuity_snapshot(root, packet=packet)
    restored = ContinuitySnapshot.from_dict(snapshot.to_dict())
    assert restored == snapshot
    assert not any(str(root) in json.dumps(item) for item in snapshot.semantic_state)
    assert {item["path"] for item in snapshot.semantic_state} >= {
        ".artifex/project-model.json",
        ".artifex/changesets/CHG-M07-LOGIN.json",
    }

    tampered = snapshot.to_dict()
    tampered["semantic_state"][0]["value"] = "tampered"
    with pytest.raises(ValueError, match="fingerprint"):
        ContinuitySnapshot.from_dict(tampered)

    unsupported = snapshot.to_dict()
    unsupported["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="unsupported"):
        ContinuitySnapshot.from_dict(unsupported)
    with pytest.raises(ValueError, match="must be an array"):
        ContinuitySnapshot.from_dict({"semantic_state": "wrong"})
    invalid_entry = snapshot.to_dict()
    invalid_entry["semantic_state"] = ["wrong"]
    with pytest.raises(ValueError, match="entries must be objects"):
        ContinuitySnapshot.from_dict(invalid_entry)
    invalid_packet = snapshot.to_dict()
    invalid_packet["execution_packet"] = "wrong"
    with pytest.raises(ValueError, match="execution_packet must be"):
        ContinuitySnapshot.from_dict(invalid_packet)

    with pytest.raises(FileNotFoundError, match="metadata not found"):
        adapter.continuity_snapshot(tmp_path / "missing")
    empty = tmp_path / "empty"
    (empty / ".artifex").mkdir(parents=True)
    with pytest.raises(ValueError, match="no portable semantic state"):
        adapter.continuity_snapshot(empty)
    malformed_root = tmp_path / "malformed"
    (malformed_root / ".artifex").mkdir(parents=True)
    (malformed_root / ".artifex" / "bad.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot snapshot"):
        adapter.continuity_snapshot(malformed_root)


@pytest.mark.conformance
def test_claude_interface_pack_has_shim_rules_skill_and_optional_mcp_entry() -> None:
    pack = Path(__file__).parents[1] / "interface_packs" / "claude"
    shim = (pack / "CLAUDE.md").read_text(encoding="utf-8")
    rules = (pack / ".claude" / "rules" / "artifex.md").read_text(encoding="utf-8")
    skill = (pack / ".claude" / "skills" / "artifex" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    mcp = json.loads((pack / "mcp.json.example").read_text(encoding="utf-8"))

    assert "@.artifex/project-model.json" in shim
    assert "canonical" in shim.lower()
    assert "REBASE_REQUIRED" in rules
    assert "worktree HEAD" in skill
    assert mcp["mcpServers"]["artifex"]["transport"] == "stdio"
