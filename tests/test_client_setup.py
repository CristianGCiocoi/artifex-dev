from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.client_setup import (
    ClientConfigurationError,
    ClientSetupPlan,
    apply_client_enable,
    apply_client_rollback,
    plan_client_enable,
    plan_client_rollback,
    verify_client_integration,
)


def _runner(arguments: object) -> subprocess.CompletedProcess[str]:
    command = tuple(str(item) for item in arguments)  # type: ignore[arg-type]
    if command[-1] == "--version":
        return subprocess.CompletedProcess(command, 0, "client 1.2.3\n", "")
    return subprocess.CompletedProcess(command, 0, '{"status":"PASS"}\n', "")


@pytest.mark.integration
def test_codex_enable_is_approved_idempotent_secret_free_and_reversible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_root = tmp_path / "codex"
    config_root.mkdir()
    original = 'model = "example"\n# token-like user data must remain: private-value\n'
    (config_root / "config.toml").write_text(original, encoding="utf-8")
    bridge = tmp_path / "ARTIFEX" / "artifex.exe"
    bridge.parent.mkdir()
    bridge.write_bytes(b"fixture")
    approvals = ApprovalStore(tmp_path / "approvals")
    monkeypatch.setattr("artifex.distribution.client_setup.shutil.which", lambda _: "codex")

    plan = plan_client_enable(
        "codex",
        project,
        bridge_command=(str(bridge),),
        config_root=config_root,
        approval_store=approvals,
    )
    assert plan.decision.approval_required
    restored = ClientSetupPlan.from_dict(plan.to_dict())
    receipt = apply_client_enable(
        restored,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=approvals,
        runner=_runner,
    )
    config = (config_root / "config.toml").read_text(encoding="utf-8")
    assert "[mcp_servers.artifex]" in config
    assert (project / ".agents/skills/artifex-router/SKILL.md").is_file()
    assert receipt["verification"]["status"] == "READY"
    assert receipt["client_version"] == "client 1.2.3"
    receipt_text = Path(str(receipt["receipt_path"])).read_text(encoding="utf-8")
    assert "private-value" not in receipt_text
    assert json.loads(receipt_text)["secret_material_present"] is False

    second = plan_client_enable(
        "codex",
        project,
        bridge_command=(str(bridge),),
        config_root=config_root,
        approval_store=approvals,
    )
    assert all(item.action == "UNCHANGED" for item in second.mutations)

    rollback = plan_client_rollback(
        str(receipt["receipt_path"]), approval_store=approvals
    )
    outcome = apply_client_rollback(
        rollback,
        confirmation_token=rollback["decision"]["confirmation_token"],
        approval_store=approvals,
    )
    assert outcome["status"] == "PASS"
    assert (config_root / "config.toml").read_text(encoding="utf-8") == original
    assert not (project / "AGENTS.md").exists()
    assert not (project / ".agents/skills/artifex-router/SKILL.md").exists()


@pytest.mark.integration
def test_claude_public_mcp_config_preserves_unrelated_bytes_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    original = b'{\n  "mcpServers": {\n    "other": {"command": "safe"}\n  },\n  "flag": true\n}\n'
    (project / ".mcp.json").write_bytes(original)
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    approvals = ApprovalStore(tmp_path / "approvals")
    monkeypatch.setattr("artifex.distribution.client_setup.shutil.which", lambda _: "claude")

    plan = plan_client_enable(
        "claude", project, bridge_command=(str(bridge),), approval_store=approvals
    )
    receipt = apply_client_enable(
        plan,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=approvals,
        runner=_runner,
    )
    configured = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    assert configured["mcpServers"]["other"] == {"command": "safe"}
    assert configured["mcpServers"]["artifex"] == {
        "type": "stdio",
        "command": str(bridge),
        "args": ["mcp", "serve"],
    }
    assert "python" not in json.dumps(configured["mcpServers"]["artifex"])

    rollback = plan_client_rollback(
        str(receipt["receipt_path"]), approval_store=approvals
    )
    apply_client_rollback(
        rollback,
        confirmation_token=rollback["decision"]["confirmation_token"],
        approval_store=approvals,
    )
    assert (project / ".mcp.json").read_bytes() == original


@pytest.mark.adversarial
def test_client_setup_refuses_unmanaged_collision(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config = tmp_path / "codex"
    config.mkdir()
    (config / "config.toml").write_text(
        '[mcp_servers.artifex]\ncommand = "unknown"\n', encoding="utf-8"
    )
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    with pytest.raises(ClientConfigurationError, match="unmanaged"):
        plan_client_enable(
            "codex", project, bridge_command=(str(bridge),), config_root=config
        )


@pytest.mark.unit
def test_client_doctor_reports_friendly_non_model_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    monkeypatch.setattr("artifex.distribution.client_setup.shutil.which", lambda _: None)
    report = verify_client_integration(
        "claude", project, bridge_command=(str(bridge),), run_processes=True, runner=_runner
    )
    assert report["status"] == "NEEDS_ATTENTION"
    assert report["live_model_invocation"] is False
    assert "PowerShell ExecutionPolicy" in report["diagnostics"][0]
