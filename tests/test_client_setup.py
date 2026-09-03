from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import artifex.distribution.client_setup as client_setup
from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.client_setup import (
    ClientConfigurationError,
    ClientSetupPlan,
    _interface_pack,
    _run_process,
    apply_client_enable,
    apply_client_rollback,
    discover_bridge_command,
    plan_client_enable,
    plan_client_rollback,
    verify_client_integration,
)


@pytest.mark.unit
def test_interface_pack_resolves_nuitka_standalone_sibling_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    compiled_module = bundle / "artifex" / "distribution" / "client_setup.py"
    executable = bundle / "artifex.exe"
    interface_pack = bundle / "interface_packs" / "codex"
    interface_pack.mkdir(parents=True)
    executable.write_bytes(b"native-artifact")
    monkeypatch.setattr(client_setup, "__file__", str(compiled_module))
    monkeypatch.setattr(client_setup.sys, "executable", str(executable))

    assert _interface_pack("codex") == interface_pack


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


@pytest.mark.adversarial
def test_client_plan_schema_and_bridge_discovery_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    plan = plan_client_enable(
        "codex", project, bridge_command=(str(bridge),), config_root=tmp_path / "codex"
    ).to_dict()
    invalid = []
    for key, value in (
        ("mutations", "invalid"),
        ("bridge_command", "invalid"),
        ("decision", "invalid"),
        ("mutations", [1]),
    ):
        candidate = dict(plan)
        candidate[key] = value
        invalid.append(candidate)
    wrong_risk = dict(plan)
    wrong_risk["decision"] = {**plan["decision"], "risk": "DESTRUCTIVE"}
    invalid.append(wrong_risk)
    for candidate in invalid:
        with pytest.raises(ClientConfigurationError):
            ClientSetupPlan.from_dict(candidate)

    monkeypatch.setattr("artifex.distribution.client_setup.shutil.which", lambda _: None)
    with pytest.raises(ClientConfigurationError, match="launcher was not found"):
        discover_bridge_command()
    with pytest.raises(ClientConfigurationError, match="does not exist"):
        discover_bridge_command(tmp_path / "missing.exe")
    with pytest.raises(ClientConfigurationError, match="project root"):
        plan_client_enable("codex", tmp_path / "missing", bridge_command=(str(bridge),))
    with pytest.raises(ClientConfigurationError, match="absolute"):
        plan_client_enable("codex", project, bridge_command=("artifex.exe",))
    with pytest.raises(ClientConfigurationError, match="codex or claude"):
        plan_client_enable("hermes", project, bridge_command=(str(bridge),))


@pytest.mark.adversarial
def test_claude_configuration_collisions_are_friendly(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    config = project / ".mcp.json"
    cases = (
        ("{invalid", "invalid"),
        ("[]", "must contain an object"),
        ('{"mcpServers": []}', "mcpServers must be an object"),
        (
            '{"mcpServers":{"artifex":{"command":"unmanaged"}}}',
            "unmanaged artifex MCP entry",
        ),
    )
    for content, message in cases:
        config.write_text(content, encoding="utf-8")
        with pytest.raises(ClientConfigurationError, match=message):
            plan_client_enable("claude", project, bridge_command=(str(bridge),))


@pytest.mark.unit
def test_client_verifier_and_process_errors_report_actual_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    bridge = tmp_path / "artifex.exe"
    bridge.write_bytes(b"fixture")
    monkeypatch.setattr(
        "artifex.distribution.client_setup.shutil.which", lambda _: "claude"
    )

    def failing_runner(arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(tuple(arguments), 7, "", "not registered")  # type: ignore[arg-type]

    report = verify_client_integration(
        "claude", project, bridge_command=(str(bridge),), runner=failing_runner
    )
    assert report["status"] == "NEEDS_ATTENTION"
    assert report["bridge_status"] == "FAIL"
    assert report["client_registration"] == "FAIL"
    assert len(report["diagnostics"]) == 2

    monkeypatch.setattr(
        "artifex.distribution.client_setup.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    failed = _run_process((str(bridge), "mcp", "test"))
    assert failed.returncode == 127
    assert "OSError" in failed.stderr
