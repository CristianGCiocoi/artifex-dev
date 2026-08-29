from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from artifex.cli import app
from artifex.distribution import windows_installer


class _Result:
    def __init__(self, operation: str) -> None:
        self.operation = operation

    def to_dict(self) -> dict[str, str]:
        return {"operation": self.operation, "status": "COMPLETE"}


@pytest.mark.unit
def test_installer_bridge_uses_install_then_upgrade_without_weakening_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        windows_installer,
        "install_plan",
        lambda *args, **kwargs: SimpleNamespace(confirmation_token="install-token"),
    )
    monkeypatch.setattr(
        windows_installer,
        "install",
        lambda *args, **kwargs: (
            calls.append(("install", kwargs["confirmation_token"])) or _Result("install")
        ),
    )
    monkeypatch.setattr(
        windows_installer,
        "upgrade_plan",
        lambda *args, **kwargs: SimpleNamespace(confirmation_token="upgrade-token"),
    )
    monkeypatch.setattr(
        windows_installer,
        "upgrade",
        lambda *args, **kwargs: (
            calls.append(("upgrade", kwargs["confirmation_token"])) or _Result("upgrade")
        ),
    )
    source = tmp_path / "candidate" / "artifex.exe"
    source.parent.mkdir()
    source.write_bytes(b"candidate")
    root = tmp_path / "installed"
    state = tmp_path / "state"

    assert windows_installer.apply_installer(source, root, state)["operation"] == "install"
    root.mkdir()
    (root / windows_installer.MANIFEST_NAME).write_text("{}", encoding="utf-8")
    assert windows_installer.apply_installer(source, root, state)["operation"] == "upgrade"
    assert calls == [("install", "install-token"), ("upgrade", "upgrade-token")]


@pytest.mark.unit
def test_installer_bridge_uninstall_consumes_fresh_bound_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        windows_installer,
        "uninstall_plan",
        lambda *args, **kwargs: SimpleNamespace(confirmation_token="remove-token"),
    )
    monkeypatch.setattr(
        windows_installer,
        "uninstall",
        lambda *args, **kwargs: {
            "operation": "uninstall",
            "confirmation_token": kwargs["confirmation_token"],
        },
    )
    value = windows_installer.remove_installer(tmp_path / "installed")
    assert value == {"operation": "uninstall", "confirmation_token": "remove-token"}


@pytest.mark.adversarial
def test_hidden_installer_command_requires_explicit_enclosing_consent() -> None:
    result = CliRunner().invoke(
        app,
        ["_installer-lifecycle", "uninstall", "--install-root", "C:/ARTIFEX"],
    )
    assert result.exit_code != 0
    assert "explicit enclosing installer consent is required" in result.output
