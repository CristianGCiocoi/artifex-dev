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
    probes: list[object] = []

    def plan(token: str):
        def capture(*args: object, **kwargs: object) -> SimpleNamespace:
            probes.append(kwargs["identity_probe"])
            return SimpleNamespace(confirmation_token=token)

        return capture

    monkeypatch.setattr(
        windows_installer,
        "install_plan",
        plan("install-token"),
    )
    monkeypatch.setattr(
        windows_installer,
        "install",
        lambda *args, **kwargs: (
            probes.append(kwargs["identity_probe"])
            or calls.append(("install", kwargs["confirmation_token"]))
            or _Result("install")
        ),
    )
    monkeypatch.setattr(
        windows_installer,
        "upgrade_plan",
        plan("upgrade-token"),
    )
    monkeypatch.setattr(
        windows_installer,
        "upgrade",
        lambda *args, **kwargs: (
            probes.append(kwargs["identity_probe"])
            or calls.append(("upgrade", kwargs["confirmation_token"]))
            or _Result("upgrade")
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
    assert probes == [windows_installer._running_artifact_identity] * 4


@pytest.mark.adversarial
def test_installer_in_process_identity_is_frozen_and_path_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (tmp_path / "candidate" / "artifex.exe").resolve()
    source.parent.mkdir()
    source.write_bytes(b"candidate")
    identity = {
        "product": "ARTIFEX",
        "version": "1.0.0",
        "format": "nuitka-standalone",
        "artifact": "artifex.exe",
        "sha256": "a" * 64,
    }
    monkeypatch.setattr(windows_installer.sys, "argv", [str(source)])
    monkeypatch.setattr(
        windows_installer, "runtime_release_identity", lambda: identity
    )

    assert windows_installer._running_artifact_identity(source, 60) == identity
    with pytest.raises(ValueError, match="not the running artifact"):
        windows_installer._running_artifact_identity(tmp_path / "other.exe", 60)

    monkeypatch.setattr(
        windows_installer,
        "runtime_release_identity",
        lambda: {**identity, "format": "python-source", "sha256": None},
    )
    with pytest.raises(ValueError, match="frozen runtime identity"):
        windows_installer._running_artifact_identity(source, 60)


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
