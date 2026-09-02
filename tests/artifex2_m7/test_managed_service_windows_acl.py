from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import artifex.managed_service as managed_service
from artifex.managed_service import ManagedServiceError, ServicePaths


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL contract")
def test_acl_enforcement_uses_fixed_argument_vectors_without_a_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        managed_service,
        "_windows_current_user_sid",
        lambda: "S-1-5-21-100-200-300-400",
    )
    monkeypatch.setattr(
        managed_service,
        "_run_windows_command",
        lambda arguments: calls.append(tuple(arguments)) or "",
    )
    verified: list[tuple[Path, str, bool]] = []
    monkeypatch.setattr(
        managed_service,
        "_verify_windows_private_acl",
        lambda path, *, current_sid, directory: verified.append(
            (path, current_sid, directory)
        ),
    )

    target = tmp_path / "state"
    managed_service._enforce_windows_private_acl(target, directory=True)

    assert calls == [
        (
            "icacls.exe",
            str(target),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-21-100-200-300-400:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
        ),
        (
            "icacls.exe",
            str(target),
            "/remove:g",
            "*S-1-5-32-544",
            "*S-1-5-32-545",
            "*S-1-5-11",
            "*S-1-3-0",
            "*S-1-3-4",
        ),
        ("icacls.exe", str(target), "/verify"),
    ]
    assert verified == [(target, "S-1-5-21-100-200-300-400", True)]


def test_windows_utility_runner_disables_shell_and_captures_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def run(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["arguments"] = arguments
        observed.update(kwargs)
        return subprocess.CompletedProcess(arguments, 0, stdout="verified", stderr="")

    monkeypatch.setattr(managed_service.subprocess, "run", run)
    output = managed_service._run_windows_command(("icacls.exe", "C:\\state", "/verify"))

    assert output == "verified"
    assert observed["arguments"] == ["icacls.exe", "C:\\state", "/verify"]
    assert observed["shell"] is False
    assert observed["capture_output"] is True
    assert observed["stdin"] is subprocess.DEVNULL
    assert observed["timeout"] == 15


def test_windows_utility_failure_does_not_expose_captured_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "transport-token-must-not-escape"

    def run(arguments: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 5, stdout=marker, stderr=marker)

    monkeypatch.setattr(managed_service.subprocess, "run", run)
    with pytest.raises(ManagedServiceError) as failure:
        managed_service._run_windows_command(("icacls.exe", "C:\\state", "/verify"))

    assert marker not in str(failure.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows token ACL contract")
def test_token_is_removed_when_windows_acl_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "private-transport-token"

    def reject(_path: Path, *, directory: bool) -> None:
        assert directory is False
        raise ManagedServiceError("ACL verification failed")

    monkeypatch.setattr(managed_service, "_enforce_windows_private_acl", reject)
    target = tmp_path / ".local-transport-token"
    with pytest.raises(ManagedServiceError) as failure:
        managed_service._write_private_text(target, token, enforce_windows_acl=True)

    assert not target.exists()
    assert token not in str(failure.value)


def test_sddl_verification_rejects_inheritance_and_unexpected_principals() -> None:
    current_sid = "S-1-5-21-100-200-300-400"
    valid = (
        "state\r\n"
        f"D:P(A;OICI;FA;;;{current_sid})(A;OICI;FA;;;SY)\r\n"
    )
    managed_service._validate_windows_private_sddl(
        valid, current_sid=current_sid, directory=True
    )

    inherited = valid.replace("D:P", "D:AI")
    with pytest.raises(ManagedServiceError, match="inheritance"):
        managed_service._validate_windows_private_sddl(
            inherited, current_sid=current_sid, directory=True
        )

    unexpected = valid.rstrip("\r\n") + "(A;OICI;FR;;;WD)\r\n"
    with pytest.raises(ManagedServiceError, match="unexpected principal"):
        managed_service._validate_windows_private_sddl(
            unexpected, current_sid=current_sid, directory=True
        )


def test_sddl_verification_accepts_local_administrator_alias_only_for_rid_500() -> None:
    local_administrator_sid = "S-1-5-21-100-200-300-500"
    aliased = "state\r\nD:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)\r\n"

    managed_service._validate_windows_private_sddl(
        aliased, current_sid=local_administrator_sid, directory=True
    )

    with pytest.raises(ManagedServiceError, match="unexpected principal"):
        managed_service._validate_windows_private_sddl(
            aliased,
            current_sid="S-1-5-21-100-200-300-400",
            directory=True,
        )


def test_workspace_sddl_verification_requires_enabled_inheritance_and_inherited_ace() -> None:
    managed_service._validate_windows_inherited_sddl(
        "workspace\r\nD:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)\r\n"
    )

    with pytest.raises(ManagedServiceError, match="remains disabled"):
        managed_service._validate_windows_inherited_sddl(
            "workspace\r\nD:PAI(A;OICIIOID;GA;;;CO)\r\n"
        )

    with pytest.raises(ManagedServiceError, match="no inherited principal"):
        managed_service._validate_windows_inherited_sddl(
            "workspace\r\nD:AI(A;OICI;FA;;;SY)\r\n"
        )


def test_workspace_acl_enforcement_fast_paths_an_inherited_dacl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def run(arguments: tuple[str, ...]) -> str:
        calls.append(arguments)
        return f"{tmp_path} BUILTIN\\Users:(I)(OI)(CI)(RX)"

    monkeypatch.setattr(managed_service, "_run_windows_command", run)

    managed_service._enforce_windows_inherited_acl(tmp_path)

    assert calls == [("icacls.exe", str(tmp_path))]


@pytest.mark.skipif(os.name != "nt", reason="requires native icacls")
def test_native_windows_state_root_and_token_acl_round_trip(tmp_path: Path) -> None:
    paths = ServicePaths.resolve(tmp_path / "state")
    paths.prepare()
    managed_service._write_private_text(
        paths.transport_token,
        "native-private-token",
        enforce_windows_acl=True,
    )

    assert paths.state_root.is_dir()
    assert paths.workspace_root.is_dir()
    assert paths.workspace_root == paths.state_root.with_name("state-workspaces")
    assert paths.state_root not in paths.workspace_root.parents
    assert paths.transport_token.read_text(encoding="utf-8") == "native-private-token"
    managed_service._verify_windows_private_acl(
        paths.state_root,
        current_sid=managed_service._windows_current_user_sid(),
        directory=True,
    )
    managed_service._verify_windows_private_acl(
        paths.transport_token,
        current_sid=managed_service._windows_current_user_sid(),
        directory=False,
    )
