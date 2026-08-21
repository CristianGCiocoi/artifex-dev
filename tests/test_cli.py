from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from artifex.cli import app


@pytest.mark.unit
@pytest.mark.parametrize("command", ["health", "version"])
def test_system_commands_use_application_api(command: str) -> None:
    result = CliRunner().invoke(app, ["system", command])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["ok"] is True


@pytest.mark.unit
@pytest.mark.parametrize(
    "arguments",
    [
        ["doctor"],
        ["integration", "list"],
        ["integration", "conformance", "manual"],
        ["call", "system.health", "--arguments", "{}"],
    ],
)
def test_semantic_cli_commands_return_normalized_application_results(
    arguments: list[str],
) -> None:
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
