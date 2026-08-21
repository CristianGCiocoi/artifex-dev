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
