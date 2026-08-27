from __future__ import annotations

import json
from pathlib import Path

import yaml

from artifex.mcp import LocalMCPServer, main


def test_codex_interface_pack_uses_packaged_mcp_and_role_specific_claims() -> None:
    root = Path(__file__).parents[2]
    mcp = json.loads((root / "interface_packs/codex/mcp.json").read_text(encoding="utf-8"))
    pack = yaml.safe_load((root / "interface_packs/codex/pack.yaml").read_text(encoding="utf-8"))

    assert mcp["mcpServers"]["artifex"] == {
        "command": "artifex-mcp",
        "args": [],
        "transport": "stdio",
    }
    assert pack["roles"] == ["INTERACTION", "EXECUTION_IMPLEMENTER"]
    assert "HARNESS" not in pack["roles"]


def test_packaged_mcp_entrypoint_uses_default_public_application() -> None:
    assert callable(main)
    server = LocalMCPServer()
    response = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    assert response is not None
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert "system.health" in names
