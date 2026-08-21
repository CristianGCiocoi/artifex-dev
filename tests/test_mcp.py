from __future__ import annotations

import io
import json

import pytest

from artifex.application import Application, OperationRequest
from artifex.mcp import LocalMCPServer, serve_stdio


@pytest.mark.unit
def test_mcp_initialization_and_tool_discovery() -> None:
    server = LocalMCPServer()
    initialized = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert initialized is not None
    assert initialized["result"]["capabilities"]["tools"] == {"listChanged": False}
    listed = server.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    assert listed is not None
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert {"system.health", "manual.packet.create", "research.bundle.validate"} <= names


@pytest.mark.unit
def test_mcp_and_direct_api_return_the_same_semantic_result() -> None:
    application = Application()
    expected = application.dispatch(OperationRequest("system.health")).to_dict()
    server = LocalMCPServer(application)

    direct = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": "direct",
            "method": "operations/call",
            "params": {"operation": "system.health", "arguments": {}},
        }
    )
    tool = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": "tool",
            "method": "tools/call",
            "params": {"name": "system.health", "arguments": {}},
        }
    )
    assert direct is not None and direct["result"] == expected
    assert tool is not None and tool["result"]["structuredContent"] == expected
    assert json.loads(tool["result"]["content"][0]["text"]) == expected


@pytest.mark.unit
def test_json_lines_stdio_is_local_deterministic_and_normalizes_errors() -> None:
    input_stream = io.StringIO(
        "{bad json}\n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        + "\n"
    )
    output_stream = io.StringIO()
    serve_stdio(stdin=input_stream, stdout=output_stream)
    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
    assert len(responses) == 2
    assert responses[0]["error"]["code"] == -32700
    assert responses[1] == {"jsonrpc": "2.0", "id": 1, "result": {}}
