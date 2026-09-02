"""Local JSON-lines MCP stdio transport over the ARTIFEX Application API."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any, TextIO

from artifex import __version__
from artifex.application import Application, OperationContext, OperationRequest

JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2025-06-18"


def bridge_identity() -> dict[str, Any]:
    """Return the installed bridge identity without starting a listener."""

    return {
        "name": "artifex",
        "version": __version__,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "transport": "stdio",
        "network_listener": False,
        "authority": "ARTIFEX_APPLICATION_API",
    }


def bridge_self_test(application: Application | None = None) -> dict[str, Any]:
    """Exercise initialization, ping, and tool discovery in-process."""

    server = LocalMCPServer(application)
    initialize = server.handle_message(
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": "initialize",
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        }
    )
    ping = server.handle_message(
        {"jsonrpc": JSONRPC_VERSION, "id": "ping", "method": "ping", "params": {}}
    )
    tools = server.handle_message(
        {"jsonrpc": JSONRPC_VERSION, "id": "tools", "method": "tools/list", "params": {}}
    )
    tool_values = tools.get("result", {}).get("tools", ()) if tools is not None else ()
    passed = (
        initialize is not None
        and initialize.get("result", {}).get("serverInfo", {}).get("version") == __version__
        and ping is not None
        and ping.get("result") == {}
        and isinstance(tool_values, list)
        and any(item.get("name") == "system.health" for item in tool_values)
    )
    return {
        **bridge_identity(),
        "status": "PASS" if passed else "FAIL",
        "checks": {
            "initialize": initialize is not None and "result" in initialize,
            "ping": ping is not None and ping.get("result") == {},
            "tools": isinstance(tool_values, list) and bool(tool_values),
        },
        "tool_count": len(tool_values) if isinstance(tool_values, list) else 0,
    }


class LocalMCPServer:
    """Minimal MCP server with one tool per semantic Application operation."""

    def __init__(self, application: Application | None = None) -> None:
        self.application = Application() if application is None else application

    def handle_line(self, line: str) -> str | None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            return _encode(_error(None, -32700, "Parse error", {"detail": str(exc)}))
        response = self.handle_message(message)
        return None if response is None else _encode(response)

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, Mapping):
            return _error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        if message.get("jsonrpc") != JSONRPC_VERSION or not isinstance(message.get("method"), str):
            return _error(request_id, -32600, "Invalid Request")
        method = str(message["method"])
        params = message.get("params", {})
        if not isinstance(params, Mapping):
            return _error(request_id, -32602, "Invalid params")

        # JSON-RPC notifications intentionally receive no response.
        notification = "id" not in message
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return None
        try:
            result = self._dispatch_method(method, params)
        except (KeyError, TypeError, ValueError) as exc:
            if notification:
                return None
            return _error(
                request_id,
                -32602,
                "Invalid params",
                {"detail": str(exc), "type": type(exc).__name__},
            )
        if result is None:
            if notification:
                return None
            return _error(request_id, -32601, "Method not found", {"method": method})
        if notification:
            return None
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}

    def _dispatch_method(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any] | None:
        if method == "initialize":
            return {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "artifex", "version": __version__},
                "instructions": "ARTIFEX operations preserve Core authority and semantic state.",
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": name,
                        "description": f"ARTIFEX semantic operation: {name}",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": True,
                        },
                    }
                    for name in self.application.operation_names
                ]
            }
        if method in {"tools/call", "operations/call"}:
            name_key = "name" if method == "tools/call" else "operation"
            name = params.get(name_key)
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not name:
                raise ValueError(f"{name_key} is required")
            if not isinstance(arguments, Mapping):
                raise TypeError("arguments must be an object")
            project_root = arguments.get("project_root")
            context = OperationContext(
                project_root=project_root if isinstance(project_root, str) else None,
                actor="mcp",
                correlation_id=str(params.get("correlation_id"))
                if params.get("correlation_id") is not None
                else None,
            )
            result = self.application.dispatch(OperationRequest(name, dict(arguments), context))
            payload = result.to_dict()
            if method == "operations/call":
                return payload
            return {
                "content": [{"type": "text", "text": _encode(payload)}],
                "structuredContent": payload,
                "isError": not result.ok,
            }
        return None


def serve_stdio(
    application: Application | None = None,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> None:
    """Serve one JSON-RPC object per line without a daemon or network listener."""

    server = LocalMCPServer(application)
    for line in stdin:
        if not line.strip():
            continue
        response = server.handle_line(line)
        if response is not None:
            stdout.write(response + "\n")
            stdout.flush()


def main() -> None:
    """Run the packaged stdio server without assuming a Python executable."""

    serve_stdio()


def _encode(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _error(
    request_id: Any,
    code: int,
    message: str,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = dict(data)
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


if __name__ == "__main__":
    main()
