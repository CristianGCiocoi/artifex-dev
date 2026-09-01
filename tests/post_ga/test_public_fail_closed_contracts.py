from __future__ import annotations

import io
import json
import os
import socket
from pathlib import Path
from typing import Any

import pytest

import artifex.application.api as application_api
import artifex.managed_service as managed_service
from artifex.application import Application, OperationContext, OperationRequest, OperationResult
from artifex.managed_service import ManagedServiceError
from artifex.mcp import JSONRPC_VERSION, LocalMCPServer, serve_stdio


@pytest.mark.parametrize("operation", Application().operation_names)
def test_every_public_operation_normalizes_empty_input_without_uncaught_failure(
    operation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every published operation must fail closed or return a typed result.

    This exercises the current 2.x public dispatch surface independently of the
    historical V1 release validator. Empty input is intentionally adversarial:
    handlers may inspect the isolated project root but must not escape it or
    surface an implementation exception.
    """

    monkeypatch.chdir(tmp_path)
    for name in tuple(os.environ):
        if name.startswith("COV_CORE_") or name == "COVERAGE_PROCESS_START":
            monkeypatch.delenv(name, raising=False)
    result = Application().dispatch(
        OperationRequest(
            operation,
            {},
            OperationContext(
                project_root=str(tmp_path / "project"),
                actor="post-ga-ci",
                correlation_id="post-ga-empty-input",
            ),
        )
    )

    assert isinstance(result, OperationResult)
    payload = result.to_dict()
    assert payload["ok"] is result.ok
    assert set(payload) <= {"ok", "value", "error"}
    if not result.ok:
        assert result.error is not None
        assert result.error.code in {
            "ARTIFACT_CORRUPT",
            "INVALID_ARGUMENT",
            "NOT_FOUND",
            "OPERATION_FAILED",
            "POLICY_BLOCKED",
        }
        assert "Traceback" not in result.error.message


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: application_api._mapping([], "value"), TypeError),
        (lambda: application_api._required_mapping({"value": {}}, "value"), ValueError),
        (lambda: application_api._required_string({}, "value"), ValueError),
        (lambda: application_api._required_string({"value": " "}, "value"), ValueError),
        (lambda: application_api._required_sequence({"value": "x"}, "value"), ValueError),
        (lambda: application_api._required_sequence({"value": []}, "value"), ValueError),
        (lambda: application_api._string_sequence({"value": "x"}, "value"), TypeError),
        (lambda: application_api._string_sequence({"value": [""]}, "value"), TypeError),
        (lambda: application_api._mapping_sequence({"value": {}}, "value"), TypeError),
        (lambda: application_api._mapping_sequence({"value": [1]}, "value"), TypeError),
        (lambda: application_api._optional_bool({"value": 1}, "value", False), TypeError),
        (lambda: application_api._optional_string({"value": 1}, "value"), TypeError),
        (lambda: application_api._optional_int({"value": True}, "value"), TypeError),
        (lambda: application_api._required_int({"value": True}, "value"), TypeError),
    ],
)
def test_public_argument_decoders_reject_ambiguous_json_types(
    call: Any, error: type[Exception]
) -> None:
    with pytest.raises(error):
        call()


def test_public_argument_decoders_accept_only_the_documented_shapes() -> None:
    assert application_api._mapping({"a": 1}, "value") == {"a": 1}
    assert application_api._required_mapping({"value": {"a": 1}}, "value") == {"a": 1}
    assert application_api._optional_mapping({}, "value") == {}
    assert application_api._required_string({"value": "x"}, "value") == "x"
    assert application_api._required_sequence({"value": [1]}, "value") == [1]
    assert application_api._string_sequence({"value": ["a", "b"]}, "value") == ("a", "b")
    assert application_api._mapping_sequence({"value": [{"a": 1}]}, "value") == ({"a": 1},)
    assert application_api._optional_bool({}, "value", True) is True
    assert application_api._optional_string({}, "value") is None
    assert application_api._optional_int({}, "value") is None
    assert application_api._required_int({"value": 1}, "value") == 1
    assert application_api._string_sequence_or_default({}, "value", ("default",)) == (
        "default",
    )
    assert application_api._string_or_default({}, "value", "default") == "default"


@pytest.mark.parametrize(
    "message",
    [
        None,
        [],
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"jsonrpc": JSONRPC_VERSION, "id": 1},
        {"jsonrpc": JSONRPC_VERSION, "id": 1, "method": "ping", "params": []},
        {"jsonrpc": JSONRPC_VERSION, "id": 1, "method": "missing"},
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "method": "tools/call",
            "params": {},
        },
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "method": "tools/call",
            "params": {"name": "system.health", "arguments": []},
        },
    ],
)
def test_mcp_protocol_errors_are_structured_and_never_raise(message: Any) -> None:
    result = LocalMCPServer().handle_message(message)
    assert result is not None
    assert result["jsonrpc"] == JSONRPC_VERSION
    assert "error" in result


def test_mcp_notifications_and_stdio_preserve_json_lines() -> None:
    server = LocalMCPServer()
    assert server.handle_line("not-json") is not None
    assert server.handle_message(
        {"jsonrpc": JSONRPC_VERSION, "method": "notifications/initialized"}
    ) is None
    assert server.handle_message({"jsonrpc": JSONRPC_VERSION, "method": "missing"}) is None

    source = io.StringIO(
        "\n"
        + json.dumps({"jsonrpc": JSONRPC_VERSION, "id": 1, "method": "initialize"})
        + "\n"
        + json.dumps({"jsonrpc": JSONRPC_VERSION, "id": 2, "method": "tools/list"})
        + "\n"
        + json.dumps({"jsonrpc": JSONRPC_VERSION, "id": 3, "method": "ping"})
        + "\n"
    )
    output = io.StringIO()
    serve_stdio(stdin=source, stdout=output)
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [item["id"] for item in responses] == [1, 2, 3]
    assert responses[0]["result"]["serverInfo"]["name"] == "artifex"
    assert responses[1]["result"]["tools"]
    assert responses[2]["result"] == {}


def test_managed_service_private_file_and_lock_decoders_fail_closed(tmp_path: Path) -> None:
    private = tmp_path / "private"
    managed_service._write_private_text(private, "secret", enforce_windows_acl=False)
    assert private.read_text(encoding="utf-8") == "secret"
    managed_service._verify_private_file(private)

    lock = tmp_path / "lock"
    assert managed_service._read_lock_owner(lock) is None
    lock.write_text("not-json", encoding="utf-8")
    assert managed_service._read_lock_owner(lock) is None
    lock.write_text(json.dumps({"instance_id": "", "process_id": True}), encoding="utf-8")
    assert managed_service._read_lock_owner(lock) is None
    lock.write_text(json.dumps({"instance_id": "owner", "process_id": 123}), encoding="utf-8")
    assert managed_service._read_lock_owner(lock) == ("owner", 123)
    assert managed_service._process_exists(-1) is False
    assert managed_service._process_exists(os.getpid()) is True


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json\n",
        b"[]\n",
    ],
)
def test_managed_service_transport_rejects_invalid_frames(payload: bytes) -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(payload)
        writer.shutdown(socket.SHUT_WR)
        with pytest.raises((ManagedServiceError, json.JSONDecodeError)):
            managed_service._read_socket_line(reader)
    finally:
        reader.close()
        writer.close()

    reader, writer = socket.socketpair()
    try:
        writer.sendall(b'{"request_id": 1}\n')
        assert managed_service._read_socket_line(reader) == {"request_id": 1}
    finally:
        reader.close()
        writer.close()


def test_windows_acl_decoder_accepts_supported_encodings_and_rejects_invalid_data() -> None:
    sddl = "state\r\nD:P(A;OICI;FA;;;S-1-5-18)\r\n"
    for encoding in ("utf-16", "utf-16-le", "utf-8-sig"):
        assert "D:P" in managed_service._decode_icacls_acl(sddl.encode(encoding))
    with pytest.raises(ManagedServiceError, match="invalid encoding"):
        managed_service._decode_icacls_acl(b"not-an-acl")


@pytest.mark.parametrize(
    ("sddl", "message"),
    [
        ("no dacl", "did not return"),
        ("D:AI(A;OICI;FA;;;SY)", "inheritance"),
        ("D:P(A;OICI;FA;;;SY)", "unexpected principal"),
        ("D:P(A;OICI;FR;;;SY)(A;OICI;FA;;;S-1-5-21-1)", "full control"),
        ("D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1)", "child objects"),
    ],
)
def test_windows_acl_validator_classifies_security_failures(sddl: str, message: str) -> None:
    with pytest.raises(ManagedServiceError, match=message):
        managed_service._validate_windows_private_sddl(
            sddl, current_sid="S-1-5-21-1", directory=True
        )
