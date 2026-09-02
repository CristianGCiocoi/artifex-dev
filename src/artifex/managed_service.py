"""Platform-neutral managed-service host and authenticated local client.

The host owns the durable runtime independently of any CLI, MCP, or other
frontend process.  OS service registration is intentionally outside this
module: installers may run this module under the supported platform's service
manager without changing its authority or transport contract.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hmac
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from time import sleep, time
from typing import Any

from artifex.application import Application, OperationContext, OperationRequest
from artifex.runtime import ManagedRuntimeService

SERVICE_STATE_SCHEMA = "artifex.managed-service-state/v1"
LOCAL_TRANSPORT_PROTOCOL = "artifex.local-jsonl/v1"
MAX_REQUEST_BYTES = 1024 * 1024


class ManagedServiceError(RuntimeError):
    """Base error for managed-service lifecycle and transport failures."""


class ServiceAlreadyRunningError(ManagedServiceError):
    """Raised when single-instance ownership cannot be acquired safely."""


class ServiceUnavailableError(ManagedServiceError):
    """Raised when the public local client cannot reach a running service."""


@dataclass(frozen=True, slots=True)
class ServicePaths:
    """Deterministic paths owned by one user-scoped ARTIFEX service."""

    state_root: Path
    state_file: Path
    runstore: Path
    workspace_root: Path
    instance_lock: Path
    transport_token: Path

    @classmethod
    def resolve(cls, root: str | Path | None = None) -> ServicePaths:
        selected = Path(root).expanduser() if root is not None else _default_state_root()
        resolved = selected.resolve()
        if resolved.parent == resolved:
            raise ValueError("managed service state root cannot be a filesystem root")
        return cls(
            state_root=resolved,
            state_file=resolved / "service-state.json",
            runstore=resolved / "runstore.sqlite3",
            workspace_root=_managed_workspace_root(resolved),
            instance_lock=resolved / ".service-instance.lock",
            transport_token=resolved / ".local-transport-token",
        )

    def prepare(self) -> None:
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.state_root.is_dir():
            raise ManagedServiceError("managed service state root must be a directory")
        _restrict_directory(self.state_root)
        workspace_mode = _managed_workspace_mode()
        if workspace_mode is None:
            self.workspace_root.mkdir(parents=True, exist_ok=True)
        else:
            self.workspace_root.mkdir(
                mode=workspace_mode, parents=True, exist_ok=True
            )
        if not self.workspace_root.is_dir():
            raise ManagedServiceError("managed service workspace root must be a directory")
        if os.name != "nt":
            _restrict_directory(self.workspace_root)


def _managed_workspace_root(
    state_root: Path, *, platform_name: str = os.name
) -> Path:
    """Keep Windows provider sandboxes outside the private RunStore DACL tree.

    The Windows managed-service state root is intentionally restricted to the
    current user and LocalSystem. Codex's native Windows sandbox runs under a
    dedicated sandbox identity, so a workspace nested beneath that private root
    is not traversable even after Codex authorizes the workspace leaf. A
    deterministic sibling remains service-owned and isolated while preserving
    the private ACL boundary around RunStore, fencing and transport credentials.
    """

    if platform_name == "nt":
        return state_root.with_name(f"{state_root.name}-workspaces")
    return state_root / "workspaces"


def _managed_workspace_mode(*, platform_name: str = os.name) -> int | None:
    """Avoid Python's private ``0o700`` DACL on Windows provider workspaces.

    Windows provider sandboxes add a capability SID to each owned workspace.
    Creating the managed workspace root with ``mode=0o700`` produces a protected
    owner-only DACL on current Python builds, preventing that sandbox SID from
    traversing the root.  Omitting the mode preserves the normal inherited user
    ACL; each provider workspace still applies its own sandbox boundary.
    """

    return None if platform_name == "nt" else 0o700


@dataclass(frozen=True, slots=True)
class ServiceState:
    """Secret-free durable service discovery and lifecycle projection."""

    service_id: str
    instance_id: str
    lifecycle_state: str
    process_id: int
    coordinator_generation: int
    started_at: int
    stopped_at: int | None
    shutdown_reason: str | None
    host: str
    port: int
    paths: ServicePaths

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SERVICE_STATE_SCHEMA,
            "service_id": self.service_id,
            "instance_id": self.instance_id,
            "lifecycle_state": self.lifecycle_state,
            "process_id": self.process_id,
            "coordinator_generation": self.coordinator_generation,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "shutdown_reason": self.shutdown_reason,
            "frontend_independent": True,
            "transport": {
                "kind": "TCP_LOOPBACK",
                "protocol": LOCAL_TRANSPORT_PROTOCOL,
                "host": self.host,
                "port": self.port,
            },
            "paths": {
                "state_root": str(self.paths.state_root),
                "runstore": str(self.paths.runstore),
                "workspace_root": str(self.paths.workspace_root),
            },
        }


class _InstanceLock:
    """Atomic single-instance guard with one bounded stale-owner recovery."""

    def __init__(self, path: Path, instance_id: str) -> None:
        self.path = path
        self.instance_id = instance_id
        self.owned = False

    def acquire(self) -> None:
        payload = _encode_json({"instance_id": self.instance_id, "process_id": os.getpid()})
        for attempt in range(2):
            try:
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                owner = _read_lock_owner(self.path)
                if owner is None:
                    raise ServiceAlreadyRunningError(
                        "service lock is unreadable; refusing unsafe ownership recovery"
                    ) from exc
                if _process_exists(owner[1]):
                    raise ServiceAlreadyRunningError(
                        f"managed service is already owned by process {owner[1]}"
                    ) from exc
                if attempt > 0:
                    raise ServiceAlreadyRunningError(
                        "stale service ownership changed during bounded recovery"
                    ) from exc
                with suppress(FileNotFoundError):
                    self.path.unlink()
                continue
            try:
                os.write(descriptor, payload.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _verify_private_file(self.path)
            self.owned = True
            return
        raise ServiceAlreadyRunningError("managed service ownership was not acquired")

    def release(self) -> None:
        if not self.owned:
            return
        owner = _read_lock_owner(self.path)
        if owner is not None and owner[0] == self.instance_id:
            self.path.unlink(missing_ok=True)
        self.owned = False


class _LoopbackServer(socketserver.TCPServer):
    allow_reuse_address = False


class ManagedServiceHost:
    """Long-running runtime owner with controlled shutdown and fencing heartbeat."""

    def __init__(
        self,
        state_root: str | Path | None = None,
        *,
        service_id: str = "artifex-managed-service",
        host: str = "127.0.0.1",
        port: int = 0,
        lease_seconds: int = 30,
        clock: Callable[[], int] = lambda: int(time()),
    ) -> None:
        if not service_id.strip() or any(character.isspace() for character in service_id):
            raise ValueError("service_id must be a non-empty identifier without whitespace")
        if host != "127.0.0.1":
            raise ValueError("managed service transport must bind to IPv4 loopback")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if lease_seconds < 3:
            raise ValueError("coordinator lease must be at least three seconds")
        self.paths = ServicePaths.resolve(state_root)
        self.service_id = service_id
        self.host = host
        self.requested_port = port
        self.lease_seconds = lease_seconds
        self.clock = clock
        self.instance_id = uuid.uuid4().hex
        self._lock = _InstanceLock(self.paths.instance_lock, self.instance_id)
        self._runtime: ManagedRuntimeService | None = None
        self._application: Application | None = None
        self._server: _LoopbackServer | None = None
        self._server_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop = threading.Event()
        self._shutdown_requested = threading.Event()
        self._authority_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._started_at: int | None = None
        self._port = 0
        self._running = False
        self._transport_token = ""

    @property
    def state(self) -> ServiceState:
        runtime = self._runtime
        if runtime is None or self._started_at is None:
            raise ServiceUnavailableError("managed service has not started")
        return ServiceState(
            service_id=self.service_id,
            instance_id=self.instance_id,
            lifecycle_state="RUNNING" if self._running else "STOPPED",
            process_id=os.getpid(),
            coordinator_generation=runtime.coordinator.token.generation,
            started_at=self._started_at,
            stopped_at=None,
            shutdown_reason=None,
            host=self.host,
            port=self._port,
            paths=self.paths,
        )

    def start(self) -> ServiceState:
        with self._lifecycle_lock:
            if self._running:
                return self.state
            self.paths.prepare()
            self._lock.acquire()
            try:
                self._runtime = ManagedRuntimeService(
                    self.paths.runstore,
                    service_id=self.service_id,
                    workspace_root=self.paths.workspace_root,
                    clock=self.clock,
                    lease_seconds=self.lease_seconds,
                )
                self._application = Application(runtime_service=self._runtime)
                self._transport_token = secrets.token_urlsafe(48)
                _write_private_text(
                    self.paths.transport_token,
                    self._transport_token,
                    enforce_windows_acl=True,
                )
                self._server = _LoopbackServer(
                    (self.host, self.requested_port), self._handler_type()
                )
                address = self._server.server_address
                self._port = int(address[1])
                self._started_at = self.clock()
                self._running = True
                self._write_state(self.state)
                self._server_thread = threading.Thread(
                    target=self._server.serve_forever,
                    name=f"artifex-service-transport-{self.instance_id[:8]}",
                    daemon=True,
                )
                self._heartbeat_thread = threading.Thread(
                    target=self._heartbeat,
                    name=f"artifex-service-fence-{self.instance_id[:8]}",
                    daemon=True,
                )
                self._server_thread.start()
                self._heartbeat_thread.start()
                return self.state
            except Exception:
                self._running = False
                if self._server is not None:
                    self._server.server_close()
                self.paths.transport_token.unlink(missing_ok=True)
                self._lock.release()
                raise

    def serve_forever(self) -> None:
        self.start()
        try:
            self._shutdown_requested.wait()
        finally:
            self.stop(reason="CONTROLLED")

    def request_shutdown(self) -> None:
        """Request service-owned shutdown without depending on client lifetime."""

        self._shutdown_requested.set()
        threading.Thread(
            target=self.stop,
            kwargs={"reason": "CLIENT_REQUEST"},
            name=f"artifex-service-stop-{self.instance_id[:8]}",
            daemon=True,
        ).start()

    def stop(self, *, reason: str = "CONTROLLED") -> None:
        with self._lifecycle_lock:
            if not self._running:
                return
            self._running = False
            self._shutdown_requested.set()
            self._heartbeat_stop.set()
            server = self._server
            if server is not None:
                server.shutdown()
                server.server_close()
            if (
                self._server_thread is not None
                and self._server_thread is not threading.current_thread()
            ):
                self._server_thread.join(timeout=5)
            if (
                self._heartbeat_thread is not None
                and self._heartbeat_thread is not threading.current_thread()
            ):
                self._heartbeat_thread.join(timeout=5)
            runtime = self._runtime
            started_at = self._started_at
            if runtime is not None and started_at is not None:
                self._write_state(
                    ServiceState(
                        service_id=self.service_id,
                        instance_id=self.instance_id,
                        lifecycle_state="STOPPED",
                        process_id=os.getpid(),
                        coordinator_generation=runtime.coordinator.token.generation,
                        started_at=started_at,
                        stopped_at=self.clock(),
                        shutdown_reason=reason,
                        host=self.host,
                        port=self._port,
                        paths=self.paths,
                    )
                )
            self.paths.transport_token.unlink(missing_ok=True)
            self._transport_token = ""
            self._lock.release()

    def _heartbeat(self) -> None:
        interval = max(1.0, self.lease_seconds / 3)
        while not self._heartbeat_stop.wait(interval):
            try:
                with self._authority_lock:
                    runtime = self._require_runtime()
                    runtime.coordinator.renew()
                    if self._running:
                        self._write_state(self.state)
            except Exception:
                self._shutdown_requested.set()
                return

    def _handler_type(self) -> type[socketserver.StreamRequestHandler]:
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
                if not line or len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
                    owner._write_response(
                        self.wfile, _transport_error(None, "INVALID_REQUEST", "invalid frame")
                    )
                    return
                try:
                    value = json.loads(line)
                    response = owner._dispatch_transport(value)
                except (TypeError, ValueError, json.JSONDecodeError):
                    response = _transport_error(None, "INVALID_REQUEST", "invalid request")
                owner._write_response(self.wfile, response)

        return Handler

    def _dispatch_transport(self, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise TypeError("request must be an object")
        request_id = value.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id is required")
        if value.get("protocol") != LOCAL_TRANSPORT_PROTOCOL:
            return _transport_error(request_id, "PROTOCOL_MISMATCH", "unsupported protocol")
        token = value.get("authorization")
        if not isinstance(token, str) or not hmac.compare_digest(token, self._transport_token):
            return _transport_error(request_id, "UNAUTHORIZED", "local authorization failed")
        operation = value.get("operation")
        if not isinstance(operation, str) or not operation:
            raise ValueError("operation is required")
        arguments = value.get("arguments", {})
        context = value.get("context", {})
        if not isinstance(arguments, Mapping) or not isinstance(context, Mapping):
            raise TypeError("arguments and context must be objects")
        if operation == "service.status":
            result: Mapping[str, object] = {"ok": True, "value": self.state.to_dict()}
        elif operation == "service.shutdown":
            result = {"ok": True, "value": {"shutdown_requested": True}}
            self.request_shutdown()
        else:
            application = self._application
            if application is None:
                raise ServiceUnavailableError("managed service application is unavailable")
            project_root = context.get("project_root")
            correlation_id = context.get("correlation_id")
            if project_root is not None and not isinstance(project_root, str):
                raise TypeError("context project_root must be a string")
            if correlation_id is not None and not isinstance(correlation_id, str):
                raise TypeError("context correlation_id must be a string")
            with self._authority_lock:
                result = application.dispatch(
                    OperationRequest(
                        operation,
                        dict(arguments),
                        OperationContext(
                            project_root,
                            "managed-service-local-client",
                            correlation_id,
                        ),
                    )
                ).to_dict()
        return {
            "protocol": LOCAL_TRANSPORT_PROTOCOL,
            "request_id": request_id,
            "result": dict(result),
        }

    @staticmethod
    def _write_response(stream: Any, response: Mapping[str, object]) -> None:
        try:
            stream.write((_encode_json(response) + "\n").encode("utf-8"))
            stream.flush()
        except (BrokenPipeError, ConnectionResetError):
            # The service-owned operation is complete even if its frontend closed.
            return

    def _require_runtime(self) -> ManagedRuntimeService:
        if self._runtime is None:
            raise ServiceUnavailableError("managed runtime is unavailable")
        return self._runtime

    def _write_state(self, state: ServiceState) -> None:
        _write_json_atomic(self.paths.state_file, state.to_dict())


class LocalServiceClient:
    """Public frontend-independent client for the managed local service."""

    def __init__(
        self,
        state_root: str | Path | None = None,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("client timeout must be positive")
        self.paths = ServicePaths.resolve(state_root)
        self.timeout_seconds = timeout_seconds

    def call(
        self,
        operation: str,
        arguments: Mapping[str, object] | None = None,
        *,
        project_root: str | None = None,
        correlation_id: str | None = None,
    ) -> Mapping[str, object]:
        state = read_service_state(self.paths.state_file)
        if state.get("lifecycle_state") != "RUNNING":
            raise ServiceUnavailableError("managed service is not running")
        transport = state.get("transport")
        if not isinstance(transport, Mapping):
            raise ServiceUnavailableError("managed service transport state is invalid")
        host = transport.get("host")
        port = transport.get("port")
        protocol = transport.get("protocol")
        if host != "127.0.0.1" or not isinstance(port, int) or protocol != LOCAL_TRANSPORT_PROTOCOL:
            raise ServiceUnavailableError("managed service transport state is unsupported")
        try:
            authorization = self.paths.transport_token.read_text(encoding="utf-8")
        except OSError as exc:
            raise ServiceUnavailableError("managed service authorization is unavailable") from exc
        request_id = uuid.uuid4().hex
        request = {
            "protocol": LOCAL_TRANSPORT_PROTOCOL,
            "request_id": request_id,
            "authorization": authorization,
            "operation": operation,
            "arguments": dict(arguments or {}),
            "context": {
                "project_root": project_root,
                "correlation_id": correlation_id,
            },
        }
        try:
            with socket.create_connection((host, port), timeout=self.timeout_seconds) as connection:
                connection.sendall((_encode_json(request) + "\n").encode("utf-8"))
                response = _read_socket_line(connection)
        except OSError as exc:
            raise ServiceUnavailableError("managed service transport is unavailable") from exc
        if response.get("protocol") != LOCAL_TRANSPORT_PROTOCOL:
            raise ServiceUnavailableError("managed service returned an invalid protocol")
        if response.get("request_id") != request_id:
            raise ServiceUnavailableError("managed service response correlation failed")
        result = response.get("result")
        if not isinstance(result, Mapping):
            error = response.get("error")
            raise ServiceUnavailableError(f"managed service request failed: {error!r}")
        return result

    def status(self) -> Mapping[str, object]:
        return self.call("service.status")

    def shutdown(self) -> Mapping[str, object]:
        return self.call("service.shutdown")


def read_service_state(path: str | Path) -> Mapping[str, object]:
    state_path = Path(path)
    failure: OSError | json.JSONDecodeError | None = None
    value: object = None
    for _attempt in range(5):
        try:
            value = json.loads(state_path.read_text(encoding="utf-8"))
            break
        except PermissionError as exc:
            # Windows readers can briefly overlap an atomic replacement.
            failure = exc
            sleep(0.01)
        except (OSError, json.JSONDecodeError) as exc:
            failure = exc
            break
    else:
        value = None
    if failure is not None and value is None:
        raise ServiceUnavailableError(
            "managed service state is unavailable or invalid"
        ) from failure
    if not isinstance(value, Mapping) or value.get("schema_version") != SERVICE_STATE_SCHEMA:
        raise ServiceUnavailableError("managed service state schema is unsupported")
    return value


def main(argv: Sequence[str] | None = None) -> None:
    """Run the managed host as ``python -m artifex.managed_service``."""

    parser = argparse.ArgumentParser(description="Run the ARTIFEX managed local service")
    parser.add_argument("--state-root")
    parser.add_argument("--service-id", default="artifex-managed-service")
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args(argv)
    host = ManagedServiceHost(
        arguments.state_root,
        service_id=arguments.service_id,
        port=arguments.port,
    )

    def request_stop(_signum: int, _frame: object) -> None:
        host.request_shutdown()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)
    host.serve_forever()


def _default_state_root() -> Path:
    configured = os.environ.get("ARTIFEX_STATE_ROOT")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "ARTIFEX" / "state"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ARTIFEX" / "state"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state).expanduser() / "artifex"
    return Path.home() / ".local" / "state" / "artifex"


def _restrict_directory(path: Path) -> None:
    if os.name == "nt":
        _enforce_windows_private_acl(path, directory=True)
        return
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ManagedServiceError("managed service directory is not private")


def _write_private_text(
    path: Path, value: str, *, enforce_windows_acl: bool = False
) -> None:
    path.unlink(missing_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _verify_private_file(path)
    if enforce_windows_acl and os.name == "nt":
        try:
            _enforce_windows_private_acl(path, directory=False)
        except Exception:
            path.unlink(missing_ok=True)
            raise


def _verify_private_file(path: Path) -> None:
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        path.unlink(missing_ok=True)
        raise ManagedServiceError("managed service private file permissions are unsafe")


def _enforce_windows_private_acl(path: Path, *, directory: bool) -> None:
    """Restrict a Windows path to the current user and LocalSystem."""

    if os.name != "nt":
        raise ManagedServiceError("Windows ACL enforcement is unavailable on this platform")
    current_sid = _windows_current_user_sid()
    inheritance = "(OI)(CI)F" if directory else "F"
    grants = [f"*{current_sid}:{inheritance}"]
    if current_sid != "S-1-5-18":
        grants.append(f"*S-1-5-18:{inheritance}")
    _run_windows_command(
        (
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/grant:r",
            *grants,
        )
    )
    _run_windows_command(
        (
            "icacls.exe",
            str(path),
            "/remove:g",
            "*S-1-5-32-544",
            "*S-1-3-4",
        )
    )
    _run_windows_command(("icacls.exe", str(path), "/verify"))
    _verify_windows_private_acl(path, current_sid=current_sid, directory=directory)


def _windows_current_user_sid() -> str:
    output = _run_windows_command(("whoami.exe", "/user", "/fo", "csv", "/nh"))
    try:
        row = next(csv.reader(output.splitlines()))
    except (StopIteration, csv.Error) as exc:
        raise ManagedServiceError("Windows user SID lookup returned invalid data") from exc
    sid = row[-1].strip() if row else ""
    if re.fullmatch(r"S-1-(?:\d+-)+\d+", sid, flags=re.IGNORECASE) is None:
        raise ManagedServiceError("Windows user SID lookup returned invalid data")
    return sid.upper()


def _run_windows_command(arguments: Sequence[str]) -> str:
    """Run one reviewed Windows utility argument vector without a shell."""

    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ManagedServiceError("Windows ACL utility could not be executed") from exc
    if completed.returncode != 0:
        raise ManagedServiceError("Windows ACL utility rejected the requested operation")
    return completed.stdout


def _verify_windows_private_acl(
    path: Path, *, current_sid: str, directory: bool
) -> None:
    acl_file = path.parent / f".artifex-acl-{uuid.uuid4().hex}.txt"
    try:
        _run_windows_command(("icacls.exe", str(path), "/save", str(acl_file)))
        raw = acl_file.read_bytes()
    except OSError as exc:
        raise ManagedServiceError("Windows ACL verification data is unavailable") from exc
    finally:
        acl_file.unlink(missing_ok=True)
    sddl = _decode_icacls_acl(raw)
    _validate_windows_private_sddl(sddl, current_sid=current_sid, directory=directory)


def _decode_icacls_acl(raw: bytes) -> str:
    encodings = ("utf-16", "utf-16-le", "utf-8-sig")
    for encoding in encodings:
        try:
            value = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "D:" in value:
            return value
    raise ManagedServiceError("Windows ACL verification data has an invalid encoding")


def _validate_windows_private_sddl(
    value: str, *, current_sid: str, directory: bool
) -> None:
    match = re.search(r"D:([^\r\n]+)", value)
    if match is None:
        raise ManagedServiceError("Windows ACL verification did not return a DACL")
    dacl = match.group(0)
    prefix = dacl.split("(", 1)[0]
    if "P" not in prefix[2:]:
        raise ManagedServiceError("Windows ACL inheritance remains enabled")
    entries = re.findall(r"\(([^()]*)\)", dacl)
    required_sids = {current_sid.upper(), "S-1-5-18"}
    if len(entries) != len(required_sids):
        raise ManagedServiceError("Windows ACL contains an unexpected principal")
    expected_sids = {current_sid.upper(), "S-1-5-18", "SY"}
    observed: set[str] = set()
    for entry in entries:
        fields = entry.split(";")
        if len(fields) != 6:
            raise ManagedServiceError("Windows ACL contains an invalid entry")
        ace_type, flags, rights, _object_id, _inherit_id, sid = fields
        normalized_sid = sid.upper()
        if ace_type != "A" or normalized_sid not in expected_sids:
            raise ManagedServiceError("Windows ACL contains an unexpected principal")
        if "ID" in flags or rights.upper() not in {"FA", "F", "0X1F01FF"}:
            raise ManagedServiceError("Windows ACL does not grant explicit full control")
        if directory and not {"OI", "CI"} <= set(re.findall(r".{2}", flags)):
            raise ManagedServiceError("Windows directory ACL does not protect child objects")
        if not directory and flags:
            raise ManagedServiceError("Windows token ACL has unexpected inheritance flags")
        observed.add("S-1-5-18" if normalized_sid == "SY" else normalized_sid)
    if observed != required_sids:
        raise ManagedServiceError("Windows ACL principals are incomplete")


def _write_json_atomic(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    _write_private_text(temporary, _encode_json(value))
    os.replace(temporary, path)


def _read_lock_owner(path: Path) -> tuple[str, int] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping):
        return None
    instance_id = value.get("instance_id")
    process_id = value.get("process_id")
    if not isinstance(instance_id, str) or not instance_id or not isinstance(process_id, int):
        return None
    return instance_id, process_id


def _process_exists(process_id: int) -> bool:
    if process_id <= 0:
        return False
    if process_id == os.getpid():
        return True
    if os.name == "nt":
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(process_query_limited_information, False, process_id)
        if not handle:
            # Access denied is treated as a live owner; only invalid PIDs recover.
            return int(kernel32.GetLastError()) != 87
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return int(exit_code.value) == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_socket_line(connection: socket.socket) -> Mapping[str, object]:
    chunks = bytearray()
    while len(chunks) <= MAX_REQUEST_BYTES:
        part = connection.recv(min(65536, MAX_REQUEST_BYTES + 1 - len(chunks)))
        if not part:
            break
        chunks.extend(part)
        if b"\n" in part:
            break
    if len(chunks) > MAX_REQUEST_BYTES or not chunks.endswith(b"\n"):
        raise ServiceUnavailableError("managed service returned an invalid frame")
    try:
        value = json.loads(bytes(chunks))
    except json.JSONDecodeError as exc:
        raise ServiceUnavailableError("managed service returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ServiceUnavailableError("managed service response must be an object")
    return value


def _transport_error(
    request_id: object, code: str, message: str
) -> dict[str, object]:
    return {
        "protocol": LOCAL_TRANSPORT_PROTOCOL,
        "request_id": request_id,
        "error": {"code": code, "message": message},
    }


def _encode_json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


if __name__ == "__main__":
    main()


__all__ = [
    "LOCAL_TRANSPORT_PROTOCOL",
    "LocalServiceClient",
    "ManagedServiceError",
    "ManagedServiceHost",
    "ServiceAlreadyRunningError",
    "ServicePaths",
    "ServiceState",
    "ServiceUnavailableError",
    "read_service_state",
]
