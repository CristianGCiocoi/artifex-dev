"""Transport-independent operation registry and dispatch."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from artifex import __version__


@dataclass(frozen=True, slots=True)
class OperationContext:
    project_root: str | None = None
    actor: str = "anonymous"
    correlation_id: str | None = None


@dataclass(frozen=True, slots=True)
class OperationRequest:
    operation: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    context: OperationContext = field(default_factory=OperationContext)


@dataclass(frozen=True, slots=True)
class OperationError:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OperationResult:
    ok: bool
    value: Mapping[str, Any] = field(default_factory=dict)
    error: OperationError | None = None


Operation = Callable[[OperationRequest], OperationResult]


class Application:
    """The single semantic API used by CLI, MCP, and interface packs."""

    def __init__(self) -> None:
        self._operations: dict[str, Operation] = {}
        self.register("system.version", self._version)
        self.register("system.health", self._health)

    def register(self, name: str, operation: Operation) -> None:
        if not name or name in self._operations:
            raise ValueError(f"operation is empty or already registered: {name!r}")
        self._operations[name] = operation

    def dispatch(self, request: OperationRequest) -> OperationResult:
        operation = self._operations.get(request.operation)
        if operation is None:
            return OperationResult(
                ok=False,
                error=OperationError(
                    "OPERATION_NOT_FOUND", f"unknown operation {request.operation!r}"
                ),
            )
        try:
            return operation(request)
        except Exception as exc:  # semantic boundary: normalize transport errors
            return OperationResult(
                ok=False,
                error=OperationError("OPERATION_FAILED", str(exc), {"type": type(exc).__name__}),
            )

    @staticmethod
    def _version(_: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value={"version": __version__})

    @staticmethod
    def _health(_: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value={"status": "PASS", "core": "available"})
