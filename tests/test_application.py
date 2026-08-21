from __future__ import annotations

import pytest

from artifex.application import Application, OperationRequest, OperationResult


@pytest.mark.unit
def test_health_and_version_smoke_operations() -> None:
    app = Application()
    assert app.dispatch(OperationRequest("system.health")).value["status"] == "PASS"
    assert app.dispatch(OperationRequest("system.version")).ok is True


@pytest.mark.unit
def test_unknown_operation_is_normalized() -> None:
    result = Application().dispatch(OperationRequest("missing.operation"))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "OPERATION_NOT_FOUND"


@pytest.mark.unit
def test_registration_rejects_duplicates_and_normalizes_failures() -> None:
    app = Application()
    with pytest.raises(ValueError):
        app.register("system.health", lambda _: OperationResult(ok=True))

    def failing(_: OperationRequest) -> OperationResult:
        raise RuntimeError("normalized")

    app.register("test.failing", failing)
    result = app.dispatch(OperationRequest("test.failing"))
    assert result.error is not None
    assert result.error.code == "OPERATION_FAILED"

