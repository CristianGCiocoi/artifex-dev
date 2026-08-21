from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_validator():
    path = Path(__file__).parents[1] / "scripts" / "validate_traceability.py"
    spec = importlib.util.spec_from_file_location("validate_traceability", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.architecture
def test_every_requirement_has_milestone_ownership() -> None:
    accepted, traced, architecture = _load_validator().measure()
    assert accepted == traced
    assert accepted == architecture
