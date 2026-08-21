from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


@pytest.mark.unit
def test_dashboard_schema_is_valid_json_schema() -> None:
    path = Path(__file__).parents[1] / "schemas" / "dashboard-state.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

