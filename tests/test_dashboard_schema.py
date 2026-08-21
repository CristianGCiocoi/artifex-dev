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


@pytest.mark.unit
def test_dashboard_schema_rejects_weakly_typed_claimed_state() -> None:
    path = Path(__file__).parents[1] / "schemas" / "dashboard-state.schema.json"
    validator = Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))
    invalid = {
        "schema_version": "1.0",
        "project": {
            "id": "ARTIFEX",
            "name": None,
            "architecture_version": "1.0",
            "implementation_plan_version": "1.0",
            "current_stage": None,
            "current_milestone": None,
            "accepted_baseline": None,
        },
        "milestones": [
            {"id": 0, "state": "ACCEPTED", "completed_tasks": 1, "total_tasks": 1, "blockers": []}
        ],
        "gates": {"pass": 1, "fail": 0, "blocked": 0, "waived": 0, "stale": 0},
        "evidence": {"current": 1, "stale": 0},
        "tests": {"suites": []},
        "traceability": {
            "requirements_total": 1,
            "requirements_traced": 1,
            "orphan_requirements": 0,
        },
        "documentation": [],
        "integrations": [],
        "comprehension": {"state": "NOT_RUN", "score": None},
        "git": {"commit": None, "tag": None, "dirty": "false"},
    }
    assert len(list(validator.iter_errors(invalid))) >= 3
