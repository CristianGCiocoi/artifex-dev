from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.artifex2.validate_m8c import validate, validate_public_outcome


def _evidence() -> dict[str, object]:
    path = Path(__file__).parents[2] / "implementation/EVIDENCE/M8C-PUBLIC-OUTCOME.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_blocked_m8c_control_plane_and_public_evidence_are_self_consistent() -> None:
    state = validate(Path(__file__).parents[2])
    milestone = next(item for item in state["milestones"] if item["id"] == "M8C")
    assert milestone["state"] == "BLOCKED_EXTERNAL_PREREQUISITE"
    assert milestone["accepted"] is False


def test_blocked_public_evidence_cannot_claim_live_certification() -> None:
    forged = copy.deepcopy(_evidence())
    forged["provider_certification"]["roles"][0]["state"] = "LIVE_ROLE_CERTIFIED"
    with pytest.raises(ValueError, match="inherited a live certification"):
        validate_public_outcome(forged)
