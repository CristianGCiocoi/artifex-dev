from pathlib import Path

from tools.artifex2.validate_m2 import validate as validate_m2


def test_m2_control_plane_acceptance_is_self_consistent() -> None:
    state = validate_m2(Path(__file__).parents[2])

    m2 = next(item for item in state["milestones"] if item["id"] == "M2")
    assert m2["state"] == "ACCEPTED"
    assert m2["accepted"] is True
    m3 = next(item for item in state["milestones"] if item["id"] == "M3")
    assert m3["state"] in {"READY", "ACTIVE", "ACCEPTED"}

