from pathlib import Path

from tools.artifex2.validate_m2 import validate as validate_m2


def test_m2_control_plane_acceptance_is_self_consistent() -> None:
    state = validate_m2(Path(__file__).parents[2])

    assert state["program"]["current_milestone"] == "M2"
    assert state["program"]["current_status"] == "ACCEPTED"
    m3 = next(item for item in state["milestones"] if item["id"] == "M3")
    assert m3["state"] == "READY"
    assert m3["started"] is False

