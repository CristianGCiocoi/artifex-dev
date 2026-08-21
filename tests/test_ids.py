from __future__ import annotations

import pytest

from artifex.ids import StableId


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["REQ-F-001", "REQ-NF-012", "INV-028", "M00", "M11-T13", "EVD-001", "CHG-SELF-001"],
)
def test_stable_ids_round_trip(value: str) -> None:
    assert str(StableId.parse(value.lower())) == value


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "REQ-1", "M1", "../EVD-1", "REQ-F-0001"])
def test_stable_ids_reject_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        StableId.parse(value)

