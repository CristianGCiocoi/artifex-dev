from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.artifex2.validate_m9 import M9EvidenceError, validate_outcome

EVIDENCE = Path("implementation/EVIDENCE/M9-J09-SHIPPING-QUALIFIED.json")
ARTIFACT_SHA256 = "6f532c163ddf83546ab9d77773e46efc630ad72e4b416477a7de39563373bb85"
SOURCE_COMMIT = "6854bfbd07863fcb0f176adca1c4807890fcbec1"


def _evidence() -> dict[str, object]:
    value = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_validate_real_m9_shipping_outcome() -> None:
    result = validate_outcome(
        _evidence(),
        expected_artifact_sha256=ARTIFACT_SHA256,
        expected_source_commit=SOURCE_COMMIT,
    )

    assert result["status"] == "PASS"
    assert result["journey"] == "J09"
    assert result["public_process_call_count"] == 12


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("approval_tokens_retained",), True),
        (("journeys", "J09", "empty_legacy_runtime_history"), False),
        (("journeys", "J09", "semantic_fingerprint_after"), "0" * 64),
        (("candidate", "installed", "native"), False),
    ],
)
def test_validate_m9_fails_closed(path: tuple[str, ...], replacement: object) -> None:
    value = copy.deepcopy(_evidence())
    target: dict[str, object] = value
    for key in path[:-1]:
        child = target[key]
        assert isinstance(child, dict)
        target = child
    target[path[-1]] = replacement

    with pytest.raises(M9EvidenceError):
        validate_outcome(
            value,
            expected_artifact_sha256=ARTIFACT_SHA256,
            expected_source_commit=SOURCE_COMMIT,
        )
