from __future__ import annotations

from pathlib import Path

import yaml

from tools.artifex2.capture_v1_baseline import capture
from tools.artifex2.control_plane import _normalized_text_fingerprint, derive, render
from tools.artifex2.probe_known_gaps import probe
from tools.artifex2.validate_m0 import validate

ROOT = Path(__file__).parents[2]
INTAKE_COMMIT = "5cc5dcfeb420a6df171a44426c04a0f08fa1e877"


def _yaml(relative: str) -> dict[str, object]:
    value = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_v1_release_fixture_is_git_hash_bound_and_deterministic() -> None:
    first = capture(ROOT, "v1.0.0", INTAKE_COMMIT)
    second = capture(ROOT, "v1.0.0", INTAKE_COMMIT)

    assert first == second
    assert first["source_commit"] == "317ec177df8655ae4f94e24162107fd2acecceec"
    assert first["file_count"] >= 300
    assert len(first["aggregate_sha256"]) == 64


def test_known_v1_gaps_are_reproduced_without_source_mutation() -> None:
    result = probe(ROOT, INTAKE_COMMIT)

    assert result["status"] == "PASS"
    assert result["source_project_mutated"] is False
    assert result["reproduced"] == 10
    assert result["controlled_baselines"] == 1
    assert result["unexpected"] == []


def test_control_plane_covers_frozen_contracts_and_preserves_m0_gate() -> None:
    state = derive(ROOT)

    assert state["summary"]["milestones_total"] == 16
    assert state["summary"]["program_progress_percent"] == round(
        state["summary"]["milestones_accepted"] / 16 * 100
    )
    assert state["summary"]["current_milestone_progress_percent"] == round(
        state["summary"]["acceptance_classes_passing"]
        / state["summary"]["acceptance_classes_required"]
        * 100
    )
    assert state["summary"]["adr_count"] == 24
    assert state["summary"]["invariant_count"] == 34
    assert len(state["journeys"]) == 21
    assert state["milestones"][0]["state"] == "ACCEPTED"
    m1 = next(item for item in state["milestones"] if item["id"] == "M1")
    assert m1["state"] in {"READY", "ACTIVE", "ACCEPTED"}


def test_provider_certification_schema_is_role_specific() -> None:
    providers = _yaml("implementation/PROVIDERS/ROLE-CERTIFICATION.yaml")
    rows = providers["providers"]
    assert isinstance(rows, list)
    assert {item["role"] for item in rows if item["provider"] == "codex"} == {
        "INTERACTION",
        "EXECUTION_IMPLEMENTER",
        "HARNESS",
    }
    assert all("LIVE_ROLE_CERTIFIED" in item["steps"] for item in rows)


def test_dashboard_and_current_state_are_deterministic_projections() -> None:
    before = (ROOT / "implementation/dashboard/index.html").read_bytes()
    state = render(ROOT, write=False)
    render(ROOT, write=True)
    after = (ROOT / "implementation/dashboard/index.html").read_bytes()

    assert before == after
    assert state["projection"]["authoritative"] is False
    assert b"Derived view only" in after
    assert b"Core release baseline" in after
    assert b"optional roadmap excluded" in after
    assert b'role="progressbar"' in after


def test_evidence_fingerprint_is_checkout_line_ending_independent(tmp_path: Path) -> None:
    lf = tmp_path / "lf.yaml"
    crlf = tmp_path / "crlf.yaml"
    lf.write_bytes(b"status: PASS\nevidence:\n  - stable\n")
    crlf.write_bytes(b"status: PASS\r\nevidence:\r\n  - stable\r\n")

    assert _normalized_text_fingerprint(lf) == _normalized_text_fingerprint(crlf)


def test_m0_validator_passes_current_repository_state() -> None:
    state = validate(ROOT, None)

    assert state["milestones"][0]["state"] == "ACCEPTED"
    assert state["m0_acceptance"]["acceptance_commit"] == (
        "f476d40e7a721913b9c94c4a60b78f0500f0e85f"
    )
