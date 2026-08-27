from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from tools.artifex2 import qualify_m3_black_box as harness
from tools.artifex2.validate_m3 import validate, validate_outcome_evidence


def _passing_evidence() -> dict[str, object]:
    operations = [
        "project.create",
        "distribution.setup.plan",
        "distribution.setup.apply",
        "providers.graph",
        "providers.readiness",
        "providers.resolve",
        "providers.resolve",
        "providers.interact",
        "runtime.bootstrap",
        "runtime.workspace.create",
        "runtime.provider.execute",
        "runtime.status",
        "runtime.accept",
        "runtime.workspace.promote",
        "providers.certifications",
        "runtime.status",
    ]
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_REAL_CODEX_MULTI_PROCESS",
        "shipping_artifact": "INSTALLED_WHEEL",
        "source_tree_imported": False,
        "custom_application_factory_used": False,
        "provider_injection_used": False,
        "simulated_provider": False,
        "live_gate": {
            "status": "PASS",
            "blockers": [],
            "codex_probe": {
                "status": "PASS",
                "version_exit_code": 0,
                "auth_exit_code": 0,
                "credential_material_read": False,
            },
        },
        "journeys": {
            "J01": dict(harness.J01_INTERPRETATION),
            "J16": {
                "status": "PASS",
                "fresh_process_consumed_setup": True,
                "healthy_but_ineligible_excluded": True,
            },
            "M3_CODEX_VERTICAL_SLICE": {
                "status": "PASS",
                "provider_execution": {"live": True, "simulated": False},
                "provider_result_self_accepted": False,
                "semantic_revision": 2,
                "workspace": {"isolated": True},
                "role_certifications": {
                    "INTERACTION": "LIVE_ROLE_CERTIFIED",
                    "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
                },
            },
        },
        "public_process_calls": [{"operation": operation} for operation in operations],
    }


def test_harness_imports_no_product_modules_or_private_factories() -> None:
    path = Path(harness.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "artifex" or name.startswith("artifex.") for name in imported)
    text = path.read_text(encoding="utf-8")
    assert "create_codex_application(" not in text
    assert "Application(" not in text


def test_missing_codex_is_blocked_and_never_passes(tmp_path: Path) -> None:
    result = harness.probe_codex([], cwd=tmp_path, environment={})
    assert result["status"] == "BLOCKED"
    assert result["blocker"]["code"] == "CODEX_EXECUTABLE_NOT_FOUND"


def test_windows_qualification_root_avoids_protected_profile_temp(tmp_path: Path) -> None:
    observed = harness._qualification_temporary_parent(tmp_path / "source")
    if harness.os.name == "nt":
        assert observed == tmp_path.resolve()
    else:
        assert observed is None


def test_interaction_marker_must_be_unique_and_bounded() -> None:
    marker = "ARTIFEX_INTERACTION project_id=project semantic_revision=1"
    assert harness._is_bounded_interaction_response(marker, marker)
    assert harness._is_bounded_interaction_response(f"Result: {marker}.", marker)
    assert not harness._is_bounded_interaction_response(f"{marker}\n{marker}", marker)
    assert not harness._is_bounded_interaction_response("x" * 513 + marker, marker)


def test_unauthenticated_codex_is_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, "codex-cli 0.150.1\n", ""),
            subprocess.CompletedProcess([], 1, "", "Not logged in\n"),
        ]
    )
    monkeypatch.setattr(harness.shutil, "which", lambda _: "codex")
    monkeypatch.setattr(harness, "_run", lambda *args, **kwargs: next(responses))
    result = harness.probe_codex(["codex"], cwd=tmp_path, environment={})
    assert result["status"] == "BLOCKED"
    assert result["blocker"]["code"] == "CODEX_AUTH_UNAVAILABLE"
    assert "Not logged in" in result["blocker"]["detail"]


def test_fail_closed_validator_accepts_only_live_bounded_vertical_slice() -> None:
    validate_outcome_evidence(_passing_evidence())

    mutations = (
        ("status", "BLOCKED", "not PASS"),
        ("source_tree_imported", True, "forbidden shortcut"),
        ("provider_injection_used", True, "forbidden shortcut"),
        ("simulated_provider", True, "forbidden shortcut"),
    )
    for field, value, expected in mutations:
        evidence = _passing_evidence()
        evidence[field] = value
        with pytest.raises(ValueError, match=expected):
            validate_outcome_evidence(evidence)


def test_validator_rejects_full_j01_pass_role_conflation_and_auth_ambiguity() -> None:
    j01 = _passing_evidence()
    j01["journeys"]["J01"]["status"] = "PASS"  # type: ignore[index]
    with pytest.raises(ValueError, match="must not mark full J01 PASS"):
        validate_outcome_evidence(j01)

    roles = _passing_evidence()
    del roles["journeys"]["M3_CODEX_VERTICAL_SLICE"]["role_certifications"][  # type: ignore[index]
        "INTERACTION"
    ]
    with pytest.raises(ValueError, match="role certifications"):
        validate_outcome_evidence(roles)

    auth = _passing_evidence()
    auth["live_gate"]["codex_probe"]["auth_exit_code"] = 1  # type: ignore[index]
    with pytest.raises(ValueError, match="auth live gate"):
        validate_outcome_evidence(auth)


def test_active_m3_control_plane_is_valid_without_claiming_live_acceptance() -> None:
    state = validate(Path(__file__).parents[2])
    m3 = next(item for item in state["milestones"] if item["id"] == "M3")
    assert m3["state"] == "ACTIVE"
    assert m3["accepted"] is False
