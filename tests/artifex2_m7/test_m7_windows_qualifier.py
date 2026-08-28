from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from tools.artifex2.qualify_m7_windows import (
    _enforce_official_host,
    _enforce_provider_separation,
)
from tools.artifex2.validate_m7 import (
    CELL_CONTRACTS,
    DEFAULT_WINDOWS_BUILD,
    DEFAULT_WINDOWS_VERSION,
    ELIGIBLE_WINDOWS_VERSIONS,
    M7_CONTRACT_DIGEST,
    WINDOWS_SERVICE_MANAGER,
    M7EvidenceError,
    validate_cell_outcome,
    validate_matrix,
)

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64
_COMMIT = "c" * 40


def _call(operation: str) -> dict[str, object]:
    return {
        "operation": operation,
        "returncode": 0,
        "ok": True,
        "stdout_sha256": _DIGEST,
        "stderr_sha256": _DIGEST,
    }


def _provider_journey(provider: str, *, j01: bool) -> dict[str, object]:
    value: dict[str, object] = {
        "status": "PASS",
        "provider_id": provider,
        "project_created": True,
        "baseline_revision": 8,
        "plan_approved": True,
        "envelope_approved": True,
        "interaction_live": True,
        "execution_live": True,
        "workspace_isolated": True,
        "runstore_durable": True,
        "validation_recorded": True,
        "provider_self_accepted": False,
        "acceptance_authority_separate": True,
        "project_authority_promoted": True,
        "promotion_revision": 9,
        "documentation_current": True,
        "dashboard_current": True,
        "role_certifications": {
            "INTERACTION": "LIVE_ROLE_CERTIFIED",
            "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
        },
    }
    if j01:
        value.update({"frontend_closed_during_run": True, "reconnect_observed_run": True})
    return value


def _provider_calls(*, codex: bool) -> list[dict[str, object]]:
    operations = [
        "service.status",
        "project.create",
        "distribution.setup.plan",
        "distribution.setup.apply",
        "distribution.bootstrap",
        "distribution.doctor",
        "providers.graph",
        "providers.readiness",
        "providers.interact",
        "governance.envelope.propose",
        "governance.envelope.approve",
        "runtime.run.authorize",
        "runtime.workspace.create",
        "runtime.provider.execute",
        "runtime.status",
        "runtime.accept",
        "runtime.workspace.promote",
        "providers.certifications",
        "documentation.status",
        "dashboard.project",
    ]
    if codex:
        operations.append("runtime.status")
    return [_call(operation) for operation in operations]


def _outcome(cell_id: str) -> dict[str, Any]:
    contract = CELL_CONTRACTS[cell_id]
    provider_id = str(contract["provider"])
    provider: dict[str, object]
    journeys: dict[str, object]
    if provider_id == "none":
        provider = {
            "id": "none",
            "codex_present": False,
            "claude_present": False,
            "automated_candidates": [],
            "credential_files_read": False,
            "pii_persisted": False,
        }
        journeys = {
            "J10": {
                "status": "PASS",
                "automated_candidates": [],
                "no_false_automated_ready": True,
                "bootstrap_status": "MANUAL_FALLBACK",
                "manual_fallback_selected": True,
                "doctor_actionable": True,
                "beginner_start_succeeded": True,
                "manual_operations": [
                    "manual.packet.create",
                    "manual.result.submit",
                ],
                "manual_result_self_accepted": False,
                "automated_dispatch_occurred": False,
            }
        }
        calls = [
            _call(operation)
            for operation in (
                "service.status",
                "distribution.bootstrap",
                "distribution.doctor",
                "providers.graph",
                "beginner.start",
                "manual.packet.create",
                "manual.result.submit",
            )
        ]
        probe_names = (
            "host",
            "installed_origin",
            "service_status",
            "bootstrap",
            "doctor",
            "graph",
        )
    else:
        provider = {
            "id": provider_id,
            "installed": True,
            "other_core_provider_absent": True,
            "configured": True,
            "authenticated": True,
            "version": "qualified-version",
            "executable_sha256": _DIGEST,
            "auth_probe_sha256": _DIGEST,
            "readiness_state": "AVAILABLE",
            "credential_files_read": False,
            "pii_persisted": False,
        }
        journey_id = "J01" if provider_id == "codex" else "J02"
        journeys = {
            journey_id: _provider_journey(provider_id, j01=provider_id == "codex"),
            "J16": {
                "status": "PASS",
                "provider_id": provider_id,
                "setup_sha256": _DIGEST,
                "fresh_process_consumed_setup": True,
                "provider_registered_after_consumption": True,
                "service_generation_advanced": True,
                "service_process_changed": True,
                "custom_injection_used": False,
            },
        }
        calls = _provider_calls(codex=provider_id == "codex")
        probe_names = (
            "host",
            "installed_origin",
            "service_status",
            "bootstrap",
            "doctor",
            "graph",
            "readiness",
        )
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "cell": {
            "id": cell_id,
            "os": "Windows 11",
            "display_version": "25H2",
            "architecture": "x86_64",
            "support_tier": "CORE",
            "mode": "STANDALONE",
            "provider": provider_id,
            "absent_providers": list(contract["absent_providers"]),
            "journeys": list(contract["journeys"]),
        },
        "candidate": {
            "source_commit": _COMMIT,
            "artifact_name": "artifex-2.0.0-windows-x64.exe",
            "artifact_sha256": _DIGEST,
            "artifact_bytes": 100,
            "contract_digest": M7_CONTRACT_DIGEST,
            "product_disposition_sha256": _DIGEST,
        },
        "clean_machine": {
            "snapshot_identity_sha256": _DIGEST,
            "first_boot": True,
            "prior_artifex_absent": True,
            "prior_service_absent": True,
            "prior_state_root_absent": True,
            "source_checkout_absent": True,
            "os_build": "26200",
            "ubr": 1234,
        },
        "composition": {
            "shipping_installer": True,
            "public_managed_service": True,
            "public_cli": True,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "atlas_present": False,
            "combined_provider_cell": False,
        },
        "installer_service": {
            "install_status": "PASS",
            "registration_status": "PASS",
            "os_service_manager": WINDOWS_SERVICE_MANAGER,
            "registration_manifest_sha256": _DIGEST,
            "executable_sha256": _DIGEST,
            "service_start_status": "PASS",
            "frontend_independent": True,
            "authenticated_loopback_transport": True,
            "restart_generation_before": 1,
            "restart_generation_after": 2,
            "service_process_changed": True,
            "doctor_secret_safe": True,
        },
        "provider": provider,
        "journeys": journeys,
        "security": {
            "credential_files_read": False,
            "pii_persisted": False,
            "transport_token_persisted": False,
            "provider_result_self_acceptance": False,
            "acceptance_authority_separate": True,
            "project_authority_required": True,
        },
        "public_process_calls": calls,
        "transcript": {
            "sha256": _DIGEST,
            "bytes": 200,
            "raw_output_persisted": False,
            "secret_scan": "PASS",
        },
        "qualifier_probes": {name: _DIGEST for name in probe_names},
    }


def test_qualifier_and_validator_import_no_product_modules() -> None:
    root = Path(__file__).parents[2]
    for name in ("qualify_m7_windows.py", "validate_m7.py"):
        tree = ast.parse((root / "tools" / "artifex2" / name).read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert not any(item == "artifex" or item.startswith("artifex.") for item in imported)


def test_exact_three_cell_matrix_passes_and_binds_same_artifact() -> None:
    result = validate_matrix([_outcome(cell_id) for cell_id in CELL_CONTRACTS])

    assert result["status"] == "PASS"
    assert result["selected_windows_version"] == "25H2"
    assert result["selected_windows_build"] == "26200"
    assert set(result["cells"]) == set(CELL_CONTRACTS)
    assert result["journeys"] == {
        "J01": "PASS",
        "J02": "PASS",
        "J10": "PASS",
        "J16": "PASS",
    }
    assert result["combined_provider_cell_claimed"] is False


@pytest.mark.parametrize(
    ("path", "bad_value"),
    [
        (("cell", "display_version"), "23H2"),
        (("cell", "architecture"), "arm64"),
        (("composition", "source_tree_imported"), True),
        (("composition", "custom_application_factory_used"), True),
        (("composition", "provider_injection_used"), True),
        (("composition", "simulated_provider"), True),
        (("composition", "combined_provider_cell"), True),
    ],
)
def test_cell_rejects_wrong_platform_or_prohibited_composition(
    path: tuple[str, str], bad_value: object
) -> None:
    value = _outcome("M7-WIN-CODEX")
    value[path[0]][path[1]] = bad_value

    with pytest.raises(M7EvidenceError):
        validate_cell_outcome(value)


def test_provider_cell_separation_is_exact() -> None:
    _enforce_provider_separation(
        "M7-WIN-CODEX", which=lambda name: f"C:/{name}.exe" if name == "codex" else None
    )
    with pytest.raises(M7EvidenceError, match="forbidden provider"):
        _enforce_provider_separation("M7-WIN-CODEX", which=lambda name: f"C:/{name}.exe")
    with pytest.raises(M7EvidenceError, match="no-provider"):
        _enforce_provider_separation(
            "M7-WIN-NOPROVIDER",
            which=lambda name: f"C:/{name}.exe" if name == "claude" else None,
        )


def test_live_host_gate_defaults_to_exact_windows_11_25h2_build_26200_x64() -> None:
    identity = {
        "system": "Windows",
        "release": "11",
        "product_name": "Windows 11 Pro",
        "display_version": "25H2",
        "architecture": "x86_64",
        "os_build": "26200",
        "ubr": 1234,
    }
    _enforce_official_host(identity)
    stale = {**identity, "display_version": "23H2"}
    with pytest.raises(M7EvidenceError, match="25H2"):
        _enforce_official_host(stale)
    wrong_build = {**identity, "os_build": "26100"}
    with pytest.raises(M7EvidenceError, match="26200"):
        _enforce_official_host(wrong_build)


def test_declared_24h2_policy_remains_eligible_only_when_selected_exactly() -> None:
    assert ELIGIBLE_WINDOWS_VERSIONS == {"24H2": "26100", "25H2": "26200"}
    assert DEFAULT_WINDOWS_VERSION == "25H2"
    assert DEFAULT_WINDOWS_BUILD == "26200"
    value = _outcome("M7-WIN-CODEX")
    value["cell"]["display_version"] = "24H2"
    value["clean_machine"]["os_build"] = "26100"
    identity = {
        "system": "Windows",
        "release": "11",
        "product_name": "Windows 11 Pro",
        "display_version": "24H2",
        "architecture": "x86_64",
        "os_build": "26100",
        "ubr": 1234,
    }

    _enforce_official_host(identity, selected_version="24H2", selected_build="26100")
    validate_cell_outcome(
        value,
        selected_version="24H2",
        selected_build="26100",
    )
    with pytest.raises(M7EvidenceError, match="display_version"):
        validate_cell_outcome(value)


def test_policy_rejects_undeclared_version_and_version_build_mismatch() -> None:
    value = _outcome("M7-WIN-CODEX")
    with pytest.raises(M7EvidenceError, match="not eligible"):
        validate_cell_outcome(value, selected_version="26H2", selected_build="26300")
    with pytest.raises(M7EvidenceError, match="exact build 26200"):
        validate_cell_outcome(value, selected_version="25H2", selected_build="26100")


def test_matrix_rejects_artifact_drift_and_missing_cell() -> None:
    values = [_outcome(cell_id) for cell_id in CELL_CONTRACTS]
    values[1]["candidate"]["artifact_sha256"] = _OTHER_DIGEST
    with pytest.raises(M7EvidenceError, match="same candidate artifact_sha256"):
        validate_matrix(values)
    with pytest.raises(M7EvidenceError, match="exactly three"):
        validate_matrix(values[:2])


def test_incomplete_journey_or_public_call_cannot_pass() -> None:
    value = _outcome("M7-WIN-CLAUDE")
    del value["journeys"]["J02"]["execution_live"]
    with pytest.raises(M7EvidenceError, match="fields invalid"):
        validate_cell_outcome(value)

    value = _outcome("M7-WIN-NOPROVIDER")
    value["public_process_calls"] = [
        item
        for item in value["public_process_calls"]
        if item["operation"] != "manual.packet.create"
    ]
    with pytest.raises(M7EvidenceError, match="incomplete"):
        validate_cell_outcome(value)


def test_secret_bearing_keys_and_self_issued_probe_shape_fail_closed() -> None:
    value = _outcome("M7-WIN-CODEX")
    value["security"]["api_key"] = "must-not-persist"
    with pytest.raises(M7EvidenceError, match="secret-bearing"):
        validate_cell_outcome(value)

    value = _outcome("M7-WIN-CODEX")
    value["provider"]["other_core_provider_absent"] = False
    with pytest.raises(M7EvidenceError):
        validate_cell_outcome(value)


def test_each_provider_must_pass_j16_independently() -> None:
    for cell_id in ("M7-WIN-CODEX", "M7-WIN-CLAUDE"):
        value = _outcome(cell_id)
        value["journeys"]["J16"]["fresh_process_consumed_setup"] = False
        with pytest.raises(M7EvidenceError, match="fresh_process_consumed_setup"):
            validate_cell_outcome(value)


def test_validator_does_not_mutate_input() -> None:
    value = _outcome("M7-WIN-NOPROVIDER")
    original = deepcopy(value)
    validate_cell_outcome(value)
    assert value == original
