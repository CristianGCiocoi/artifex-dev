"""Validate the official three-cell ARTIFEX 2.0 M7 Windows matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

M7_CONTRACT_DIGEST = "3eac41de4cacf7be80aab12e478b99ec7c5066dccddfff6ca00a03cf5a157d48"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ELIGIBLE_WINDOWS_VERSIONS: dict[str, str] = {
    "24H2": "26100",
    "25H2": "26200",
}
DEFAULT_WINDOWS_VERSION = "25H2"
DEFAULT_WINDOWS_BUILD = ELIGIBLE_WINDOWS_VERSIONS[DEFAULT_WINDOWS_VERSION]
WINDOWS_SERVICE_MANAGER = "WINDOWS_TASK_SCHEDULER_PER_USER"

CELL_CONTRACTS: dict[str, dict[str, object]] = {
    "M7-WIN-CODEX": {
        "provider": "codex",
        "absent_providers": ["claude"],
        "journeys": ["J01", "J16"],
    },
    "M7-WIN-CLAUDE": {
        "provider": "claude",
        "absent_providers": ["codex"],
        "journeys": ["J02", "J16"],
    },
    "M7-WIN-NOPROVIDER": {
        "provider": "none",
        "absent_providers": ["claude", "codex"],
        "journeys": ["J10"],
    },
}

_SENSITIVE_KEYS = re.compile(
    r"^(?:access_token|refresh_token|authorization|password|api_key|secret|"
    r"secret_value|credential_value|account_email|user_email)$",
    re.IGNORECASE,
)


class M7EvidenceError(ValueError):
    """Raised when evidence could overstate the qualified M7 outcome."""


def _selected_windows_target(version: str, build: str | None) -> tuple[str, str]:
    if version not in ELIGIBLE_WINDOWS_VERSIONS:
        eligible = ", ".join(ELIGIBLE_WINDOWS_VERSIONS)
        raise M7EvidenceError(f"Windows version is not eligible; expected one of: {eligible}")
    expected_build = ELIGIBLE_WINDOWS_VERSIONS[version]
    selected_build = expected_build if build is None else build
    if selected_build != expected_build:
        raise M7EvidenceError(
            f"Windows {version} qualification must bind exact build {expected_build}"
        )
    return version, selected_build


def canonical_sha256(value: object) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(rendered).hexdigest()


def validate_cell_outcome(
    value: Mapping[str, Any],
    *,
    expected_cell: str | None = None,
    selected_version: str = DEFAULT_WINDOWS_VERSION,
    selected_build: str | None = None,
) -> dict[str, Any]:
    selected_version, selected_build = _selected_windows_target(selected_version, selected_build)
    _exact_keys(
        value,
        {
            "schema_version",
            "status",
            "cell",
            "candidate",
            "clean_machine",
            "composition",
            "installer_service",
            "provider",
            "journeys",
            "security",
            "public_process_calls",
            "transcript",
            "qualifier_probes",
        },
        "cell outcome",
    )
    _equal(value.get("schema_version"), "1.0", "cell schema_version")
    _equal(value.get("status"), "PASS", "cell status")
    _assert_secret_safe(value)

    cell = _mapping(value.get("cell"), "cell")
    _exact_keys(
        cell,
        {
            "id",
            "os",
            "display_version",
            "architecture",
            "support_tier",
            "mode",
            "provider",
            "absent_providers",
            "journeys",
        },
        "cell identity",
    )
    cell_id = _text(cell.get("id"), "cell.id")
    if cell_id not in CELL_CONTRACTS:
        raise M7EvidenceError(f"unsupported M7 cell: {cell_id}")
    if expected_cell is not None and cell_id != expected_cell:
        raise M7EvidenceError(f"expected {expected_cell}, observed {cell_id}")
    contract = CELL_CONTRACTS[cell_id]
    _equal(cell.get("os"), "Windows 11", "cell.os")
    _equal(cell.get("display_version"), selected_version, "cell.display_version")
    _equal(cell.get("architecture"), "x86_64", "cell.architecture")
    _equal(cell.get("support_tier"), "CORE", "cell.support_tier")
    _equal(cell.get("mode"), "STANDALONE", "cell.mode")
    _equal(cell.get("provider"), contract["provider"], "cell.provider")
    _equal(
        _text_list(cell.get("absent_providers"), "cell.absent_providers"),
        contract["absent_providers"],
        "cell.absent_providers",
    )
    _equal(
        _text_list(cell.get("journeys"), "cell.journeys"),
        contract["journeys"],
        "cell.journeys",
    )

    _validate_candidate(_mapping(value.get("candidate"), "candidate"))
    _validate_clean_machine(
        _mapping(value.get("clean_machine"), "clean_machine"),
        selected_build=selected_build,
    )
    _validate_composition(_mapping(value.get("composition"), "composition"))
    _validate_installer_service(_mapping(value.get("installer_service"), "installer_service"))
    _validate_provider(_mapping(value.get("provider"), "provider"), cell_id)
    _validate_journeys(_mapping(value.get("journeys"), "journeys"), cell_id)
    _validate_security(_mapping(value.get("security"), "security"))
    _validate_calls(_sequence(value.get("public_process_calls"), "public_process_calls"), cell_id)
    _validate_transcript(_mapping(value.get("transcript"), "transcript"))
    _validate_qualifier_probes(_mapping(value.get("qualifier_probes"), "qualifier_probes"), cell_id)
    return {"cell_id": cell_id, "outcome_sha256": canonical_sha256(value)}


def validate_matrix(
    outcomes: Sequence[Mapping[str, Any]],
    *,
    selected_version: str = DEFAULT_WINDOWS_VERSION,
    selected_build: str | None = None,
) -> dict[str, Any]:
    selected_version, selected_build = _selected_windows_target(selected_version, selected_build)
    if len(outcomes) != 3:
        raise M7EvidenceError("M7 Windows matrix requires exactly three outcomes")
    validated = [
        validate_cell_outcome(
            item,
            selected_version=selected_version,
            selected_build=selected_build,
        )
        for item in outcomes
    ]
    by_id = {str(item["cell_id"]): value for item, value in zip(validated, outcomes, strict=True)}
    if set(by_id) != set(CELL_CONTRACTS) or len(by_id) != 3:
        raise M7EvidenceError("M7 Windows matrix cell IDs are missing or duplicated")
    candidates = [_mapping(value["candidate"], "candidate") for value in by_id.values()]
    for field in ("source_commit", "artifact_name", "artifact_sha256", "artifact_bytes"):
        observed = {json.dumps(candidate[field], sort_keys=True) for candidate in candidates}
        if len(observed) != 1:
            raise M7EvidenceError(f"all M7 cells must use the same candidate {field}")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "matrix": f"M7_WINDOWS_11_{selected_version}_X86_64_CORE_STANDALONE",
        "selected_windows_version": selected_version,
        "selected_windows_build": selected_build,
        "cells": {
            item["cell_id"]: item["outcome_sha256"]
            for item in sorted(validated, key=lambda candidate: str(candidate["cell_id"]))
        },
        "candidate": {
            key: candidates[0][key]
            for key in ("source_commit", "artifact_name", "artifact_sha256", "artifact_bytes")
        },
        "journeys": {"J01": "PASS", "J02": "PASS", "J10": "PASS", "J16": "PASS"},
        "linux_macos_required_by_m7_disposition": False,
        "combined_provider_cell_claimed": False,
    }


def _validate_candidate(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "source_commit",
            "artifact_name",
            "artifact_sha256",
            "artifact_bytes",
            "contract_digest",
            "product_disposition_sha256",
        },
        "candidate",
    )
    if not COMMIT.fullmatch(_text(value.get("source_commit"), "candidate.source_commit")):
        raise M7EvidenceError("candidate.source_commit must be a full Git SHA-1")
    _text(value.get("artifact_name"), "candidate.artifact_name")
    _digest(value.get("artifact_sha256"), "candidate.artifact_sha256")
    _positive_int(value.get("artifact_bytes"), "candidate.artifact_bytes")
    _equal(value.get("contract_digest"), M7_CONTRACT_DIGEST, "candidate.contract_digest")
    _digest(value.get("product_disposition_sha256"), "candidate.product_disposition_sha256")


def _validate_clean_machine(value: Mapping[str, Any], *, selected_build: str) -> None:
    _exact_keys(
        value,
        {
            "snapshot_identity_sha256",
            "first_boot",
            "prior_artifex_absent",
            "prior_service_absent",
            "prior_state_root_absent",
            "source_checkout_absent",
            "os_build",
            "ubr",
        },
        "clean_machine",
    )
    _digest(value.get("snapshot_identity_sha256"), "clean_machine.snapshot_identity_sha256")
    for field in (
        "first_boot",
        "prior_artifex_absent",
        "prior_service_absent",
        "prior_state_root_absent",
        "source_checkout_absent",
    ):
        _true(value.get(field), f"clean_machine.{field}")
    _equal(value.get("os_build"), selected_build, "clean_machine.os_build")
    _nonnegative_int(value.get("ubr"), "clean_machine.ubr")


def _validate_composition(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "shipping_installer",
            "public_managed_service",
            "public_cli",
            "source_tree_imported",
            "custom_application_factory_used",
            "provider_injection_used",
            "simulated_provider",
            "atlas_present",
            "combined_provider_cell",
        },
        "composition",
    )
    for field in ("shipping_installer", "public_managed_service", "public_cli"):
        _true(value.get(field), f"composition.{field}")
    for field in (
        "source_tree_imported",
        "custom_application_factory_used",
        "provider_injection_used",
        "simulated_provider",
        "atlas_present",
        "combined_provider_cell",
    ):
        _false(value.get(field), f"composition.{field}")


def _validate_installer_service(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "install_status",
            "registration_status",
            "os_service_manager",
            "registration_manifest_sha256",
            "executable_sha256",
            "service_start_status",
            "frontend_independent",
            "authenticated_loopback_transport",
            "restart_generation_before",
            "restart_generation_after",
            "service_process_changed",
            "doctor_secret_safe",
        },
        "installer_service",
    )
    for field in ("install_status", "registration_status", "service_start_status"):
        _equal(value.get(field), "PASS", f"installer_service.{field}")
    _equal(
        value.get("os_service_manager"),
        WINDOWS_SERVICE_MANAGER,
        "installer_service.os_service_manager",
    )
    _digest(
        value.get("registration_manifest_sha256"),
        "installer_service.registration_manifest_sha256",
    )
    _digest(value.get("executable_sha256"), "installer_service.executable_sha256")
    for field in (
        "frontend_independent",
        "authenticated_loopback_transport",
        "service_process_changed",
        "doctor_secret_safe",
    ):
        _true(value.get(field), f"installer_service.{field}")
    before = _positive_int(
        value.get("restart_generation_before"),
        "installer_service.restart_generation_before",
    )
    after = _positive_int(
        value.get("restart_generation_after"),
        "installer_service.restart_generation_after",
    )
    if after <= before:
        raise M7EvidenceError("service restart must advance coordinator generation")


def _validate_provider(value: Mapping[str, Any], cell_id: str) -> None:
    expected = str(CELL_CONTRACTS[cell_id]["provider"])
    if expected == "none":
        _exact_keys(
            value,
            {
                "id",
                "codex_present",
                "claude_present",
                "automated_candidates",
                "credential_files_read",
                "pii_persisted",
            },
            "provider",
        )
        _equal(value.get("id"), "none", "provider.id")
        _false(value.get("codex_present"), "provider.codex_present")
        _false(value.get("claude_present"), "provider.claude_present")
        _equal(value.get("automated_candidates"), [], "provider.automated_candidates")
    else:
        _exact_keys(
            value,
            {
                "id",
                "installed",
                "other_core_provider_absent",
                "configured",
                "authenticated",
                "version",
                "executable_sha256",
                "auth_probe_sha256",
                "readiness_state",
                "credential_files_read",
                "pii_persisted",
            },
            "provider",
        )
        _equal(value.get("id"), expected, "provider.id")
        for field in ("installed", "other_core_provider_absent", "configured", "authenticated"):
            _true(value.get(field), f"provider.{field}")
        _text(value.get("version"), "provider.version")
        _digest(value.get("executable_sha256"), "provider.executable_sha256")
        _digest(value.get("auth_probe_sha256"), "provider.auth_probe_sha256")
        _equal(value.get("readiness_state"), "AVAILABLE", "provider.readiness_state")
    _false(value.get("credential_files_read"), "provider.credential_files_read")
    _false(value.get("pii_persisted"), "provider.pii_persisted")


def _validate_journeys(value: Mapping[str, Any], cell_id: str) -> None:
    required = set(_text_list(CELL_CONTRACTS[cell_id]["journeys"], "cell contract journeys"))
    _exact_keys(value, required, "journeys")
    if "J01" in required:
        _validate_provider_journey(_mapping(value["J01"], "J01"), "codex", j01=True)
    if "J02" in required:
        _validate_provider_journey(_mapping(value["J02"], "J02"), "claude", j01=False)
    if "J16" in required:
        _validate_j16(_mapping(value["J16"], "J16"), str(CELL_CONTRACTS[cell_id]["provider"]))
    if "J10" in required:
        _validate_j10(_mapping(value["J10"], "J10"))


def _validate_provider_journey(value: Mapping[str, Any], provider: str, *, j01: bool) -> None:
    fields = {
        "status",
        "provider_id",
        "project_created",
        "baseline_revision",
        "plan_approved",
        "envelope_approved",
        "interaction_live",
        "execution_live",
        "workspace_isolated",
        "runstore_durable",
        "validation_recorded",
        "provider_self_accepted",
        "acceptance_authority_separate",
        "project_authority_promoted",
        "promotion_revision",
        "documentation_current",
        "dashboard_current",
        "role_certifications",
    }
    if j01:
        fields |= {"frontend_closed_during_run", "reconnect_observed_run"}
    _exact_keys(value, fields, "provider journey")
    _equal(value.get("status"), "PASS", "provider journey status")
    _equal(value.get("provider_id"), provider, "provider journey provider_id")
    for field in (
        "project_created",
        "plan_approved",
        "envelope_approved",
        "interaction_live",
        "execution_live",
        "workspace_isolated",
        "runstore_durable",
        "validation_recorded",
        "acceptance_authority_separate",
        "project_authority_promoted",
        "documentation_current",
        "dashboard_current",
    ):
        _true(value.get(field), f"provider journey {field}")
    _false(value.get("provider_self_accepted"), "provider journey provider_self_accepted")
    if j01:
        _true(value.get("frontend_closed_during_run"), "J01 frontend_closed_during_run")
        _true(value.get("reconnect_observed_run"), "J01 reconnect_observed_run")
    baseline = _positive_int(value.get("baseline_revision"), "provider journey baseline_revision")
    promotion = _positive_int(
        value.get("promotion_revision"), "provider journey promotion_revision"
    )
    if promotion != baseline + 1:
        raise M7EvidenceError("provider journey promotion must advance exactly one revision")
    _equal(
        value.get("role_certifications"),
        {
            "INTERACTION": "LIVE_ROLE_CERTIFIED",
            "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
        },
        "provider journey role_certifications",
    )


def _validate_j16(value: Mapping[str, Any], provider: str) -> None:
    _exact_keys(
        value,
        {
            "status",
            "provider_id",
            "setup_sha256",
            "fresh_process_consumed_setup",
            "provider_registered_after_consumption",
            "service_generation_advanced",
            "service_process_changed",
            "custom_injection_used",
        },
        "J16",
    )
    _equal(value.get("status"), "PASS", "J16 status")
    _equal(value.get("provider_id"), provider, "J16 provider_id")
    _digest(value.get("setup_sha256"), "J16 setup_sha256")
    for field in (
        "fresh_process_consumed_setup",
        "provider_registered_after_consumption",
        "service_generation_advanced",
        "service_process_changed",
    ):
        _true(value.get(field), f"J16 {field}")
    _false(value.get("custom_injection_used"), "J16 custom_injection_used")


def _validate_j10(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "status",
            "automated_candidates",
            "no_false_automated_ready",
            "bootstrap_status",
            "manual_fallback_selected",
            "doctor_actionable",
            "beginner_start_succeeded",
            "manual_operations",
            "manual_result_self_accepted",
            "automated_dispatch_occurred",
        },
        "J10",
    )
    _equal(value.get("status"), "PASS", "J10 status")
    _equal(value.get("automated_candidates"), [], "J10 automated_candidates")
    for field in (
        "no_false_automated_ready",
        "manual_fallback_selected",
        "doctor_actionable",
        "beginner_start_succeeded",
    ):
        _true(value.get(field), f"J10 {field}")
    _equal(value.get("bootstrap_status"), "MANUAL_FALLBACK", "J10 bootstrap_status")
    _equal(
        value.get("manual_operations"),
        ["manual.packet.create", "manual.result.submit"],
        "J10 manual_operations",
    )
    _false(value.get("manual_result_self_accepted"), "J10 manual_result_self_accepted")
    _false(value.get("automated_dispatch_occurred"), "J10 automated_dispatch_occurred")


def _validate_security(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "credential_files_read",
            "pii_persisted",
            "transport_token_persisted",
            "provider_result_self_acceptance",
            "acceptance_authority_separate",
            "project_authority_required",
        },
        "security",
    )
    for field in (
        "credential_files_read",
        "pii_persisted",
        "transport_token_persisted",
        "provider_result_self_acceptance",
    ):
        _false(value.get(field), f"security.{field}")
    _true(value.get("acceptance_authority_separate"), "security.acceptance_authority_separate")
    _true(value.get("project_authority_required"), "security.project_authority_required")


def _validate_calls(values: Sequence[Any], cell_id: str) -> None:
    calls: list[str] = []
    for index, item in enumerate(values):
        call = _mapping(item, f"public_process_calls[{index}]")
        _exact_keys(
            call,
            {"operation", "returncode", "ok", "stdout_sha256", "stderr_sha256"},
            "public process call",
        )
        operation = _text(call.get("operation"), "public process operation")
        calls.append(operation)
        _equal(call.get("returncode"), 0, f"{operation} returncode")
        _true(call.get("ok"), f"{operation} ok")
        _digest(call.get("stdout_sha256"), f"{operation} stdout_sha256")
        _digest(call.get("stderr_sha256"), f"{operation} stderr_sha256")
    common = {"service.status", "distribution.bootstrap", "distribution.doctor"}
    if cell_id == "M7-WIN-NOPROVIDER":
        required = common | {
            "providers.graph",
            "beginner.start",
            "manual.packet.create",
            "manual.result.submit",
        }
    else:
        required = common | {
            "project.create",
            "distribution.setup.plan",
            "distribution.setup.apply",
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
        }
    missing = sorted(required - set(calls))
    if missing:
        raise M7EvidenceError(f"public process calls are incomplete: {', '.join(missing)}")
    if cell_id == "M7-WIN-CODEX" and calls.count("runtime.status") < 2:
        raise M7EvidenceError("J01 requires runtime status before and after frontend reconnect")


def _validate_transcript(value: Mapping[str, Any]) -> None:
    _exact_keys(value, {"sha256", "bytes", "raw_output_persisted", "secret_scan"}, "transcript")
    _digest(value.get("sha256"), "transcript.sha256")
    _positive_int(value.get("bytes"), "transcript.bytes")
    _false(value.get("raw_output_persisted"), "transcript.raw_output_persisted")
    _equal(value.get("secret_scan"), "PASS", "transcript.secret_scan")


def _validate_qualifier_probes(value: Mapping[str, Any], cell_id: str) -> None:
    required = {"host", "installed_origin", "service_status", "bootstrap", "doctor", "graph"}
    if cell_id != "M7-WIN-NOPROVIDER":
        required.add("readiness")
    _exact_keys(value, required, "qualifier_probes")
    for name, digest in value.items():
        _digest(digest, f"qualifier_probes.{name}")


def _assert_secret_safe(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key)
            if _SENSITIVE_KEYS.fullmatch(name):
                raise M7EvidenceError(f"secret-bearing evidence key is forbidden: {path}.{name}")
            _assert_secret_safe(child, f"{path}.{name}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _assert_secret_safe(child, f"{path}[{index}]")


def _exact_keys(value: Mapping[str, Any], required: set[str], name: str) -> None:
    observed = set(value)
    if observed != required:
        missing = sorted(required - observed)
        extra = sorted(observed - required)
        raise M7EvidenceError(f"{name} fields invalid; missing={missing}, extra={extra}")


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise M7EvidenceError(f"{name} must be an object")
    return value


def _sequence(value: object, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise M7EvidenceError(f"{name} must be an array")
    return value


def _text_list(value: object, name: str) -> list[str]:
    result = list(_sequence(value, name))
    if any(not isinstance(item, str) or not item for item in result):
        raise M7EvidenceError(f"{name} must contain non-empty strings")
    return result


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise M7EvidenceError(f"{name} must be a non-empty string")
    return value


def _digest(value: object, name: str) -> str:
    observed = _text(value, name)
    if not SHA256.fullmatch(observed):
        raise M7EvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return observed


def _positive_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise M7EvidenceError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise M7EvidenceError(f"{name} must be a non-negative integer")
    return value


def _true(value: object, name: str) -> None:
    _equal(value, True, name)


def _false(value: object, name: str) -> None:
    _equal(value, False, name)


def _equal(value: object, expected: object, name: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise M7EvidenceError(f"{name} must equal {expected!r}")


def _read_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return _mapping(value, str(path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell-outcome", action="append", type=Path, required=True)
    parser.add_argument(
        "--selected-version",
        choices=tuple(ELIGIBLE_WINDOWS_VERSIONS),
        default=DEFAULT_WINDOWS_VERSION,
    )
    parser.add_argument("--selected-build")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = validate_matrix(
            [_read_object(path) for path in arguments.cell_outcome],
            selected_version=arguments.selected_version,
            selected_build=arguments.selected_build,
        )
    except (OSError, json.JSONDecodeError, M7EvidenceError) as exc:
        result = {"schema_version": "1.0", "status": "FAIL", "error": type(exc).__name__}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
