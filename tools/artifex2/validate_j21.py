"""Fail-closed validator for the ARTIFEX 2.0.2 non-CLI J21 receipt."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

J21_EVIDENCE_SCHEMA = "artifex.j21-qualification/v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class J21EvidenceError(ValueError):
    """Raised when a J21 receipt does not prove the frozen public outcome."""


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise J21EvidenceError(f"{label} must be an object")
    return value


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise J21EvidenceError(f"{label} must be a list")
    if not all(isinstance(item, str) and item for item in value):
        raise J21EvidenceError(f"{label} must contain non-empty strings")
    return list(value)


def required_stages(contract: Path) -> list[str]:
    value = _object(yaml.safe_load(contract.read_text(encoding="utf-8")), "J21 contract")
    if value.get("id") != "J21" or value.get("terminal_remediation_allowed") is not False:
        raise J21EvidenceError("J21 contract identity or terminal policy is invalid")
    return _strings(value.get("required_stages"), "J21 required stages")


def validate_j21(contract: Path, evidence: Path) -> dict[str, Any]:
    expected = required_stages(contract)
    value = _object(json.loads(evidence.read_text(encoding="utf-8")), "J21 evidence")
    if value.get("schema_version") != J21_EVIDENCE_SCHEMA:
        raise J21EvidenceError("J21 evidence schema is invalid")
    if value.get("journey") != "J21" or value.get("status") != "PASS":
        raise J21EvidenceError("J21 did not pass")
    candidate = _object(value.get("candidate"), "candidate")
    if not COMMIT.fullmatch(str(candidate.get("source_commit", ""))):
        raise J21EvidenceError("J21 source commit is invalid")
    for field in ("installer_sha256", "provenance_sha256"):
        if not SHA256.fullmatch(str(candidate.get(field, ""))):
            raise J21EvidenceError(f"J21 {field} is invalid")
    environment = _object(value.get("environment"), "environment")
    if (
        environment.get("os") != "Windows 11 24H2 x64"
        or environment.get("clean_vm") is not True
        or environment.get("defender_enabled") is not True
    ):
        raise J21EvidenceError("J21 environment is not the required clean Windows cell")
    if value.get("terminal_remediation_used") is not False:
        raise J21EvidenceError("J21 used forbidden terminal remediation")
    stages = _strings(value.get("completed_stages"), "completed stages")
    if stages != expected:
        raise J21EvidenceError("J21 stages are incomplete, reordered, or ambiguous")
    providers = _object(value.get("providers"), "providers")
    for provider in ("codex", "claude"):
        result = _object(providers.get(provider), provider)
        if (
            result.get("approval_shown") is not True
            or result.get("approval_recorded") is not True
            or result.get("live_read_only") != "PASS"
            or result.get("receipt_persisted") is not True
        ):
            raise J21EvidenceError(f"J21 {provider} integration is not accepted")
    for field in (
        "service_healthy_at_installer_finish",
        "platform_dashboard_user_launched",
        "project_dashboard_user_launched",
        "reboot_persistence_passed",
        "uninstall_passed",
        "retained_data_reported",
    ):
        if value.get(field) is not True:
            raise J21EvidenceError(f"J21 {field} is not proven")
    return {
        "journey": "J21",
        "status": "PASS",
        "source_commit": candidate["source_commit"],
        "stages": len(stages),
        "providers": ["codex", "claude"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = validate_j21(arguments.contract, arguments.evidence)
    except (OSError, json.JSONDecodeError, yaml.YAMLError, J21EvidenceError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "value": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
