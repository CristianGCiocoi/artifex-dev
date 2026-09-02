"""Fail-closed capture and validation for the non-CLI J21 journey.

The clean VM produces observations. Qualification runs afterwards and binds
them to the real shipping installer and its provenance; this module never
drives or repairs the product under test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

J21_CAPTURE_SCHEMA = "artifex.j21-capture/v1"
J21_EVIDENCE_SCHEMA = "artifex.j21-qualification/v2"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
EVIDENCE_KINDS = frozenset(
    {
        "SCREENSHOT",
        "SCREEN_RECORDING",
        "INSTALLER_LOG",
        "ARTIFEX_RECEIPT_EXPORT",
        "WINDOWS_EVENT_EXPORT",
        "FILE_INVENTORY",
        "SERVICE_STATUS_EXPORT",
        "CONFIGURATION_RECEIPT",
        "UNINSTALL_LOG",
    }
)
VISUAL_EVIDENCE = frozenset({"SCREENSHOT", "SCREEN_RECORDING"})
OUTCOMES = (
    "service_healthy_at_installer_finish",
    "platform_dashboard_user_launched",
    "project_dashboard_user_launched",
    "reboot_persistence_passed",
    "uninstall_passed",
    "installer_owned_resources_removed",
    "retained_data_reported",
)


class J21EvidenceError(ValueError):
    """Raised when a J21 capture does not prove the frozen public outcome."""


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise J21EvidenceError(f"{label} must be an object")
    return value


def _objects(value: Any, label: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise J21EvidenceError(f"{label} must be a list")
    return [_object(item, f"{label} item") for item in value]


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise J21EvidenceError(f"{label} must be a list")
    if not all(isinstance(item, str) and item for item in value):
        raise J21EvidenceError(f"{label} must contain non-empty strings")
    return list(value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, json.JSONDecodeError) as exc:
        raise J21EvidenceError(f"{label} is not readable JSON") from exc


def stage_contract(contract: Path) -> list[dict[str, str]]:
    value = _object(yaml.safe_load(contract.read_text(encoding="utf-8")), "J21 contract")
    if (
        value.get("id") != "J21"
        or value.get("terminal_remediation_allowed") is not False
        or value.get("capture_schema") != J21_CAPTURE_SCHEMA
        or value.get("qualification_schema") != J21_EVIDENCE_SCHEMA
    ):
        raise J21EvidenceError("J21 contract identity, schema, or terminal policy is invalid")
    stages = _strings(value.get("required_stages"), "J21 required stages")
    rows = _objects(value.get("stage_evidence"), "J21 stage evidence")
    normalized = [
        {"stage": str(row.get("stage", "")), "channel": str(row.get("channel", ""))} for row in rows
    ]
    if [row["stage"] for row in normalized] != stages or any(
        row["channel"] not in {"USER_UI_ACTION", "EVIDENCE_ONLY_INSPECTION"} for row in normalized
    ):
        raise J21EvidenceError("J21 stage evidence does not exactly match required stages")
    return normalized


def required_stages(contract: Path) -> list[str]:
    return [item["stage"] for item in stage_contract(contract)]


def _file(root: Path, item: Mapping[str, Any], label: str) -> dict[str, Any]:
    raw = str(item.get("path", ""))
    relative = PurePosixPath(raw)
    if not raw or relative.is_absolute() or ".." in relative.parts or "\\" in raw:
        raise J21EvidenceError(f"{label} path must be a normalized relative path")
    path = (root / Path(*relative.parts)).resolve()
    resolved_root = root.resolve()
    if path == resolved_root or resolved_root not in path.parents or not path.is_file():
        raise J21EvidenceError(f"{label} file is absent or outside the evidence root")
    kind = str(item.get("kind", ""))
    if kind not in EVIDENCE_KINDS:
        raise J21EvidenceError(f"{label} kind is invalid")
    actual = _sha256(path)
    if item.get("sha256") != actual:
        raise J21EvidenceError(f"{label} digest does not match the captured file")
    if item.get("contains_secret_material") is not False:
        raise J21EvidenceError(f"{label} is not attested secret-safe")
    return {
        "path": raw,
        "kind": kind,
        "sha256": actual,
        "bytes": path.stat().st_size,
        "contains_secret_material": False,
    }


def _candidate(value: Mapping[str, Any], installer: Path, provenance_path: Path) -> dict[str, Any]:
    commit = str(value.get("source_commit", ""))
    if not COMMIT.fullmatch(commit) or not installer.is_file() or not provenance_path.is_file():
        raise J21EvidenceError("J21 exact candidate files or source commit are invalid")
    installer_sha = _sha256(installer)
    provenance_sha = _sha256(provenance_path)
    if (
        value.get("installer_sha256") != installer_sha
        or value.get("provenance_sha256") != provenance_sha
    ):
        raise J21EvidenceError("J21 candidate digests do not match the supplied files")
    provenance = _json(provenance_path, "installer provenance")
    identity = _object(provenance.get("installer"), "provenance installer")
    if (
        provenance.get("schema_version") != "artifex.windows-installer-provenance/v1"
        or provenance.get("product") != "ARTIFEX"
        or provenance.get("source_commit") != commit
        or identity.get("name") != installer.name
        or identity.get("sha256") != installer_sha
        or identity.get("bytes") != installer.stat().st_size
    ):
        raise J21EvidenceError("J21 installer provenance differs from the exact candidate")
    return {
        "source_commit": commit,
        "product_version": str(provenance.get("product_version", "")),
        "installer_name": installer.name,
        "installer_sha256": installer_sha,
        "installer_bytes": installer.stat().st_size,
        "provenance_name": provenance_path.name,
        "provenance_sha256": provenance_sha,
    }


def _environment(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        value.get("os") != "Windows 11 24H2 x64"
        or value.get("clean_vm") is not True
        or value.get("defender_enabled") is not True
        or not str(value.get("vm_identity", "")).strip()
        or not str(value.get("snapshot_identity", "")).strip()
    ):
        raise J21EvidenceError("J21 environment is not the required identified clean Windows cell")
    return dict(value)


def _attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        value.get("shipping_artifact_only") is not True
        or value.get("secrets_excluded") is not True
        or any(
            value.get(field) is not False
            for field in (
                "source_checkout_used",
                "terminal_remediation_used",
                "manual_path_edit_used",
                "manual_vendor_configuration_edit_used",
            )
        )
    ):
        raise J21EvidenceError("J21 operator attestation permits a forbidden shortcut")
    return dict(value)


def _observations(
    expected: Sequence[Mapping[str, str]], value: Any, root: Path
) -> list[dict[str, Any]]:
    rows = _objects(value, "J21 observations")
    if len(rows) != len(expected):
        raise J21EvidenceError("J21 observations do not cover every required stage exactly once")
    normalized: list[dict[str, Any]] = []
    for number, (row, requirement) in enumerate(zip(rows, expected, strict=True), 1):
        stage, channel = requirement["stage"], requirement["channel"]
        if row.get("sequence") != number or row.get("stage") != stage:
            raise J21EvidenceError("J21 stages are incomplete, reordered, or ambiguous")
        if row.get("channel") != channel or row.get("status") != "PASS":
            raise J21EvidenceError(f"J21 stage {stage} channel or result is invalid")
        if row.get("remediation_performed") is not False or row.get("terminal_opened") is not False:
            raise J21EvidenceError(f"J21 stage {stage} used terminal remediation")
        observed_at = str(row.get("observed_at", ""))
        if not TIMESTAMP.fullmatch(observed_at):
            raise J21EvidenceError(f"J21 stage {stage} timestamp is invalid")
        artifacts = [
            _file(root, item, f"J21 stage {stage} evidence")
            for item in _objects(row.get("evidence"), f"J21 stage {stage} evidence")
        ]
        if not artifacts or (
            channel == "USER_UI_ACTION"
            and not any(item["kind"] in VISUAL_EVIDENCE for item in artifacts)
        ):
            raise J21EvidenceError(f"J21 stage {stage} lacks required captured evidence")
        normalized.append(
            {
                "sequence": number,
                "stage": stage,
                "channel": channel,
                "status": "PASS",
                "observed_at": observed_at,
                "remediation_performed": False,
                "terminal_opened": False,
                "evidence": artifacts,
            }
        )
    return normalized


def _providers(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for name in ("codex", "claude"):
        item = _object(value.get(name), name)
        if (
            not str(item.get("client_version", "")).strip()
            or not SHA256.fullmatch(str(item.get("receipt_sha256", "")))
            or item.get("approval_shown") is not True
            or item.get("approval_recorded") is not True
            or item.get("live_read_only") != "PASS"
            or item.get("receipt_persisted") is not True
        ):
            raise J21EvidenceError(f"J21 {name} integration is not accepted")
        normalized[name] = dict(item)
    return normalized


def _bind_provider_receipts(
    providers: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> None:
    by_stage = {str(item["stage"]): item for item in observations}
    for provider, stage in (
        ("codex", "CODEX_RECEIPT_PERSISTED"),
        ("claude", "CLAUDE_RECEIPT_PERSISTED"),
    ):
        receipt_sha = providers[provider]["receipt_sha256"]
        evidence = _objects(by_stage[stage].get("evidence"), f"J21 {provider} receipt evidence")
        if not any(item.get("sha256") == receipt_sha for item in evidence):
            raise J21EvidenceError(
                f"J21 {provider} persistent receipt is not bound to captured evidence"
            )


def _outcomes(value: Mapping[str, Any]) -> dict[str, bool]:
    if any(value.get(field) is not True for field in OUTCOMES):
        raise J21EvidenceError("J21 mandatory outcome is not proven")
    return {field: True for field in OUTCOMES}


def build_j21_evidence(
    contract: Path, capture_path: Path, installer: Path, provenance: Path, evidence_root: Path
) -> dict[str, Any]:
    expected = stage_contract(contract)
    capture = _json(capture_path, "J21 capture")
    if (
        capture.get("schema_version") != J21_CAPTURE_SCHEMA
        or capture.get("journey") != "J21"
        or capture.get("status") != "PASS"
    ):
        raise J21EvidenceError("J21 capture identity or result is invalid")
    observations = _observations(expected, capture.get("observations"), evidence_root)
    providers = _providers(_object(capture.get("providers"), "providers"))
    _bind_provider_receipts(providers, observations)
    return {
        "schema_version": J21_EVIDENCE_SCHEMA,
        "journey": "J21",
        "status": "PASS",
        "candidate": _candidate(
            _object(capture.get("candidate"), "candidate"), installer, provenance
        ),
        "environment": _environment(_object(capture.get("environment"), "environment")),
        "operator_attestation": _attestation(
            _object(capture.get("operator_attestation"), "operator attestation")
        ),
        "capture_manifest_sha256": _sha256(capture_path),
        "observations": observations,
        "completed_stages": [item["stage"] for item in observations],
        "providers": providers,
        "outcomes": _outcomes(_object(capture.get("outcomes"), "outcomes")),
    }


def validate_j21(
    contract: Path, evidence: Path, installer: Path, provenance: Path, evidence_root: Path
) -> dict[str, Any]:
    expected = stage_contract(contract)
    value = _json(evidence, "J21 evidence")
    if (
        value.get("schema_version") != J21_EVIDENCE_SCHEMA
        or value.get("journey") != "J21"
        or value.get("status") != "PASS"
    ):
        raise J21EvidenceError("J21 evidence identity or result is invalid")
    candidate = _candidate(_object(value.get("candidate"), "candidate"), installer, provenance)
    if dict(value.get("candidate", {})) != candidate:
        raise J21EvidenceError("J21 normalized candidate identity was altered")
    _environment(_object(value.get("environment"), "environment"))
    _attestation(_object(value.get("operator_attestation"), "operator attestation"))
    observations = _observations(expected, value.get("observations"), evidence_root)
    if value.get("completed_stages") != [item["stage"] for item in observations]:
        raise J21EvidenceError("J21 completed-stage summary differs from observations")
    providers = _providers(_object(value.get("providers"), "providers"))
    _bind_provider_receipts(providers, observations)
    _outcomes(_object(value.get("outcomes"), "outcomes"))
    return {
        "journey": "J21",
        "status": "PASS",
        "source_commit": candidate["source_commit"],
        "installer_sha256": candidate["installer_sha256"],
        "stages": len(observations),
        "providers": list(providers),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate exact J21 qualification evidence")
    for name in ("contract", "evidence", "installer", "provenance", "evidence-root"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate_j21(
            args.contract, args.evidence, args.installer, args.provenance, args.evidence_root
        )
    except (OSError, yaml.YAMLError, J21EvidenceError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "value": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
