"""Fail-closed validation for the M12 release matrix and J11/J20 evidence."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

M12_CONTRACT_DIGEST = "54529f748cac59ce8b57e2f9a8376fe51c515e0ffca6b0b7da51ae2cbc5a2c6a"
J20_SCHEMA = "artifex.m12-j20-qualification/v1"
MATRIX_SCHEMA = "artifex.m12-release-claim-matrix/v1"
COMPOSITION = "INSTALLED_NATIVE_PUBLIC_CLI_REAL_PROVIDER_MANAGED_SERVICE_MULTI_PROCESS"
TARGET_RELEASE = "2.0.0"
MANDATORY_JOURNEYS = (
    "J01",
    "J02",
    "J03",
    "J04",
    "J05",
    "J06",
    "J07",
    "J08",
    "J09",
    "J10",
    "J11",
    "J12",
    "J14",
    "J15",
    "J16",
    "J18",
    "J19",
    "J20",
)
CORE_CLAIMS = {
    "project_continuity": ("J03", "J04"),
    "persistent_supervised_autonomy": ("J05", "J06", "J07", "J18"),
    "semantic_safety": ("J14", "J15"),
    "provider_setup_persistence": ("J16",),
    "codex_support": ("J01", "J11"),
    "claude_support": ("J02", "J11"),
    "collaborative_lifecycle": ("J19",),
    "full_product": ("J20",),
    "documentation_dashboard": ("J08",),
    "v1_migration": ("J09",),
    "manual_fallback": ("J10",),
    "organizational_knowledge": ("J12",),
}
OPTIONAL_CLAIMS = {
    "hermes": "M6B",
    "pandora": "M8B",
    "deepseek": "M8C",
    "atlas_runtime": "M11",
    "linux_ga_certification": None,
    "macos_ga_certification": None,
}
EXACT_NATIVE_JOURNEYS = {"J01", "J02", "J09", "J10", "J11", "J16", "J20"}
ACCEPTANCE_CLASSES = {
    "DESIGN_CONFORMANCE",
    "COMPONENT",
    "DOMAIN_INTEGRATION",
    "PUBLIC_COMPOSITION",
    "BLACK_BOX_OUTCOME",
    "SECURITY_AUTHORITY",
    "DOCUMENTATION",
    "DASHBOARD",
    "MIGRATION",
    "PROVIDER_CERTIFICATION",
}
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_KEY = re.compile(
    r"^(?:access_token|refresh_token|authorization|password|api_key|secret|"
    r"secret_value|credential_value)$",
    re.IGNORECASE,
)


class M12EvidenceError(ValueError):
    """Raised when evidence could overstate an ARTIFEX 2.0 release claim."""


def _object(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise M12EvidenceError(f"{name} must be an object")
    return cast(Mapping[str, Any], value)


def _sequence(value: object, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise M12EvidenceError(f"{name} must be an array")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise M12EvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _equal(value: object, expected: object, name: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise M12EvidenceError(f"{name} must equal {expected!r}")


def _secret_safe(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _SENSITIVE_KEY.fullmatch(str(key)):
                raise M12EvidenceError(f"secret-bearing evidence key at {path}.{key}")
            _secret_safe(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _secret_safe(child, f"{path}[{index}]")


def validate_j20(
    value: Mapping[str, Any],
    *,
    expected_artifact_sha256: str,
    expected_source_commit: str,
) -> dict[str, Any]:
    _digest(expected_artifact_sha256, "expected artifact SHA-256")
    if not _COMMIT.fullmatch(expected_source_commit):
        raise M12EvidenceError("expected source commit must be a full Git SHA-1")
    _secret_safe(value)
    _equal(value.get("schema_version"), J20_SCHEMA, "J20 schema")
    _equal(value.get("status"), "PASS", "J20 evidence status")
    _equal(value.get("composition"), COMPOSITION, "J20 composition")
    for field in (
        "source_tree_imported",
        "custom_application_factory_used",
        "credential_material_read",
        "approval_tokens_retained",
    ):
        _equal(value.get(field), False, field)

    candidate = _object(value.get("candidate"), "candidate")
    _equal(candidate.get("artifact_sha256"), expected_artifact_sha256, "artifact hash")
    _equal(candidate.get("source_commit"), expected_source_commit, "source commit")
    _equal(candidate.get("product_version"), TARGET_RELEASE, "product version")
    if str(candidate.get("artifact_name", "")).casefold() != "artifex-setup.exe":
        raise M12EvidenceError("candidate artifact is not ARTIFEX-Setup.exe")
    artifact_bytes = candidate.get("artifact_bytes")
    if (
        not isinstance(artifact_bytes, int)
        or isinstance(artifact_bytes, bool)
        or artifact_bytes < 1
    ):
        raise M12EvidenceError("candidate artifact size must be positive")
    for field in (
        "installed_executable_sha256",
        "installed_manifest_sha256",
        "service_registration_sha256",
    ):
        _digest(candidate.get(field), field)

    journeys = _object(value.get("journeys"), "journeys")
    if set(journeys) != {"J11", "J20"}:
        raise M12EvidenceError("J20 evidence must contain exactly J11 and J20")
    j11 = _object(journeys["J11"], "J11")
    _equal(j11.get("status"), "PASS", "J11 status")
    for field in (
        "real_codex",
        "real_claude",
        "no_export_or_migration",
        "same_project_identity",
        "same_semantic_revision",
        "authority_roles_preserved",
    ):
        _equal(j11.get(field), True, f"J11 {field}")
    j20 = _object(journeys["J20"], "J20")
    _equal(j20.get("status"), "PASS", "J20 status")
    required_truths = {
        "intent_captured",
        "project_created",
        "envelope_approved",
        "persistent_execution",
        "frontend_closed_during_run",
        "execution_continued_after_frontend_close",
        "tactical_deviation_bounded",
        "material_decision_blocked",
        "material_decision_resolved_by_user",
        "validation_evidence_recorded",
        "acceptance_authority_separate",
        "project_authority_promoted",
        "workspace_isolated",
        "documentation_current",
        "dashboard_current",
        "outcome_reached",
        "managed_service_restarted",
        "coordinator_generation_advanced",
        "project_restored",
        "run_restored",
        "session_restored",
    }
    for field in required_truths:
        _equal(j20.get(field), True, f"J20 {field}")
    _equal(j20.get("provider_self_accepted"), False, "J20 provider self-acceptance")
    expected_stages = [
        "EXPLORATION",
        "RESEARCH",
        "DEFINITION",
        "ARCHITECTURE",
        "REQUIREMENTS_ADRS",
        "PLAN",
        "ENVELOPE_PROPOSED",
        "APPROVED_PLAN",
    ]
    _equal(j20.get("lifecycle_stages_accepted"), expected_stages, "J20 lifecycle stages")
    knowledge_id = j20.get("organizational_knowledge_candidate")
    if not isinstance(knowledge_id, str) or not knowledge_id:
        raise M12EvidenceError("J20 knowledge candidate is absent")
    promotion_revision = j20.get("promotion_revision")
    if not isinstance(promotion_revision, int) or promotion_revision < 2:
        raise M12EvidenceError("J20 promotion revision is invalid")

    roles = _object(value.get("role_certifications"), "role certifications")
    _equal(
        roles,
        {
            "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
            "INTERACTION": "LIVE_ROLE_CERTIFIED",
        },
        "role certifications",
    )
    calls = _sequence(value.get("public_process_calls"), "public process calls")
    observed = Counter(
        str(_object(call, f"public call {index}").get("operation"))
        for index, call in enumerate(calls)
    )
    required_calls = {
        "project.create": 1,
        "distribution.setup.plan": 1,
        "distribution.setup.apply": 1,
        "providers.interact": 2,
        "interaction.open": 1,
        "interaction.disconnect": 2,
        "interaction.reconnect": 2,
        "interaction.lifecycle.advance": 8,
        "governance.envelope.propose": 2,
        "governance.envelope.approve": 2,
        "runtime.run.authorize": 1,
        "runtime.workspace.create": 1,
        "runtime.provider.execute": 1,
        "governance.decision.request": 1,
        "governance.decision.resolve": 1,
        "runtime.accept": 1,
        "runtime.workspace.promote": 1,
        "documentation.regenerate": 1,
        "documentation.status": 1,
        "dashboard.project": 1,
        "knowledge.project.lesson.record": 1,
        "project.continue": 1,
    }
    for operation, minimum in required_calls.items():
        if observed[operation] < minimum:
            raise M12EvidenceError(f"missing public J20 operation: {operation}")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "journeys": ["J11", "J20"],
        "composition": COMPOSITION,
        "candidate": {
            "source_commit": expected_source_commit,
            "artifact_sha256": expected_artifact_sha256,
            "artifact_bytes": artifact_bytes,
            "product_version": TARGET_RELEASE,
        },
        "public_process_call_count": len(calls),
        "provider_output_retained": False,
        "credential_material_read": False,
    }


def _evidence_paths(value: object, *, root: Path, name: str) -> list[str]:
    items = _sequence(value, name)
    if not items:
        raise M12EvidenceError(f"{name} must not be empty")
    paths: list[str] = []
    for item in items:
        if (
            not isinstance(item, str)
            or not item
            or Path(item).is_absolute()
            or ".." in Path(item).parts
        ):
            raise M12EvidenceError(f"{name} contains an invalid repository-relative path")
        if not (root / "implementation" / item).is_file():
            raise M12EvidenceError(f"{name} references a missing file: {item}")
        paths.append(item)
    return paths


def validate_release_matrix(
    value: Mapping[str, Any],
    *,
    root: Path,
    expected_artifact_sha256: str,
    expected_source_commit: str,
) -> dict[str, Any]:
    _secret_safe(value)
    _equal(value.get("schema_version"), MATRIX_SCHEMA, "matrix schema")
    _equal(value.get("target_release"), TARGET_RELEASE, "target release")
    _equal(value.get("contract_digest"), M12_CONTRACT_DIGEST, "M12 contract digest")
    _equal(value.get("status"), "PASS", "matrix status")
    candidate = _object(value.get("candidate"), "matrix candidate")
    _equal(candidate.get("source_commit"), expected_source_commit, "matrix source commit")
    _equal(candidate.get("artifact_sha256"), expected_artifact_sha256, "matrix artifact hash")
    _equal(candidate.get("product_version"), TARGET_RELEASE, "matrix product version")
    _digest(candidate.get("provenance_sha256"), "candidate provenance hash")
    signing = _object(candidate.get("signing"), "candidate signing")
    signing_status = signing.get("status")
    if signing_status not in {"SIGNED", "UNSIGNED"}:
        raise M12EvidenceError("candidate signing status must be truthful")
    if signing_status == "UNSIGNED":
        _equal(signing.get("release_claim"), "NOT_CLAIMED", "unsigned release claim")
        reason = signing.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise M12EvidenceError("unsigned candidate requires a truthful reason")

    core = _object(value.get("core_mandatory_claims"), "Core claims")
    if set(core) != set(CORE_CLAIMS):
        raise M12EvidenceError("Core claim set differs from frozen release matrix")
    for claim, claim_journeys in CORE_CLAIMS.items():
        item = _object(core[claim], f"Core claim {claim}")
        _equal(item.get("status"), "PASS", f"Core claim {claim} status")
        _equal(
            item.get("journeys"),
            list(claim_journeys),
            f"Core claim {claim} journeys",
        )
        _evidence_paths(item.get("evidence"), root=root, name=f"Core claim {claim} evidence")

    optional = _object(value.get("optional_claims"), "optional claims")
    if set(optional) != set(OPTIONAL_CLAIMS):
        raise M12EvidenceError("optional claim set differs from frozen release scope")
    for claim, milestone in OPTIONAL_CLAIMS.items():
        item = _object(optional[claim], f"optional claim {claim}")
        _equal(item.get("shipped"), False, f"optional claim {claim} shipped")
        _equal(item.get("status"), "EXCLUDED", f"optional claim {claim} status")
        _equal(item.get("requires_milestone"), milestone, f"optional claim {claim} milestone")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise M12EvidenceError(f"optional claim {claim} exclusion requires a reason")

    journeys = _object(value.get("mandatory_journeys"), "mandatory journeys")
    if tuple(journeys) != MANDATORY_JOURNEYS:
        raise M12EvidenceError("mandatory Journey ordering or membership is invalid")
    for journey_id in MANDATORY_JOURNEYS:
        item = _object(journeys[journey_id], journey_id)
        _equal(item.get("status"), "PASS", f"{journey_id} status")
        binding = item.get("candidate_binding")
        allowed = {"EXACT_NATIVE"} if journey_id in EXACT_NATIVE_JOURNEYS else {
            "EXACT_NATIVE",
            "SOURCE_COMMIT",
        }
        if binding not in allowed:
            raise M12EvidenceError(f"{journey_id} candidate binding is insufficient")
        _evidence_paths(item.get("evidence"), root=root, name=f"{journey_id} evidence")

    classes = _object(value.get("acceptance_classes"), "acceptance classes")
    if set(classes) != ACCEPTANCE_CLASSES:
        raise M12EvidenceError("M12 acceptance class set is invalid")
    for name, raw in classes.items():
        item = _object(raw, f"acceptance class {name}")
        _equal(item.get("status"), "PASS", f"acceptance class {name} status")
        _evidence_paths(item.get("evidence"), root=root, name=f"acceptance class {name} evidence")

    _equal(value.get("release_manifest_truthful"), True, "release manifest truthfulness")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "target_release": TARGET_RELEASE,
        "source_commit": expected_source_commit,
        "artifact_sha256": expected_artifact_sha256,
        "core_claim_count": len(core),
        "mandatory_journey_count": len(journeys),
        "optional_claims_shipped": [],
        "signing_status": signing_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--j20", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        j20_value = _object(json.loads(arguments.j20.read_text(encoding="utf-8")), "J20")
        matrix_value = _object(
            yaml.safe_load(arguments.matrix.read_text(encoding="utf-8")), "matrix"
        )
        result = {
            "schema_version": "1.0",
            "status": "PASS",
            "j20": validate_j20(
                j20_value,
                expected_artifact_sha256=arguments.expected_artifact_sha256,
                expected_source_commit=arguments.expected_source_commit,
            ),
            "matrix": validate_release_matrix(
                matrix_value,
                root=arguments.root.resolve(),
                expected_artifact_sha256=arguments.expected_artifact_sha256,
                expected_source_commit=arguments.expected_source_commit,
            ),
        }
    except (OSError, json.JSONDecodeError, yaml.YAMLError, M12EvidenceError) as exc:
        result = {"schema_version": "1.0", "status": "FAIL", "error": type(exc).__name__}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
