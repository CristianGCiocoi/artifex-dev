from __future__ import annotations

from pathlib import Path

import pytest

from artifex import __version__
from tools.artifex2.validate_m12 import (
    ACCEPTANCE_CLASSES,
    COMPOSITION,
    CORE_CLAIMS,
    J20_SCHEMA,
    M12_CONTRACT_DIGEST,
    MANDATORY_JOURNEYS,
    MATRIX_SCHEMA,
    OPTIONAL_CLAIMS,
    TARGET_RELEASE,
    M12EvidenceError,
    validate_j20,
    validate_release_matrix,
)

DIGEST = "a" * 64
COMMIT = "b" * 40


def _j20() -> dict[str, object]:
    operations = [
        "project.create",
        "distribution.setup.plan",
        "distribution.setup.apply",
        "providers.interact",
        "providers.interact",
        "interaction.open",
        "interaction.disconnect",
        "interaction.disconnect",
        "interaction.reconnect",
        "interaction.reconnect",
        *("interaction.lifecycle.advance" for _ in range(8)),
        "governance.envelope.propose",
        "governance.envelope.propose",
        "governance.envelope.approve",
        "governance.envelope.approve",
        "runtime.run.authorize",
        "runtime.workspace.create",
        "runtime.provider.execute",
        "governance.decision.request",
        "governance.decision.resolve",
        "runtime.accept",
        "runtime.workspace.promote",
        "documentation.regenerate",
        "documentation.status",
        "dashboard.project",
        "knowledge.project.lesson.record",
        "project.continue",
    ]
    return {
        "schema_version": J20_SCHEMA,
        "status": "PASS",
        "composition": COMPOSITION,
        "source_tree_imported": False,
        "custom_application_factory_used": False,
        "credential_material_read": False,
        "approval_tokens_retained": False,
        "candidate": {
            "artifact_name": "ARTIFEX-Setup.exe",
            "artifact_sha256": DIGEST,
            "artifact_bytes": 1,
            "source_commit": COMMIT,
            "product_version": TARGET_RELEASE,
            "installed_executable_sha256": DIGEST,
            "installed_manifest_sha256": DIGEST,
            "service_registration_sha256": DIGEST,
        },
        "journeys": {
            "J11": {
                "status": "PASS",
                "real_codex": True,
                "real_claude": True,
                "no_export_or_migration": True,
                "same_project_identity": True,
                "same_semantic_revision": True,
                "authority_roles_preserved": True,
            },
            "J20": {
                "status": "PASS",
                "intent_captured": True,
                "project_created": True,
                "lifecycle_stages_accepted": [
                    "EXPLORATION",
                    "RESEARCH",
                    "DEFINITION",
                    "ARCHITECTURE",
                    "REQUIREMENTS_ADRS",
                    "PLAN",
                    "ENVELOPE_PROPOSED",
                    "APPROVED_PLAN",
                ],
                "envelope_approved": True,
                "persistent_execution": True,
                "frontend_closed_during_run": True,
                "execution_continued_after_frontend_close": True,
                "tactical_deviation_bounded": True,
                "material_decision_blocked": True,
                "material_decision_resolved_by_user": True,
                "validation_evidence_recorded": True,
                "provider_self_accepted": False,
                "acceptance_authority_separate": True,
                "project_authority_promoted": True,
                "workspace_isolated": True,
                "documentation_current": True,
                "dashboard_current": True,
                "organizational_knowledge_candidate": "LES-M12-J20",
                "outcome_reached": True,
                "managed_service_restarted": True,
                "coordinator_generation_advanced": True,
                "project_restored": True,
                "run_restored": True,
                "session_restored": True,
                "promotion_revision": 10,
            },
        },
        "role_certifications": {
            "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
            "INTERACTION": "LIVE_ROLE_CERTIFIED",
        },
        "public_process_calls": [{"operation": operation} for operation in operations],
    }


def _matrix(root: Path) -> dict[str, object]:
    evidence = root / "implementation" / "EVIDENCE" / "m12.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    reference = ["EVIDENCE/m12.json"]
    return {
        "schema_version": MATRIX_SCHEMA,
        "target_release": TARGET_RELEASE,
        "contract_digest": M12_CONTRACT_DIGEST,
        "status": "PASS",
        "candidate": {
            "source_commit": COMMIT,
            "artifact_sha256": DIGEST,
            "product_version": TARGET_RELEASE,
            "provenance_sha256": DIGEST,
            "signing": {
                "status": "UNSIGNED",
                "release_claim": "NOT_CLAIMED",
                "reason": "No authorized Authenticode identity was supplied.",
            },
        },
        "core_mandatory_claims": {
            name: {"status": "PASS", "journeys": list(journeys), "evidence": reference}
            for name, journeys in CORE_CLAIMS.items()
        },
        "optional_claims": {
            name: {
                "shipped": False,
                "status": "EXCLUDED",
                "requires_milestone": milestone,
                "reason": "Not present in the Core release manifest.",
            }
            for name, milestone in OPTIONAL_CLAIMS.items()
        },
        "mandatory_journeys": {
            journey: {
                "status": "PASS",
                "candidate_binding": "EXACT_NATIVE",
                "evidence": reference,
            }
            for journey in MANDATORY_JOURNEYS
        },
        "acceptance_classes": {
            name: {"status": "PASS", "evidence": reference}
            for name in ACCEPTANCE_CLASSES
        },
        "release_manifest_truthful": True,
    }


def test_m12_j20_validator_accepts_complete_shipping_evidence() -> None:
    result = validate_j20(
        _j20(), expected_artifact_sha256=DIGEST, expected_source_commit=COMMIT
    )
    assert result["status"] == "PASS"
    assert result["journeys"] == ["J11", "J20"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("journeys", "J20", "provider_self_accepted"), True),
        (("journeys", "J11", "real_claude"), False),
        (("candidate", "product_version"), "1.0.0"),
    ],
)
def test_m12_j20_validator_rejects_weakened_claims(
    path: tuple[str, ...], value: object
) -> None:
    evidence = _j20()
    target: dict[str, object] = evidence
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    target[path[-1]] = value
    with pytest.raises(M12EvidenceError):
        validate_j20(
            evidence, expected_artifact_sha256=DIGEST, expected_source_commit=COMMIT
        )


def test_m12_release_matrix_accepts_frozen_core_and_truthful_exclusions(
    tmp_path: Path,
) -> None:
    result = validate_release_matrix(
        _matrix(tmp_path),
        root=tmp_path,
        expected_artifact_sha256=DIGEST,
        expected_source_commit=COMMIT,
    )
    assert result["status"] == "PASS"
    assert result["optional_claims_shipped"] == []


def test_m12_release_matrix_rejects_optional_unaccepted_provider_claim(
    tmp_path: Path,
) -> None:
    matrix = _matrix(tmp_path)
    optional = matrix["optional_claims"]
    assert isinstance(optional, dict)
    hermes = optional["hermes"]
    assert isinstance(hermes, dict)
    hermes["shipped"] = True
    with pytest.raises(M12EvidenceError):
        validate_release_matrix(
            matrix,
            root=tmp_path,
            expected_artifact_sha256=DIGEST,
            expected_source_commit=COMMIT,
        )


def test_artifex_2_release_metadata_is_consistent() -> None:
    root = Path(__file__).resolve().parents[2]
    assert __version__ == TARGET_RELEASE
    assert 'version = "2.0.0"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    installer = (root / "packaging" / "windows" / "ARTIFEX-Setup.nsi").read_text(
        encoding="utf-8"
    )
    assert 'VIProductVersion "2.0.0.0"' in installer
    assert '"DisplayVersion" "2.0.0"' in installer
