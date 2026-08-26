"""Bootstrap ARTIFEX 2.0 implementation-control state from the frozen handoff."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

ACCEPTANCE_CLASSES = (
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
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return value


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(value, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )


def _heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    raise ValueError(f"missing heading: {path}")


def _section_bullets(text: str, heading: str) -> list[str]:
    marker = f"## {heading}"
    if marker not in text:
        return []
    section = text.split(marker, 1)[1].split("\n## ", 1)[0]
    return [line[2:].strip() for line in section.splitlines() if line.startswith("- ")]


def validate_handoff(root: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    manifest_path = root / "HANDOFF-MANIFEST.yaml"
    manifest = _read_yaml(manifest_path)
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("manifest files must be a list")
    seen: set[str] = set()
    validated: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("manifest file entries must be mappings")
        relative = entry.get("path")
        expected = entry.get("digest")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("manifest path and digest must be strings")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in seen:
            raise ValueError(f"unsafe or duplicate manifest path: {relative}")
        seen.add(relative)
        path = root.joinpath(*pure.parts)
        if not path.is_file():
            raise ValueError(f"missing required handoff file: {relative}")
        actual = _sha256(path)
        if actual != expected.lower():
            raise ValueError(f"handoff digest mismatch: {relative}")
        validated.append({"path": relative, "sha256": actual})

    sums: dict[str, str] = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split(None, 1)
        relative = relative.strip().removeprefix("*")
        if relative in sums:
            raise ValueError(f"duplicate SHA256SUMS entry: {relative}")
        path = root.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() or _sha256(path) != digest.lower():
            raise ValueError(f"invalid SHA256SUMS entry: {relative}")
        sums[relative] = digest.lower()
    if set(sums) != seen | {"HANDOFF-MANIFEST.yaml"}:
        raise ValueError("SHA256SUMS inventory differs from manifest plus manifest file")
    return manifest, validated


def _contract(
    *,
    identifier: str,
    title: str,
    digest: str,
    authority_source: str,
    intake_commit: str,
    dependencies: list[str],
    acceptance_criteria: list[str],
    contract_type: str,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "type": contract_type,
        "digest": digest,
        "digest_algorithm": "sha256",
        "frozen_at": "ARTIFEX-2.0-IMPLEMENTATION-HANDOFF-FROZEN-v1",
        "base_commit": intake_commit,
        "dependencies": dependencies,
        "authority_sources": [authority_source],
        "acceptance_criteria": acceptance_criteria,
        "evidence_references": ["EVIDENCE/HANDOFF-INTEGRITY.yaml"],
        "implementation_state": "NOT_STARTED",
        "m0_baseline_state": "CAPTURED",
    }


def build_contract_registry(
    handoff: Path, manifest: dict[str, Any], intake_commit: str
) -> dict[str, Any]:
    digest_by_path = {
        entry["path"]: entry["digest"] for entry in manifest["files"] if isinstance(entry, dict)
    }
    contracts: list[dict[str, Any]] = []
    for path_name, identifier, contract_type in (
        ("01-PRODUCT-DEFINITION.md", "PRODUCT-DEFINITION", "FROZEN_PRODUCT"),
        ("02-TARGET-ARCHITECTURE-FROZEN-v1.md", "TARGET-ARCHITECTURE", "FROZEN_ARCHITECTURE"),
        ("03-AUTHORITY-MATRIX.md", "AUTHORITY-MATRIX", "FROZEN_AUTHORITY"),
        ("04-FROZEN-INVARIANTS.md", "FROZEN-INVARIANTS", "FROZEN_INVARIANT_SET"),
        ("05-TARGET-IMPLEMENTATION-PLAN-FROZEN-v1.md", "IMPLEMENTATION-PLAN", "FROZEN_PLAN"),
        ("06-ORCHESTRATOR-GOVERNANCE.md", "ORCHESTRATOR-GOVERNANCE", "EXECUTION_GOVERNANCE"),
        ("MILESTONES/M0.md", "M0-CONTRACT", "MILESTONE_CONTRACT"),
    ):
        contracts.append(
            _contract(
                identifier=identifier,
                title=_heading(handoff / path_name),
                digest=digest_by_path[path_name],
                authority_source=path_name,
                intake_commit=intake_commit,
                dependencies=[],
                acceptance_criteria=["Digest and authority boundary remain unchanged"],
                contract_type=contract_type,
            )
        )

    adrs: list[dict[str, Any]] = []
    for path in sorted((handoff / "ADR").glob("ADR-T*.md")):
        relative = path.relative_to(handoff).as_posix()
        text = path.read_text(encoding="utf-8")
        match = re.search(r"ADR-T\d{3}", path.name)
        if match is None or "**Status:** FROZEN" not in text:
            raise ValueError(f"invalid frozen ADR: {relative}")
        criteria = _section_bullets(text, "Implementation conformance requirements")
        adrs.append(
            _contract(
                identifier=match.group(0),
                title=_heading(path),
                digest=digest_by_path[relative],
                authority_source=relative,
                intake_commit=intake_commit,
                dependencies=_section_bullets(text, "Dependencies"),
                acceptance_criteria=criteria,
                contract_type="FROZEN_ADR",
            )
        )

    invariant_path = handoff / "04-FROZEN-INVARIANTS.md"
    invariant_text = invariant_path.read_text(encoding="utf-8")
    invariant_pattern = re.compile(r"## (INV-F\d{2}) — ([^\n]+)\n(.*?)(?=\n## INV-F|\Z)", re.S)
    invariants: list[dict[str, Any]] = []
    for identifier, title, body in invariant_pattern.findall(invariant_text):
        expectation = re.search(r"\*\*Minimum conformance test expectation:\*\* ([^\n]+)", body)
        statement = re.search(r"\*\*Statement:\*\* ([^\n]+)", body)
        invariants.append(
            _contract(
                identifier=identifier,
                title=title.strip(),
                digest=digest_by_path["04-FROZEN-INVARIANTS.md"],
                authority_source="04-FROZEN-INVARIANTS.md",
                intake_commit=intake_commit,
                dependencies=[],
                acceptance_criteria=[expectation.group(1) if expectation else "Preserve invariant"],
                contract_type="FROZEN_INVARIANT",
            )
            | {"statement": statement.group(1) if statement else ""}
        )
    if len(adrs) != 24 or len(invariants) != 34:
        raise ValueError(
            f"expected 24 ADRs and 34 invariants; got {len(adrs)} and {len(invariants)}"
        )
    return {
        "schema_version": "1.0",
        "registry_id": "ARTIFEX-2.0-CONTRACT-REGISTRY",
        "contracts": contracts,
        "adrs": adrs,
        "invariants": invariants,
    }


def bootstrap(
    repo: Path,
    handoff: Path,
    intake_commit: str,
    branch: str,
    recorded_date: str,
) -> None:
    manifest, validated = validate_handoff(handoff)
    implementation = repo / "implementation"
    program = {
        "schema_version": "1.0",
        "program": {
            "id": "ARTIFEX-2.0-IMPLEMENTATION",
            "handoff_id": manifest["handoff_id"],
            "handoff_manifest_sha256": _sha256(handoff / "HANDOFF-MANIFEST.yaml"),
            "handoff_declared_directory": "ARTIFEX-2.0-IMPLEMENTATION-HANDOFF",
            "handoff_observed_directory": handoff.name,
            "directory_variance": "PACKAGING_NAME_VARIANCE_ACCEPTED",
            "target_release": str(manifest["target_release"]),
            "architecture_status": manifest["architecture_status"],
            "implementation_plan_status": manifest["implementation_plan_status"],
            "intake_commit": intake_commit,
            "branch": branch,
            "current_milestone": "M0",
            "current_status": "IN_PROGRESS",
            "latest_accepted_commit": intake_commit,
            "next_integration_point": "M0 acceptance",
            "m1_started": False,
            "recorded_date": recorded_date,
        },
        "target_system": {
            "overview": (
                "Persistent project-centric engineering control platform with separate "
                "semantic, execution, acceptance, observed-reality and projection authorities."
            ),
            "standalone_baseline": [
                "ARTIFEX managed service",
                "SQLite RunStore",
                "Git/files Project repositories",
                "Project Catalog",
                "Unified Platform and Project dashboard framework",
                "At least one supported provider",
            ],
            "glossary": {
                "Project Authority": "Only authority that accepts Project semantic mutations",
                "ExecutionCoordinator": (
                    "Owner of durable runtime transitions, never Project acceptance"
                ),
                "Acceptance Authority": (
                    "Interprets validation evidence and decides result acceptance"
                ),
                "ProjectJob": "Qualified ARTIFEX cross-platform execution unit",
                "Execution Envelope": "Approved versioned boundary for autonomous Runs",
                "Observed Reality": (
                    "Sourced facts that may create divergence, never silently rewrite intent"
                ),
                "Projection": "Rebuildable documentation or dashboard view, never authority",
            },
        },
        "milestone_states": {
            milestone["id"]: {
                "state": "IN_PROGRESS" if milestone["id"] == "M0" else "BLOCKED_DEPENDENCY",
                "started": milestone["id"] == "M0",
                "accepted": False,
            }
            for milestone in _read_yaml(handoff / "MILESTONES/MILESTONE-DAG.yaml")["milestones"]
        },
        "acceptance_classes": {
            item: {
                "required_m0": item
                not in {"PUBLIC_COMPOSITION", "BLACK_BOX_OUTCOME", "PROVIDER_CERTIFICATION"},
                "status": "PENDING"
                if item not in {"PUBLIC_COMPOSITION", "BLACK_BOX_OUTCOME", "PROVIDER_CERTIFICATION"}
                else "NOT_APPLICABLE",
                "evidence": [],
            }
            for item in ACCEPTANCE_CLASSES
        },
        "dashboard": {
            "state": "FOUNDATION_PENDING",
            "projection_path": "implementation/dashboard/index.html",
            "machine_state_path": "implementation/dashboard/state.json",
        },
    }
    _write_yaml(implementation / "PROGRAM-STATE.yaml", program)
    (implementation / "MILESTONE-DAG.yaml").write_bytes(
        (handoff / "MILESTONES/MILESTONE-DAG.yaml").read_bytes()
    )
    _write_yaml(
        implementation / "WORKSTREAM-REGISTRY.yaml",
        {
            "schema_version": "1.0",
            "integration_owner": "ARTIFEX_2_ORCHESTRATOR",
            "workstreams": [
                {
                    "id": identifier,
                    "milestone": "M0",
                    "purpose": purpose,
                    "owner_subagent": "ARTIFEX_2_ORCHESTRATOR",
                    "worktree": str(repo),
                    "branch": branch,
                    "base_commit": intake_commit,
                    "shared_contracts": ["M0-CONTRACT", "FROZEN-INVARIANTS"],
                    "state": "IN_PROGRESS",
                    "blockers": [],
                    "integration_owner": "ARTIFEX_2_ORCHESTRATOR",
                }
                for identifier, purpose in (
                    ("WS-M0-FIXTURES", "Capture immutable V1 and migration corpus"),
                    ("WS-M0-OUTCOMES", "Build bounded public-process Outcome Runner"),
                    ("WS-M0-CONFORMANCE", "Validate frozen contracts and authority boundaries"),
                    ("WS-M0-COMPOSITION", "Reproduce V1 public-composition gaps"),
                    ("WS-M0-DASHBOARD", "Generate implementation dashboard projection"),
                )
            ],
        },
    )
    _write_yaml(
        implementation / "CONTRACT-REGISTRY.yaml",
        build_contract_registry(handoff, manifest, intake_commit),
    )
    _write_yaml(
        implementation / "BLOCKERS.yaml",
        {
            "schema_version": "1.0",
            "blockers": [],
            "observations": [
                {
                    "id": "OBS-PACKAGE-DIRECTORY-NAME",
                    "scope": "BOOTSTRAP",
                    "state": "RESOLVED_ROUTINE_IMPLEMENTATION_CHOICE",
                    "evidence": ["EVIDENCE/HANDOFF-INTEGRITY.yaml"],
                    "required_authority": "ORCHESTRATOR",
                    "unrelated_work_may_continue": True,
                }
            ],
        },
    )
    journeys = []
    for path in sorted((handoff / "JOURNEYS").glob("J*.md")):
        identifier = path.stem
        journeys.append(
            {
                "id": identifier,
                "title": _heading(path),
                "status": "NOT_STARTED",
                "environment": None,
                "public_shipping_composition": None,
                "evidence": [],
                "last_run": None,
                "blocker": "M0 has no mandatory journeys; milestone dependencies not accepted",
            }
        )
    _write_yaml(
        implementation / "JOURNEYS/STATE.yaml",
        {"schema_version": "1.0", "m0_mandatory": [], "journeys": journeys},
    )
    _write_yaml(
        implementation / "MIGRATION/STATE.yaml",
        {
            "schema_version": "1.0",
            "milestone": "M0",
            "mode": "BASELINE_CAPTURE_ONLY",
            "project_mutation": False,
            "fixture": "MIGRATION/V1-RELEASE-FIXTURE.yaml",
            "fixture_state": "PENDING",
            "migration_execution": "NOT_STARTED",
            "rollback": "NOT_APPLICABLE_NO_MUTATION",
        },
    )
    certification = _read_yaml(handoff / "ACCEPTANCE/PROVIDER-ROLE-CERTIFICATION.yaml")
    providers: list[dict[str, Any]] = []
    for provider, roles in certification["core_2_0"].items():
        for role, requirement in roles.items():
            providers.append(
                {
                    "provider": provider,
                    "role": role,
                    "requirement": requirement,
                    "steps": {step: "NOT_STARTED" for step in certification["ladder"]},
                    "evidence": [],
                }
            )
    _write_yaml(
        implementation / "PROVIDERS/ROLE-CERTIFICATION.yaml",
        {
            "schema_version": "1.0",
            "schema_validation": "PENDING",
            "ladder": certification["ladder"],
            "providers": providers,
        },
    )
    _write_yaml(
        implementation / "EVIDENCE/HANDOFF-INTEGRITY.yaml",
        {
            "schema_version": "1.0",
            "evidence_id": "EVD-M0-HANDOFF-INTEGRITY",
            "status": "PASS",
            "handoff_id": manifest["handoff_id"],
            "manifest_sha256": _sha256(handoff / "HANDOFF-MANIFEST.yaml"),
            "manifest_entries": len(validated),
            "sha256sums_entries": len(validated) + 1,
            "required_files_valid": len(validated),
            "declared_directory": "ARTIFEX-2.0-IMPLEMENTATION-HANDOFF",
            "observed_directory": handoff.name,
            "directory_variance_disposition": "PACKAGING_NAME_VARIANCE_ACCEPTED",
            "validated_files": validated,
        },
    )
    _write_yaml(
        implementation / "ACCEPTANCE/M0.yaml",
        {
            "schema_version": "1.0",
            "milestone": "M0",
            "contract_digest": next(
                entry["digest"]
                for entry in manifest["files"]
                if entry["path"] == "MILESTONES/M0.md"
            ),
            "implementation_baseline_commit": None,
            "frozen_architecture_baseline": manifest["handoff_id"],
            "mandatory_work_complete": False,
            "blocked": [],
            "superseded": [],
            "evidence_classes": program["acceptance_classes"],
            "mandatory_journeys": [],
            "unresolved_contradiction": None,
            "provider_claim_changes": [],
            "migration": "BASELINE_CAPTURE_ONLY",
            "verdict": "IN_PROGRESS",
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--handoff-root", type=Path, required=True)
    parser.add_argument("--intake-commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--recorded-date", required=True)
    arguments = parser.parse_args()
    bootstrap(
        arguments.repo_root.resolve(),
        arguments.handoff_root.resolve(),
        arguments.intake_commit,
        arguments.branch,
        arguments.recorded_date,
    )
    print("implementation-control-bootstrap=PASS milestone=M0 status=IN_PROGRESS")


if __name__ == "__main__":
    main()
