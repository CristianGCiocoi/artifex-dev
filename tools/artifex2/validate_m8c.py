"""Fail-closed validation for the ARTIFEX 2.0 M8C non-live checkpoint."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

from tools.artifex2.bootstrap_control_plane import ACCEPTANCE_CLASSES
from tools.artifex2.control_plane import derive, render

M8C_BASE = "77aeb189e3359f8a54ff1f4056dd3c8409747ef7"
M8C_CONTRACT_DIGEST = "686191f28ba33b59db39cc67ea654d71766365c6d587041c8b0c7badb6c66929"


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return value


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def validate_public_outcome(value: dict[str, Any]) -> None:
    if value.get("milestone") != "M8C":
        raise ValueError("M8C public evidence has the wrong milestone")
    if value.get("status") not in {
        "BLOCKED_EXTERNAL_PREREQUISITE",
        "READY_FOR_LIVE_EXECUTION_QUALIFICATION",
        "PASS",
    }:
        raise ValueError("M8C public evidence has an invalid status")
    if value.get("shipping_artifact") != "INSTALLED_WHEEL":
        raise ValueError("M8C public evidence did not use an installed wheel")
    if value.get("composition") != "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS":
        raise ValueError("M8C public evidence did not use the shipping public composition")
    forbidden = {
        "source_tree_imported": True,
        "custom_application_factory_used": True,
        "provider_injection_used": True,
        "simulated_provider": True,
        "credential_material_read": True,
        "credential_material_persisted": True,
    }
    for field, forbidden_value in forbidden.items():
        if value.get(field) is forbidden_value:
            raise ValueError(f"M8C evidence used a forbidden shortcut: {field}")
    setup = value.get("setup")
    if not isinstance(setup, dict) or setup.get("fresh_process_consumed") is not True:
        raise ValueError("M8C setup evidence stops at a config write")
    if setup.get("vendor_configuration_mutated") is not False:
        raise ValueError("M8C setup mutated vendor configuration")
    migration = value.get("migration")
    if not isinstance(migration, dict) or migration.get("v1_setup_revalidated") is not True:
        raise ValueError("M8C did not readiness-revalidate V1 setup")
    if migration.get("runtime_history_fabricated") is not False:
        raise ValueError("M8C migration fabricated runtime history")
    claims = value.get("role_claims")
    if not isinstance(claims, dict):
        raise ValueError("M8C role claims are missing")
    if claims.get("INTERACTION") != "EXPERIMENTAL_NOT_CLAIMED":
        raise ValueError("M8C improperly claimed DeepSeek INTERACTION")
    if claims.get("HARNESS") != "EXPERIMENTAL_NOT_CLAIMED":
        raise ValueError("M8C improperly claimed DeepSeek HARNESS")
    certification = value.get("provider_certification")
    if not isinstance(certification, dict) or certification.get("release_status") != "EXPERIMENTAL":
        raise ValueError("M8C experimental certification status is missing")
    roles = certification.get("roles")
    if not isinstance(roles, list) or len(roles) != 1:
        raise ValueError("M8C execution role projection is malformed")
    role = roles[0]
    if not isinstance(role, dict) or role.get("role") != "EXECUTION_IMPLEMENTER":
        raise ValueError("M8C role evidence is conflated")
    if role.get("supported_version_range") != ">=1.0.0,<2":
        raise ValueError("M8C supported DeepSeek version range drifted")
    if value.get("status") != "PASS" and role.get("state") == "LIVE_ROLE_CERTIFIED":
        raise ValueError("blocked M8C evidence inherited a live certification")
    graph = value.get("capability_graph")
    resolution = value.get("contextual_resolution")
    if value.get("status") != "PASS":
        if not isinstance(graph, dict) or graph.get("certified_roles") != []:
            raise ValueError("blocked M8C evidence granted default dispatch authority")
        if not isinstance(resolution, dict) or resolution.get("eligible") is not False:
            raise ValueError("blocked M8C evidence remained contextually dispatchable")


def validate(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    _git(root, "merge-base", "--is-ancestor", M8C_BASE, "HEAD")
    program = _yaml(root / "implementation/PROGRAM-STATE.yaml")
    m8c = program["milestone_states"]["M8C"]
    if program["milestone_states"]["M4"]["state"] != "ACCEPTED":
        raise ValueError("M8C dependency M4 is not accepted")
    if not program["program"].get("m8c_started") or m8c["state"] not in {
        "ACTIVE",
        "BLOCKED_EXTERNAL_PREREQUISITE",
        "ACCEPTED",
    }:
        raise ValueError("M8C is not active, blocked, or accepted")
    contracts = _yaml(root / "implementation/CONTRACT-REGISTRY.yaml")
    contract = next(
        item for item in contracts["contracts"] if item.get("id") == "M8C-CONTRACT"
    )
    if contract.get("digest") != M8C_CONTRACT_DIGEST:
        raise ValueError("M8C contract digest is invalid")
    acceptance = _yaml(root / "implementation/ACCEPTANCE/M8C.yaml")
    if acceptance.get("contract_digest") != M8C_CONTRACT_DIGEST:
        raise ValueError("M8C acceptance contract digest is invalid")
    if acceptance.get("implementation_baseline_commit") != M8C_BASE:
        raise ValueError("M8C implementation baseline is invalid")
    if "canonical_base_commit" in acceptance:
        raise ValueError("M8C acceptance uses a noncanonical baseline key")
    if acceptance.get("acceptance_commit") is not None:
        raise ValueError("blocked M8C cannot carry an acceptance commit")
    if tuple(acceptance.get("evidence_classes", {})) != ACCEPTANCE_CLASSES:
        raise ValueError("M8C acceptance omits or reorders an evidence class")
    if acceptance.get("mandatory_journeys") != []:
        raise ValueError("M8C cannot invent a mandatory Journey")
    public = json.loads(
        (root / "implementation/EVIDENCE/M8C-PUBLIC-OUTCOME.json").read_text(
            encoding="utf-8"
        )
    )
    if not isinstance(public, dict):
        raise ValueError("M8C public evidence must be an object")
    validate_public_outcome(public)
    if acceptance.get("verdict") == "ACCEPTED":
        if public.get("status") != "PASS":
            raise ValueError("accepted M8C lacks a live PASS outcome")
        required = {
            name: item.get("status")
            for name, item in acceptance["evidence_classes"].items()
            if item.get("required_m8c")
        }
        if any(status != "PASS" for status in required.values()):
            raise ValueError(f"accepted M8C has non-PASS evidence: {required}")
    render(root, write=False)
    return derive(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    state = validate(arguments.repo_root)
    print(
        "m8c-control-plane=PASS "
        f"state={next(item['state'] for item in state['milestones'] if item['id'] == 'M8C')}"
    )


if __name__ == "__main__":
    main()
