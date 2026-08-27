"""Fail-closed validation for the accepted ARTIFEX 2.0 M1 milestone."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

import yaml

from tools.artifex2.bootstrap_control_plane import ACCEPTANCE_CLASSES
from tools.artifex2.control_plane import derive, render
from tools.artifex2.validate_m0 import validate as validate_m0

M0_ACCEPTANCE_COMMIT = "f476d40e7a721913b9c94c4a60b78f0500f0e85f"
M1_CONTRACT_DIGEST = "42c6d252e97380e841bff8eabadf673d6f69140ce9660c59f805aff38d71299d"


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return value


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _require_ancestor(root: Path, ancestor: str, descendant: str = "HEAD") -> None:
    try:
        _git(root, "merge-base", "--is-ancestor", ancestor, descendant)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"required baseline is not an ancestor: {ancestor}") from exc


def validate(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    implementation = root / "implementation"
    validate_m0(root, None)
    state = derive(root)
    program = state["program"]
    milestones = {item["id"]: item for item in state["milestones"]}
    if not program["m1_started"] or milestones["M1"]["state"] != "ACCEPTED":
        raise ValueError("M1 acceptance state is incomplete")
    if milestones["M2"]["state"] not in {"READY", "ACTIVE", "ACCEPTED"}:
        raise ValueError("M2 state is incompatible with accepted M1 dependency")
    if milestones["M2"]["started"] != program["m2_started"]:
        raise ValueError("M2 start state disagrees with the program projection")

    _require_ancestor(root, M0_ACCEPTANCE_COMMIT)
    baseline = str(program["latest_accepted_commit"])
    _require_ancestor(root, baseline)

    acceptance = _yaml(implementation / "ACCEPTANCE/M1.yaml")
    if acceptance["contract_digest"] != M1_CONTRACT_DIGEST:
        raise ValueError("M1 acceptance contract digest is invalid")
    if tuple(acceptance["evidence_classes"]) != ACCEPTANCE_CLASSES:
        raise ValueError("M1 acceptance omits or reorders an evidence class")
    required = {
        name: value["status"]
        for name, value in acceptance["evidence_classes"].items()
        if value["required_m1"]
    }
    if any(status != "PASS" for status in required.values()):
        raise ValueError(f"M1 required evidence class is not PASS: {required}")
    if acceptance["mandatory_journeys"] != ["J03"] or acceptance["verdict"] != "ACCEPTED":
        raise ValueError("M1 Journey/verdict acceptance is invalid")
    if program["m2_started"]:
        acceptance_commit = str(acceptance.get("acceptance_commit", ""))
        if not acceptance_commit:
            raise ValueError("started M2 is missing the accepted M1 commit")
        _require_ancestor(root, acceptance_commit)

    contracts = _yaml(implementation / "CONTRACT-REGISTRY.yaml")
    m1_contract = next(item for item in contracts["contracts"] if item["id"] == "M1-CONTRACT")
    if m1_contract["digest"] != M1_CONTRACT_DIGEST:
        raise ValueError("registered M1 contract digest is invalid")
    if m1_contract["implementation_state"] != "ACCEPTED":
        raise ValueError("registered M1 contract is not accepted")

    workstreams = _yaml(implementation / "WORKSTREAM-REGISTRY.yaml")["workstreams"]
    m1_workstreams = [item for item in workstreams if item["milestone"] == "M1"]
    if not m1_workstreams or any(item["state"] != "COMPLETE" for item in m1_workstreams):
        raise ValueError("M1 workstream completion is invalid")

    journeys = _yaml(implementation / "JOURNEYS/STATE.yaml")["journeys"]
    j03 = next(item for item in journeys if item["id"] == "J03")
    if j03["status"] != "PASS" or j03["public_shipping_composition"] != (
        "INSTALLED_WHEEL_CLI_TWO_PROCESS"
    ):
        raise ValueError("J03 public black-box evidence is not PASS")

    evidence = _yaml(implementation / "EVIDENCE/M1-VALIDATION.yaml")
    if evidence["status"] != "PASS" or evidence["unexpected_failures"]:
        raise ValueError("M1 validation evidence is not clean")
    regression = evidence["v1_release_harness_regression"]
    if not regression["signature_matches_m0"] or regression["source_repaired_by_m1"]:
        raise ValueError("M1 did not preserve the controlled V1 regression")
    if _git(root, "diff", "--name-only", M0_ACCEPTANCE_COMMIT, "--", "tests/test_release.py"):
        raise ValueError("M1 changed the controlled V1 release regression source")

    migration = _yaml(implementation / "MIGRATION/STATE.yaml")
    allowed_migration_states = {"V1_MODEL_ADAPTER_BASELINE_QUALIFIED"}
    if program["m2_started"]:
        allowed_migration_states.add("ENGINEERING_ACTIVE_NO_LEGACY_RUNTIME_IMPORT")
        allowed_migration_states.add("M2_ACCEPTED_EMPTY_RUNSTORE")
    if migration["migration_execution"] not in allowed_migration_states:
        raise ValueError("migration state is incompatible with accepted M1 provenance")
    if migration["project_mutation"]:
        raise ValueError("later migration state mutated accepted M1 Project semantics")
    render(root, write=False)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    state = validate(arguments.repo_root)
    print(
        "m1-control-plane=PASS "
        f"status={state['program']['current_status']} "
        f"m2_state={next(item for item in state['milestones'] if item['id'] == 'M2')['state']}"
    )


if __name__ == "__main__":
    main()
