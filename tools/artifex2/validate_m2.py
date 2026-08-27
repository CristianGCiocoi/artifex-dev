"""Fail-closed validation for the accepted ARTIFEX 2.0 M2 milestone."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

import yaml

from tools.artifex2.bootstrap_control_plane import ACCEPTANCE_CLASSES
from tools.artifex2.control_plane import derive, render
from tools.artifex2.validate_m1 import validate as validate_m1

CANONICAL_M1_BASE = "0b77fd4fb0c6ed93b943917fb511e809ecc06740"
M2_IMPLEMENTATION_BASELINE = "1547cd295e06b2c05546c1c9f2c157969c59531f"
M2_CONTRACT_DIGEST = "2165c197747cf55f9b7a8aebc3c2dc29e1a6f59a9390d4a0db5d6769ba6a8401"


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


def _require_ancestor(root: Path, ancestor: str, descendant: str = "HEAD") -> None:
    try:
        _git(root, "merge-base", "--is-ancestor", ancestor, descendant)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"required baseline is not an ancestor: {ancestor}") from exc


def validate(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    implementation = root / "implementation"
    validate_m1(root)
    state = derive(root)
    program = state["program"]
    milestones = {item["id"]: item for item in state["milestones"]}
    if not program["m2_started"] or milestones["M2"]["state"] != "ACCEPTED":
        raise ValueError("M2 acceptance state is incomplete")
    if program["current_milestone"] == "M2":
        if program["current_status"] != "ACCEPTED":
            raise ValueError("M2 current milestone state is not accepted")
        if milestones["M3"]["state"] != "READY" or milestones["M3"]["started"]:
            raise ValueError("M3 must be READY and unstarted immediately after M2 acceptance")
    elif not milestones["M3"]["started"] or milestones["M3"]["state"] not in {
        "ACTIVE",
        "ACCEPTED",
    }:
        raise ValueError("later milestone state does not preserve accepted M2 provenance")

    _require_ancestor(root, CANONICAL_M1_BASE)
    _require_ancestor(root, M2_IMPLEMENTATION_BASELINE)
    if _git(
        root,
        "diff",
        "--name-only",
        CANONICAL_M1_BASE,
        "--",
        "implementation/ACCEPTANCE/M1.yaml",
        "implementation/ACCEPTANCE/M1.md",
        "implementation/EVIDENCE/M1-VALIDATION.yaml",
    ):
        raise ValueError("M2 changed immutable M1 acceptance provenance")
    if _git(root, "diff", "--name-only", CANONICAL_M1_BASE, "--", "tests/test_release.py"):
        raise ValueError("M2 changed the controlled V1 release regression source")

    acceptance = _yaml(implementation / "ACCEPTANCE/M2.yaml")
    if acceptance["contract_digest"] != M2_CONTRACT_DIGEST:
        raise ValueError("M2 acceptance contract digest is invalid")
    if acceptance["implementation_baseline_commit"] != M2_IMPLEMENTATION_BASELINE:
        raise ValueError("M2 implementation baseline is invalid")
    if tuple(acceptance["evidence_classes"]) != ACCEPTANCE_CLASSES:
        raise ValueError("M2 acceptance omits or reorders an evidence class")
    required = {
        name: value["status"]
        for name, value in acceptance["evidence_classes"].items()
        if value["required_m2"]
    }
    if any(status != "PASS" for status in required.values()):
        raise ValueError(f"M2 required evidence class is not PASS: {required}")
    if acceptance["mandatory_journeys"] != ["J05", "J15", "J18"]:
        raise ValueError("M2 mandatory Journey set is invalid")
    if acceptance["verdict"] != "ACCEPTED" or not acceptance["mandatory_work_complete"]:
        raise ValueError("M2 verdict is not accepted")
    acceptance_commit = str(acceptance.get("acceptance_commit", ""))
    if acceptance_commit:
        _require_ancestor(root, acceptance_commit)

    contracts = _yaml(implementation / "CONTRACT-REGISTRY.yaml")
    m2_contract = next(item for item in contracts["contracts"] if item["id"] == "M2-CONTRACT")
    if (
        m2_contract["digest"] != M2_CONTRACT_DIGEST
        or m2_contract["implementation_state"] != "ACCEPTED"
    ):
        raise ValueError("registered M2 contract is not accepted")

    workstreams = _yaml(implementation / "WORKSTREAM-REGISTRY.yaml")["workstreams"]
    m2_workstreams = [item for item in workstreams if item["milestone"] == "M2"]
    if not m2_workstreams or any(item["state"] != "COMPLETE" for item in m2_workstreams):
        raise ValueError("M2 workstream completion is invalid")

    journeys = {
        item["id"]: item for item in _yaml(implementation / "JOURNEYS/STATE.yaml")["journeys"]
    }
    for identifier in ("J05", "J15", "J18"):
        journey = journeys[identifier]
        if journey["status"] != "PASS" or "INSTALLED_WHEEL_CLI" not in str(
            journey["public_shipping_composition"]
        ):
            raise ValueError(f"{identifier} public black-box evidence is not PASS")

    evidence = _yaml(implementation / "EVIDENCE/M2-VALIDATION.yaml")
    if evidence["status"] != "PASS" or evidence["unexpected_failures"]:
        raise ValueError("M2 validation evidence is not clean")
    if evidence["component"]["passed"] != 11 or evidence["domain_integration"]["passed"] != 347:
        raise ValueError("M2 component or domain test count is invalid")
    if evidence["black_box_outcome"]["status"] != "PASS":
        raise ValueError("M2 black-box outcome is not PASS")
    for identifier in ("J05", "J15", "J18"):
        if evidence["black_box_outcome"]["journeys"][identifier]["status"] != "PASS":
            raise ValueError(f"{identifier} evidence is not PASS")
    if evidence["automated_codex_execution"] or evidence["provider_dispatch"]:
        raise ValueError("M2 improperly claims automated provider execution")
    regression = evidence["v1_release_harness_regression"]
    if not regression["signature_matches_m0_and_m1"] or regression["source_repaired_by_m2"]:
        raise ValueError("M2 did not preserve the controlled V1 regression")

    migration = _yaml(implementation / "MIGRATION/STATE.yaml")
    if (
        migration["migration_execution"] != "M2_ACCEPTED_EMPTY_RUNSTORE"
        or migration["project_mutation"]
    ):
        raise ValueError("M2 migration evidence is invalid")
    if not (root / "docs/architecture/DURABLE_RUNTIME.md").is_file():
        raise ValueError("M2 runtime authority documentation is missing")
    render(root, write=False)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    state = validate(arguments.repo_root)
    print(
        "m2-control-plane=PASS "
        f"status={state['program']['current_status']} "
        f"m3_state={next(item for item in state['milestones'] if item['id'] == 'M3')['state']}"
    )


if __name__ == "__main__":
    main()
