"""Fail-closed validation for the ARTIFEX 2.0 M0 implementation-control baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from tools.artifex2.bootstrap_control_plane import ACCEPTANCE_CLASSES, validate_handoff
from tools.artifex2.capture_v1_baseline import capture
from tools.artifex2.control_plane import derive, render

SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r'''(?i)(?:api[_-]?key|password|secret|token)\s*[:=]\s*["']?[^\s,"']{16,}'''),
)


def _read_yaml(path: Path) -> dict[str, Any]:
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


def _validate_dag(dag: dict[str, Any]) -> None:
    milestones = dag["milestones"]
    identifiers = {item["id"] for item in milestones}
    expected = {
        "M0",
        "M1",
        "M2",
        "M3",
        "M4",
        "M5",
        "M6A",
        "M6B",
        "M7",
        "M8A",
        "M8B",
        "M8C",
        "M9",
        "M10",
        "M11",
        "M12",
    }
    if identifiers != expected:
        raise ValueError(f"milestone set mismatch: {sorted(identifiers)}")
    dependencies = {item["id"]: set(item["depends_on"]) for item in milestones}
    if any(not values <= identifiers for values in dependencies.values()):
        raise ValueError("milestone dependency references an unknown milestone")
    remaining = {key: set(value) for key, value in dependencies.items()}
    resolved: set[str] = set()
    while remaining:
        ready = {key for key, value in remaining.items() if value <= resolved}
        if not ready:
            raise ValueError("milestone DAG contains a cycle")
        resolved |= ready
        remaining = {key: value for key, value in remaining.items() if key not in ready}


def _validate_secret_exclusion(implementation: Path) -> None:
    for path in implementation.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {
            ".yaml",
            ".yml",
            ".json",
            ".md",
            ".html",
        }:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(text):
                raise ValueError(f"potential secret value in implementation artifact: {path}")


def validate(repo_root: Path, handoff_root: Path | None) -> dict[str, Any]:
    root = repo_root.resolve()
    implementation = root / "implementation"
    state = derive(root)
    program = state["program"]
    dag = _read_yaml(implementation / "MILESTONE-DAG.yaml")
    _validate_dag(dag)

    contracts = _read_yaml(implementation / "CONTRACT-REGISTRY.yaml")
    if [item["id"] for item in contracts["adrs"]] != [
        f"ADR-T{number:03d}" for number in range(1, 25)
    ]:
        raise ValueError("ADR registry must contain ADR-T001 through ADR-T024 in order")
    if [item["id"] for item in contracts["invariants"]] != [
        f"INV-F{number:02d}" for number in range(1, 35)
    ]:
        raise ValueError("invariant registry must contain INV-F01 through INV-F34 in order")

    journeys = _read_yaml(implementation / "JOURNEYS/STATE.yaml")
    if [item["id"] for item in journeys["journeys"]] != [
        f"J{number:02d}" for number in range(1, 21)
    ]:
        raise ValueError("journey state must contain J01 through J20 in order")
    if journeys["m0_mandatory"]:
        raise ValueError("M0 must not invent mandatory journeys")

    provider_state = _read_yaml(implementation / "PROVIDERS/ROLE-CERTIFICATION.yaml")
    provider_schema = json.loads(
        (root / "schemas/artifex2/provider-role-certification.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(provider_schema)
    jsonschema.validate(provider_state, provider_schema)

    acceptance = _read_yaml(implementation / "ACCEPTANCE/M0.yaml")
    if tuple(acceptance["evidence_classes"]) != ACCEPTANCE_CLASSES:
        raise ValueError("M0 acceptance must explicitly report all evidence classes in order")
    if acceptance["mandatory_journeys"]:
        raise ValueError("M0 acceptance must not claim mandatory journeys")

    machine_program = _read_yaml(implementation / "PROGRAM-STATE.yaml")
    milestone_states = machine_program["milestone_states"]
    if milestone_states["M1"]["started"] or program["m1_started"]:
        raise ValueError("M1 started before M0 acceptance")
    if acceptance["verdict"] != "ACCEPTED":
        if milestone_states["M1"]["state"] != "BLOCKED_DEPENDENCY":
            raise ValueError("M1 must remain dependency-blocked before M0 acceptance")
    else:
        required_statuses = {
            name: value["status"]
            for name, value in acceptance["evidence_classes"].items()
            if value["required_m0"]
        }
        if any(value != "PASS" for value in required_statuses.values()):
            raise ValueError(f"accepted M0 has incomplete evidence classes: {required_statuses}")
        if milestone_states["M0"]["state"] != "ACCEPTED":
            raise ValueError("accepted M0 verdict disagrees with program milestone state")
        if milestone_states["M1"]["state"] != "READY":
            raise ValueError("M1 must become READY, but remain unstarted, after M0 acceptance")
        if machine_program["acceptance_classes"] != acceptance["evidence_classes"]:
            raise ValueError("program and milestone acceptance evidence classes disagree")
        workstreams = _read_yaml(implementation / "WORKSTREAM-REGISTRY.yaml")["workstreams"]
        if any(item["state"] != "COMPLETE" for item in workstreams):
            raise ValueError("accepted M0 has an incomplete workstream")
        if program.get("dashboard_state") != "CURRENT":
            raise ValueError("accepted M0 dashboard state is not CURRENT")

    fixture_path = implementation / "MIGRATION/V1-RELEASE-FIXTURE.yaml"
    if fixture_path.is_file():
        fixture = _read_yaml(fixture_path)
        captured = capture(root, fixture["source_ref"], program["intake_commit"])
        for field in ("source_commit", "source_tree", "file_count", "aggregate_sha256"):
            if fixture[field] != captured[field]:
                raise ValueError(f"V1 fixture drift: {field}")

    gap_path = implementation / "EVIDENCE/V1-KNOWN-GAPS.yaml"
    if gap_path.is_file() and _read_yaml(gap_path)["status"] != "PASS":
        raise ValueError("known V1 gap baseline has unexpected results")

    outcome_path = implementation / "EVIDENCE/M0-PUBLIC-CLI-HEALTH.json"
    if outcome_path.is_file():
        outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
        if outcome["status"] != "PASS" or outcome["composition"] != "PUBLIC_PROCESS":
            raise ValueError("public-process Outcome Runner evidence is not PASS")

    changed_runtime = _git(
        root, "diff", "--name-only", program["intake_commit"], "--", "src/artifex"
    )
    if changed_runtime:
        raise ValueError(f"M0 changed target runtime/provider implementation: {changed_runtime}")

    if handoff_root is not None:
        manifest, validated_files = validate_handoff(handoff_root.resolve())
        if manifest["handoff_id"] != program["handoff_id"] or len(validated_files) != 84:
            raise ValueError("live handoff validation disagrees with control-plane intake")

    _validate_secret_exclusion(implementation)
    render(root, write=False)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--handoff-root", type=Path)
    arguments = parser.parse_args()
    state = validate(arguments.repo_root, arguments.handoff_root)
    print(
        "m0-control-plane=PASS "
        f"status={state['program']['current_status']} "
        f"m1_started={str(state['program']['m1_started']).lower()}"
    )


if __name__ == "__main__":
    main()
