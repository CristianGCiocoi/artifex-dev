"""Fail-closed validation for ARTIFEX 2.0 M3 live public outcomes."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

from tools.artifex2.bootstrap_control_plane import ACCEPTANCE_CLASSES
from tools.artifex2.control_plane import derive, render
from tools.artifex2.validate_m2 import validate as validate_m2

M3_ACTIVATION_BASELINE = "25c4be8b390d7f803cb6b43b31278ac8a372954d"
M3_CONTRACT_DIGEST = "4c715b81581f4688f3b38d34829a967760e7f862f8408a477f37245f886d07eb"
LIVE_EVIDENCE_PATH = "implementation/EVIDENCE/M3-PUBLIC-OUTCOME.json"


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


def validate_outcome_evidence(value: dict[str, Any]) -> None:
    """Reject blocked, synthetic, source-tree, or overclaimed M3 evidence."""

    if value.get("status") != "PASS" or value.get("live_gate", {}).get("status") != "PASS":
        raise ValueError("M3 live public outcome is not PASS")
    if value.get("live_gate", {}).get("blockers"):
        raise ValueError("M3 PASS evidence contains live blockers")
    if value.get("shipping_artifact") != "INSTALLED_WHEEL":
        raise ValueError("M3 outcome did not use an installed wheel")
    if "INSTALLED_WHEEL_PUBLIC_CLI_REAL_CODEX" not in str(value.get("composition")):
        raise ValueError("M3 outcome composition is not installed-wheel real-Codex")
    forbidden = {
        "source_tree_imported": True,
        "custom_application_factory_used": True,
        "provider_injection_used": True,
        "simulated_provider": True,
    }
    for field, forbidden_value in forbidden.items():
        if value.get(field) is forbidden_value:
            raise ValueError(f"M3 outcome used forbidden shortcut: {field}")
    probe = value.get("live_gate", {}).get("codex_probe", {})
    if (
        probe.get("status") != "PASS"
        or probe.get("version_exit_code") != 0
        or probe.get("auth_exit_code") != 0
        or probe.get("credential_material_read") is not False
    ):
        raise ValueError("M3 Codex executable/auth live gate is not valid")
    journeys = value.get("journeys", {})
    if journeys.get("J16", {}).get("status") != "PASS":
        raise ValueError("J16 fresh-process setup persistence is not PASS")
    if not journeys["J16"].get("fresh_process_consumed_setup"):
        raise ValueError("J16 evidence stops at configuration writing")
    if journeys["J16"].get("healthy_but_ineligible_excluded") is not True:
        raise ValueError("J16 evidence equates health with contextual eligibility")
    interpretation = journeys.get("J01", {})
    if interpretation.get("status") != "M3_VERTICAL_SLICE_ONLY":
        raise ValueError("M3 must not mark full J01 PASS")
    if (
        interpretation.get("full_journey_status") != "NOT_CLAIMED"
        or interpretation.get("primary_proving_milestone") != "M7"
    ):
        raise ValueError("M3 J01 interpretation is not bounded to M7")
    vertical = journeys.get("M3_CODEX_VERTICAL_SLICE", {})
    if vertical.get("status") != "PASS":
        raise ValueError("M3 Codex vertical slice is not PASS")
    execution = vertical.get("provider_execution", {})
    if execution.get("live") is not True or execution.get("simulated") is not False:
        raise ValueError("M3 provider execution is not proven live")
    if vertical.get("provider_result_self_accepted") is not False:
        raise ValueError("provider result crossed the Acceptance Authority boundary")
    if vertical.get("semantic_revision") != 2:
        raise ValueError("real Codex ProjectJob did not reach semantic revision 2")
    if vertical.get("workspace", {}).get("isolated") is not True:
        raise ValueError("real Codex execution workspace was not isolated")
    roles = vertical.get("role_certifications", {})
    expected = {"INTERACTION", "EXECUTION_IMPLEMENTER"}
    certified = {role for role, state in roles.items() if state == "LIVE_ROLE_CERTIFIED"}
    if certified != expected:
        raise ValueError(f"Codex role certifications are incomplete or conflated: {roles}")
    operations = [item.get("operation") for item in value.get("public_process_calls", [])]
    required_operations = {
        "distribution.setup.plan",
        "distribution.setup.apply",
        "providers.graph",
        "providers.readiness",
        "providers.resolve",
        "providers.interact",
        "runtime.provider.execute",
        "providers.certifications",
        "runtime.accept",
        "runtime.workspace.promote",
    }
    if not required_operations.issubset(set(operations)):
        raise ValueError("M3 evidence omits required public-process operations")


def validate(
    repo_root: Path,
    *,
    evidence_path: Path | None = None,
    require_live: bool = False,
) -> dict[str, Any]:
    root = repo_root.resolve()
    validate_m2(root)
    try:
        _git(root, "merge-base", "--is-ancestor", M3_ACTIVATION_BASELINE, "HEAD")
    except subprocess.CalledProcessError as exc:
        raise ValueError("M3 activation baseline is not an ancestor") from exc
    state = derive(root)
    program = state["program"]
    milestones = {item["id"]: item for item in state["milestones"]}
    if not program.get("m3_started") or milestones["M3"]["state"] not in {"ACTIVE", "ACCEPTED"}:
        raise ValueError("M3 is not active or accepted")
    acceptance = _yaml(root / "implementation" / "ACCEPTANCE" / "M3.yaml")
    if acceptance.get("contract_digest") != M3_CONTRACT_DIGEST:
        raise ValueError("M3 acceptance contract digest is invalid")
    if tuple(acceptance.get("evidence_classes", {})) != ACCEPTANCE_CLASSES:
        raise ValueError("M3 acceptance omits or reorders an evidence class")
    if acceptance.get("mandatory_journeys") != ["J01", "J16"]:
        raise ValueError("M3 mandatory Journey set is invalid")
    contracts = _yaml(root / "implementation" / "CONTRACT-REGISTRY.yaml")
    m3 = next(item for item in contracts["contracts"] if item["id"] == "M3-CONTRACT")
    if m3.get("digest") != M3_CONTRACT_DIGEST or m3.get("implementation_state") not in {
        "ACTIVE",
        "ACCEPTED",
    }:
        raise ValueError("registered M3 contract is invalid")
    selected = evidence_path or root / LIVE_EVIDENCE_PATH
    accepted = milestones["M3"]["state"] == "ACCEPTED" or acceptance.get("verdict") == "ACCEPTED"
    if selected.is_file():
        evidence = json.loads(selected.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            raise ValueError("M3 public outcome evidence must be an object")
        if evidence.get("status") == "PASS":
            validate_outcome_evidence(evidence)
        elif accepted or require_live:
            raise ValueError("M3 live evidence is BLOCKED or FAIL")
    elif accepted or require_live:
        raise ValueError(f"M3 live evidence is missing: {selected}")
    if accepted:
        required = {
            name: item.get("status")
            for name, item in acceptance["evidence_classes"].items()
            if item.get("required_m3")
        }
        if any(status != "PASS" for status in required.values()):
            raise ValueError(f"accepted M3 has a non-PASS evidence class: {required}")
        if not acceptance.get("mandatory_work_complete"):
            raise ValueError("accepted M3 mandatory work is incomplete")
    render(root, write=False)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--require-live", action="store_true")
    arguments = parser.parse_args()
    state = validate(
        arguments.repo_root,
        evidence_path=arguments.evidence,
        require_live=arguments.require_live,
    )
    print(f"m3-control-plane=PASS status={state['program']['current_status']}")


if __name__ == "__main__":
    main()
