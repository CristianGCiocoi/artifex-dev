"""Qualify M5 journeys through an installed wheel and public CLI processes."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast


def _call(python: Path, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(python),
            "-I",
            "-m",
            "artifex.cli",
            "call",
            operation,
            "--arguments",
            json.dumps(arguments, separators=(",", ":")),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise AssertionError(
            f"{operation} failed: exit={completed.returncode} "
            f"stdout={completed.stdout[:500]} stderr={completed.stderr[:500]}"
        )
    result = json.loads(completed.stdout)
    if result.get("ok") is not True:
        raise AssertionError(f"{operation} returned a failed semantic result: {result}")
    return cast(dict[str, Any], result)


def _document_states(result: dict[str, Any]) -> dict[str, str]:
    value = result["value"]
    return {str(item["name"]): str(item["state"]) for item in value["documents"]}


def qualify(python: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="artifex-m5-black-box-") as directory:
        root = Path(directory)
        project = root / "project"
        catalog = root / "catalog.sqlite3"
        common = {"name": "M5 Public Project", "catalog_path": str(catalog)}
        created = _call(
            python,
            "project.create",
            {
                **common,
                "project_root": str(project),
                "project_id": "project-m5-public",
                "description": "Operational reality and documentation lifecycle",
            },
        )
        if created["value"]["semantic_revision"] != 1:
            raise AssertionError("Project creation did not establish semantic revision 1")

        baseline = _call(python, "documentation.status", common)
        baseline_states = _document_states(baseline)
        if not baseline_states or set(baseline_states.values()) != {"CURRENT"}:
            raise AssertionError(f"documentation baseline is not CURRENT: {baseline_states}")

        user_guide = project / ".artifex" / "docs" / "USER_GUIDE.md"
        user_guide.write_text("externally tampered projection\n", encoding="utf-8")
        tampered = _call(python, "documentation.status", common)
        tampered_states = _document_states(tampered)
        if tampered_states.get("USER_GUIDE.md") != "STALE":
            raise AssertionError("tampered documentation was not classified STALE")
        if tampered["value"]["semantic_revision"] != 1:
            raise AssertionError("projection tampering changed semantic authority")

        regenerated = _call(
            python,
            "documentation.regenerate",
            {**common, "documents": ["USER_GUIDE.md"]},
        )
        regenerated_states = _document_states(regenerated)
        if regenerated_states.get("USER_GUIDE.md") != "CURRENT":
            raise AssertionError("selective documentation regeneration did not converge")

        project_dashboard = _call(python, "dashboard.project", common)["value"]
        platform_dashboard = _call(
            python, "dashboard.platform", {"catalog_path": str(catalog)}
        )["value"]
        if project_dashboard.get("authoritative") is not False:
            raise AssertionError("Project dashboard incorrectly claims authority")
        if project_dashboard.get("semantic_revision") != 1:
            raise AssertionError("Project dashboard does not match Project Authority")
        projects = platform_dashboard.get("projects", [])
        if len(projects) != 1 or projects[0].get("project_id") != "project-m5-public":
            raise AssertionError("Platform dashboard does not match Project Catalog")

        model_path = project / ".artifex" / "project-model.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["project"]["description"] = "external reality changed outside authority"
        model_path.write_text(
            json.dumps(model, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        observed = _call(python, "project.observe", common)["value"]
        if observed.get("semantic_revision") != 1:
            raise AssertionError("observation silently changed semantic revision")
        if observed.get("semantic_revision_unchanged") is not True:
            raise AssertionError("observation did not prove unchanged semantic authority")
        if observed["observation"].get("status") != "DIVERGED":
            raise AssertionError("external model change was not observed as divergence")
        proposal_id = observed.get("proposal_id")
        if not isinstance(proposal_id, str) or not proposal_id:
            raise AssertionError("divergence did not create an explicit proposal")
        reality_before = _call(python, "reality.state", common)["value"]
        if reality_before.get("open_divergence_count") != 1:
            raise AssertionError("open divergence was not projected")

        accepted = _call(
            python,
            "project.accept",
            {**common, "proposal_id": proposal_id, "expected_revision": 1},
        )["value"]
        if accepted.get("semantic_revision") != 2:
            raise AssertionError("Project Authority did not independently accept revision 2")
        reality_after = _call(python, "reality.state", common)["value"]
        if reality_after.get("open_divergence_count") != 0:
            raise AssertionError("accepted reconciliation did not close divergence")

        return {
            "schema_version": "1.0",
            "status": "PASS",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS",
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "journeys": {
                "J08": {
                    "status": "PASS",
                    "automatic_baseline": True,
                    "tamper_classified_stale": True,
                    "selective_regeneration": True,
                    "project_dashboard_store_parity": True,
                    "platform_dashboard_catalog_parity": True,
                },
                "J14": {
                    "status": "PASS",
                    "external_change_detected": True,
                    "semantic_revision_before_acceptance": 1,
                    "explicit_proposal": True,
                    "accepted_semantic_revision": 2,
                    "divergence_closed_after_acceptance": True,
                },
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.python.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


if __name__ == "__main__":
    main()
