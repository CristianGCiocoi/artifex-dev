"""Qualify M8A J12 through a clean installed wheel and fresh public CLI processes."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _call(
    python: Path, operation: str, arguments: dict[str, Any], *, expect_ok: bool = True
) -> dict[str, Any]:
    completed = subprocess.run(
        [str(python), "-I", "-m", "artifex.cli", "call", operation,
         "--arguments", json.dumps(arguments, separators=(",", ":"))],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False, timeout=120,
    )
    if not completed.stdout.strip():
        raise AssertionError(
            f"{operation} returned no JSON: exit={completed.returncode} "
            f"stderr={completed.stderr[:500]}"
        )
    result = json.loads(completed.stdout)
    if bool(result["ok"]) is not expect_ok:
        raise AssertionError(f"{operation} expected ok={expect_ok}: {result}")
    if expect_ok != (completed.returncode == 0):
        raise AssertionError(f"{operation} process exit disagrees with semantic result")
    return result


def _actor(actor_id: str, *permissions: str) -> dict[str, Any]:
    return {
        "actor_id": actor_id,
        "actor_type": "USER",
        "authenticated": True,
        "authentication_method": "m8a-black-box",
        "direct_permissions": list(permissions),
    }


def _lesson(
    project_id: str, identifier: str = "LES-J12", confidence: float = 0.94
) -> dict[str, Any]:
    return {
        "id": identifier,
        "scope": "PROJECT",
        "kind": "LESSON",
        "statement": "Pin dependency versions after validating the release candidate.",
        "provenance": [{
            "source": f"project:{project_id}",
            "observed_at": "2026-08-27T00:01:00Z",
            "artifact": "evidence/j12.json",
            "commit": "a" * 40,
            "integration": "manual",
            "evidence_ids": ["EVD-J12"],
        }],
        "confidence": confidence,
        "sensitivity": "INTERNAL",
        "promotion_policy": {
            "allowed_targets": ["INSTANCE", "PROJECT"],
            "minimum_confidence": 0.7,
            "minimum_evidence": 1,
            "maximum_sensitivity": "SENSITIVE",
            "require_validation": True,
        },
        "verified_against": [], "revisit_triggers": [], "state": "CURRENT",
        "project_id": project_id, "run_id": None, "promoted_from": None,
    }


def _current(project: Path) -> dict[str, Any]:
    paths = sorted((project / ".artifex" / "semantic-revisions").glob("*.json"))
    return json.loads(paths[-1].read_text(encoding="utf-8"))


def qualify(python: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="artifex-m8a-") as temporary:
        root = Path(temporary)
        project_a, project_b = root / "project-a", root / "project-b"
        catalog = root / "catalog.sqlite3"
        organization = root / "organizational-knowledge.sqlite3"
        for identifier, project in (("project-a", project_a), ("project-b", project_b)):
            _call(python, "project.create", {
                "project_root": str(project), "catalog_path": str(catalog),
                "project_id": identifier, "name": identifier,
            })
        record_actor = _actor("project-a-owner", "knowledge:record")
        _call(python, "knowledge.project.lesson.record", {
            "store_path": str(organization), "project_root": str(project_a),
            "project_id": "project-a", "lesson": _lesson("project-a"),
            "actor": record_actor,
        })
        low = _call(python, "knowledge.project.lesson.record", {
            "store_path": str(organization), "project_root": str(project_a),
            "project_id": "project-a", "lesson": _lesson("project-a", "LES-LOW", 0.2),
            "actor": record_actor,
        }, expect_ok=False)
        _call(python, "knowledge.project.lesson.record", {
            "store_path": str(organization), "project_root": str(project_a),
            "project_id": "project-a", "lesson": _lesson("project-a", "LES-STALE"),
            "actor": record_actor,
        })
        stale_record = _call(python, "knowledge.organizational.promote", {
            "store_path": str(organization), "source_project_root": str(project_a),
            "source_project_id": "project-a", "lesson_id": "LES-STALE",
            "applicability": {"project_ids": ["project-b"]},
            "fresh_until": "2026-08-27T00:02:01Z",
            "created_at": "2026-08-27T00:02:00Z",
            "evidence_digests": ["c" * 64], "validator_id": "validator-independent",
            "actor": _actor("org-promoter", "knowledge:promote"),
        })["value"]["knowledge"]
        stale = _call(python, "knowledge.organizational.recommend", {
            "store_path": str(organization), "knowledge_id": stale_record["id"],
            "target_project_root": str(project_b), "target_project_id": "project-b",
            "now": "2026-08-27T00:03:00Z",
            "actor": _actor("project-b-reader", "knowledge:recommend"),
        }, expect_ok=False)
        promoted = _call(python, "knowledge.organizational.promote", {
            "store_path": str(organization), "source_project_root": str(project_a),
            "source_project_id": "project-a", "lesson_id": "LES-J12",
            "applicability": {"project_ids": ["project-b"]},
            "fresh_until": "2027-08-27T00:00:00Z",
            "created_at": "2026-08-27T00:02:00Z",
            "evidence_digests": ["b" * 64], "validator_id": "validator-independent",
            "actor": _actor("org-promoter", "knowledge:promote"),
        })["value"]["knowledge"]
        found = _call(python, "knowledge.organizational.search", {
            "store_path": str(organization), "query": "dependency versions",
            "target_project_id": "project-b", "now": "2026-08-27T00:03:00Z",
            "actor": _actor("project-b-reader", "knowledge:read"),
        })["value"]["knowledge"]
        if [item["id"] for item in found] != [promoted["id"]]:
            raise AssertionError("eligible Organizational Knowledge was not found")
        if _call(python, "knowledge.organizational.search", {
            "store_path": str(organization), "query": "dependency versions",
            "target_project_id": "project-c", "now": "2026-08-27T00:03:00Z",
            "actor": _actor("project-c-reader", "knowledge:read"),
        })["value"]["knowledge"]:
            raise AssertionError("cross-Project applicability leaked")

        before = _current(project_b)
        model_path = project_b / ".artifex" / "project-model.json"
        before_bytes = model_path.read_bytes()
        recommendation = _call(python, "knowledge.organizational.recommend", {
            "store_path": str(organization), "knowledge_id": promoted["id"],
            "target_project_root": str(project_b), "target_project_id": "project-b",
            "now": "2026-08-27T00:03:00Z",
            "actor": _actor("project-b-reader", "knowledge:recommend"),
        })["value"]["recommendation"]
        after_recommendation = _current(project_b)
        if model_path.read_bytes() != before_bytes:
            raise AssertionError("recommendation changed target Project bytes")
        if (after_recommendation["revision"], after_recommendation["fingerprint"]) != (
            before["revision"], before["fingerprint"]
        ):
            raise AssertionError("recommendation changed target Project authority")

        forged = _call(python, "knowledge.project.adopt", {
            "store_path": str(organization), "recommendation_id": "ORGR-forged",
            "target_project_root": str(project_b), "expected_revision": 1,
            "actor": _actor("project-b-owner", "knowledge:adopt"),
        }, expect_ok=False)
        forged_model = json.loads(before_bytes)
        forged_model["knowledge_adoptions"] = [{"organizational_knowledge_id": "ORGK-forged"}]
        model_path.write_text(json.dumps(forged_model), encoding="utf-8")
        direct = _call(python, "knowledge.project.adopt", {
            "store_path": str(organization), "recommendation_id": recommendation["id"],
            "target_project_root": str(project_b), "expected_revision": 1,
            "accepted_at": "2026-08-27T00:04:00Z",
            "actor": _actor("project-b-owner", "knowledge:adopt"),
        }, expect_ok=False)
        model_path.write_bytes(before_bytes)
        accepted = _call(python, "knowledge.project.adopt", {
            "store_path": str(organization), "recommendation_id": recommendation["id"],
            "target_project_root": str(project_b), "expected_revision": 1,
            "accepted_at": "2026-08-27T00:04:00Z",
            "actor": _actor("project-b-owner", "knowledge:adopt"),
        })["value"]
        after = _current(project_b)
        adoption = after["model"]["knowledge_adoptions"][0]
        if after["revision"] != 2 or after["parent_fingerprint"] != before["fingerprint"]:
            raise AssertionError("explicit adoption did not produce continuous revision +1")
        if adoption["record_digest"] != promoted["record_digest"]:
            raise AssertionError("adoption did not retain Organizational Knowledge lineage")
        if accepted["proposal"]["source"] != "ORGANIZATIONAL_KNOWLEDGE_ADOPTION":
            raise AssertionError("adoption did not traverse an explicit semantic proposal")

        return {
            "schema_version": "1.0", "status": "PASS",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS",
            "source_tree_imported": False, "custom_application_factory_used": False,
            "journeys": {"J12": {
                "status": "PASS", "organizational_id_separate": promoted["id"],
                "recommendation_advisory": recommendation["advisory"],
                "target_bytes_unchanged_before_adoption": True,
                "target_revision_before_adoption": before["revision"],
                "accepted_revision": after["revision"],
                "lineage_retained": True, "restart_multi_process": True,
                "adversarial": {
                    "low_confidence": low["error"]["details"]["type"],
                    "stale": stale["error"]["details"]["type"],
                    "forged_recommendation": forged["error"]["details"]["type"],
                    "direct_mutation": direct["error"]["details"]["type"],
                    "cross_project_leak": False,
                },
            }},
            "migration": {"acceptance": "N/A", "mode": "CLASSIFICATION_QUARANTINE"},
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
