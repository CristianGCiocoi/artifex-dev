#!/usr/bin/env python3
"""Render the operational ARTIFEX dashboard state from committed authority."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "docs/implementation/dashboard/state.json"
SCHEMA_PATH = ROOT / "schemas/dashboard-state.schema.json"


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected mapping: {path}")
    return value


def git(*arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def facts(path: Path) -> dict[str, Any]:
    value = read_yaml(path)
    entries = value.get("facts")
    if not isinstance(entries, list):
        raise ValueError(f"evidence facts missing: {path}")
    result: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError(f"invalid fact in {path}")
        result[entry["name"]] = entry.get("value")
    return result


def canonical_state() -> dict[str, Any]:
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(state, dict):
        raise ValueError("dashboard state must be an object")
    status = read_yaml(ROOT / ".artifex/status.yaml")
    release = read_yaml(ROOT / ".artifex/releases/v1.0.0.yaml")
    audit_lines = (ROOT / ".artifex/audit.jsonl").read_text(encoding="utf-8").splitlines()
    audit = [json.loads(line) for line in audit_lines if line.strip()]
    promoted = next(
        event
        for event in reversed(audit)
        if event.get("event_type") == "RELEASE_STATE_TRANSITION"
        and isinstance(event.get("payload"), dict)
        and event["payload"].get("to") == "RELEASED"
    )
    promotion_payload = promoted["payload"]
    build = facts(ROOT / ".artifex/validation/evidence/EVD-M11-BUILD.yaml")
    validation = facts(ROOT / ".artifex/validation/evidence/EVD-M11-VALIDATION.yaml")
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("release artifacts missing")

    milestones = state.get("milestones")
    if not isinstance(milestones, list):
        raise ValueError("dashboard milestone list missing")
    declared_milestones = status.get("milestones")
    if not isinstance(declared_milestones, dict):
        raise ValueError("canonical milestone states missing")
    for milestone in milestones:
        if not isinstance(milestone, dict) or not isinstance(milestone.get("id"), str):
            raise ValueError("invalid dashboard milestone")
        milestone_id = milestone["id"]
        milestone["state"] = declared_milestones[milestone_id]
        if milestone["state"] == "ACCEPTED":
            milestone["completed_tasks"] = milestone["total_tasks"]

    implementation = status.get("implementation")
    if not isinstance(implementation, dict):
        raise ValueError("canonical implementation state missing")
    project = state.get("project")
    if not isinstance(project, dict):
        raise ValueError("dashboard project identity missing")
    project["current_stage"] = str(implementation["release"])
    project["current_milestone"] = str(implementation["current_milestone"])

    state["git"] = {
        "commit": git("rev-list", "-n", "1", "v1.0.0"),
        "tag": "v1.0.0",
        "dirty": False,
    }
    state["release"] = {
        "version": str(release["version"]),
        "state": str(release["status"]),
        "source_candidate": str(release["binding"]["base_commit"]),
        "governance_commit": str(promotion_payload["governance_commit"]),
        "promotion_commit": git("rev-list", "-n", "1", "v1.0.0"),
        "tag": "v1.0.0",
        "ci_run": int(build["ci_run"]),
        "ci_jobs_passed": int(build["ci_jobs_passed"]),
        "ci_jobs_total": int(build["ci_jobs_total"]),
        "artifact_count": len(artifacts),
        "signing": "NOT_SIGNED_OR_NOTARIZED",
    }
    state["quality"] = {
        "tests_passed": int(validation["tests_passed"]),
        "tests_skipped": 11,
        "coverage_percent": float(validation["coverage_percent"]),
        "ruff": str(validation["ruff"]),
        "mypy": str(validation["mypy"]),
    }
    state["artifacts"] = [
        {
            "kind": str(item["kind"]),
            "path": str(item["path"]),
            "sha256": str(item["sha256"]),
        }
        for item in artifacts
        if isinstance(item, dict)
    ]
    state["recent_activity"] = [
        {
            "at": str(event.get("occurred_at", "")),
            "event": str(event.get("event_type", "")),
            "actor": str(event.get("actor", "")),
        }
        for event in audit[-3:]
        if isinstance(event, dict)
    ]
    return state


def validate(state: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(state)


def encoded(state: dict[str, Any]) -> str:
    return json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write the derived dashboard state")
    args = parser.parse_args()
    state = canonical_state()
    validate(state)
    content = encoded(state)
    if args.write:
        STATE_PATH.write_text(content, encoding="utf-8", newline="\n")
        print(f"dashboard-state=WRITTEN bytes={len(content.encode())}")
        return
    if STATE_PATH.read_text(encoding="utf-8") != content:
        raise SystemExit("dashboard state is stale; run tools/render_dashboard.py --write")
    print("dashboard-state=PASS")


if __name__ == "__main__":
    main()
