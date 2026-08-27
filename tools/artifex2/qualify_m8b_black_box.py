"""Qualify M8B public non-live behavior through a clean installed wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _call(
    python: Path,
    operation: str,
    arguments: dict[str, Any],
    *,
    project_root: Path | None = None,
    expect_ok: bool = True,
) -> dict[str, Any]:
    command = [
        str(python),
        "-I",
        "-m",
        "artifex.cli",
        "call",
        operation,
        "--arguments",
        json.dumps(arguments, separators=(",", ":")),
    ]
    if project_root is not None:
        command.extend(("--project-root", str(project_root)))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
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


def _request() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "kind": "RESEARCH_REQUEST",
        "request_id": "RSR-J13-NONLIVE",
        "purpose": "qualify Pandora research authority boundaries",
        "stage": "RESEARCH",
        "questions": ["Does the evidence preserve Project Authority?"],
        "project_constraints": ["Pandora is evidence-only"],
        "required_freshness": "2026-08-28",
        "required_source_quality": "primary sources",
        "resource_envelope": {"network": "provider-owned", "max_sources": 3},
        "desired_alternatives": 1,
        "desired_risks": True,
        "output_form": "research-bundle-v1",
    }


def _bundle(instance_id: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "kind": "RESEARCH_BUNDLE",
        "bundle_id": "RSB-J13-NONLIVE",
        "request_id": "RSR-J13-NONLIVE",
        "findings": ["Use an explicit semantic proposal and separate acceptance."],
        "alternatives": [{"name": "explicit-adoption"}],
        "claims": [{
            "claim": "Project Authority remains singular",
            "evidence_source_ids": ["SRC-J13"],
            "confidence": 0.95,
        }],
        "unresolved_questions": [],
        "source_manifest": [{
            "source_id": "SRC-J13",
            "uri": "https://example.invalid/j13-primary",
            "title": "J13 primary fixture",
            "retrieved_at": "2026-08-28T08:00:00+00:00",
            "quality": "primary",
        }],
        "generation_metadata": {
            "provider_id": "pandora",
            "provider_instance_id": instance_id,
            "provider_version": "0.1.0.dev0",
            "provider_role": "RESEARCH",
        },
    }


def _current(project: Path) -> dict[str, Any]:
    paths = sorted((project / ".artifex" / "semantic-revisions").glob("*.json"))
    return json.loads(paths[-1].read_text(encoding="utf-8"))


def qualify(python: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="artifex-m8b-") as temporary:
        root = Path(temporary)
        project = root / "project"
        exchange = root / "exchange"
        catalog = root / "catalog.sqlite3"
        exchange.mkdir()
        instance_id = "pandora-nonlive-fixture"
        manifest = {
            "schema_version": "1.0",
            "provider_id": "pandora",
            "role": "RESEARCH",
            "instance_id": instance_id,
            "version": "0.1.0.dev0",
            "contract": "filesystem-contract-v1",
            "issued_at": "2026-08-28T08:00:00+00:00",
        }
        (exchange / "pandora-provider.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        _call(
            python,
            "project.create",
            {
                "project_root": str(project),
                "catalog_path": str(catalog),
                "project_id": "project-j13",
                "name": "project-j13",
            },
        )
        before = _current(project)
        model_path = project / ".artifex" / "project-model.json"
        before_bytes = model_path.read_bytes()
        request = _request()
        exported = _call(
            python,
            "research.pandora.request",
            {"exchange_root": str(exchange), "request": request},
        )["value"]
        request_directory = exchange / request["request_id"]
        (request_directory / "research-bundle.json").write_text(
            json.dumps(_bundle(instance_id), sort_keys=True), encoding="utf-8"
        )
        (request_directory / "research-report.md").write_text(
            "# Non-live Pandora fixture\n\nEvidence only.\n", encoding="utf-8"
        )
        imported = _call(
            python,
            "research.pandora.import",
            {"exchange_root": str(exchange), "request": request},
        )["value"]
        after_import = _current(project)
        if model_path.read_bytes() != before_bytes:
            raise AssertionError("Pandora import changed Project Model bytes")
        if (after_import["revision"], after_import["fingerprint"]) != (
            before["revision"],
            before["fingerprint"],
        ):
            raise AssertionError("Pandora import changed Project Authority")
        readiness = _call(
            python,
            "research.pandora.readiness",
            {"exchange_root": str(exchange)},
        )["value"]
        blocked = _call(
            python,
            "research.pandora.adoption.propose",
            {
                "exchange_root": str(exchange),
                "request": request,
                "expected_revision": before["revision"],
            },
            project_root=project,
            expect_ok=False,
        )
        forged = _bundle("forged-instance")
        (request_directory / "research-bundle.json").write_text(
            json.dumps(forged, sort_keys=True), encoding="utf-8"
        )
        tampered = _call(
            python,
            "research.pandora.import",
            {"exchange_root": str(exchange), "request": request},
            expect_ok=False,
        )
        return {
            "schema_version": "1.0",
            "status": "BLOCKED_EXTERNAL_PREREQUISITE",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS_NON_LIVE",
            "shipping_artifact": "INSTALLED_WHEEL",
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "simulated_provider": True,
            "provider_claimed_live": False,
            "provider": {
                "id": "pandora",
                "role": "RESEARCH",
                "readiness_state": readiness["state"],
                "globally_available": readiness["globally_available"],
                "certification_ladder": {
                    "ADAPTER_IMPLEMENTED": "PASS",
                    "ROLE_CONFORMANCE_VERIFIED": "PASS",
                    "PACKAGED": "PASS",
                    "PUBLIC_COMPOSITION_VERIFIED": "PASS",
                    "LIVE_ROLE_CERTIFIED": "BLOCKED_EXTERNAL_PREREQUISITE",
                },
            },
            "journeys": {
                "J13": {
                    "status": "BLOCKED_EXTERNAL_PREREQUISITE",
                    "request_exported": Path(exported["request_path"]).is_file(),
                    "evidence_imported": imported["authority"] == "research-evidence-only",
                    "project_bytes_unchanged": True,
                    "project_revision_unchanged": True,
                    "explicit_adoption_blocked_without_live_certification": not blocked["ok"],
                    "forged_provider_lineage_rejected": not tampered["ok"],
                }
            },
            "blocker": {
                "id": "BLK-M8B-PANDORA-RUNTIME-UNAVAILABLE",
                "class": "EXTERNAL_PREREQUISITE",
                "required_resolution": (
                    "Provide a real reachable Pandora runtime, supported RESEARCH exchange "
                    "identity, and independent live public-composition evidence"
                ),
            },
            "artifact_sha256": hashlib.sha256(python.read_bytes()).hexdigest(),
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
