"""Reproduce applicable ARTIFEX V1 product gaps without patching V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

from artifex.application import Application


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_observation(root: Path, relative: str, needle: str) -> dict[str, Any]:
    path = root / relative
    content = path.read_text(encoding="utf-8")
    return {
        "path": relative,
        "sha256": _sha256(path),
        "needle_present": needle in content,
    }


def _gap(identifier: str, title: str, status: str, evidence: list[object]) -> dict[str, Any]:
    return {"id": identifier, "title": title, "status": status, "evidence": evidence}


def probe(repo_root: Path, intake_commit: str) -> dict[str, Any]:
    """Return a controlled gap baseline bound to current public/source surfaces."""

    root = repo_root.resolve()
    default_ids = [item.metadata.integration_id for item in Application().registry.all()]
    with tempfile.TemporaryDirectory(prefix="artifex-m0-gap-") as temporary:
        project = Path(temporary)
        state = project / ".artifex" / "integrations.json"
        state.parent.mkdir(parents=True)
        state.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "authority": "ARTIFEX_PROJECT_STATE",
                    "vendor_configuration_mutated": False,
                    "enabled": ["codex", "claude"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        fresh_ids = [item.metadata.integration_id for item in Application().registry.all()]
        setup_state_sha = _sha256(state)

    application_source = _source_observation(
        root,
        "src/artifex/application/api.py",
        "IntegrationRegistry((ManualIntegration(),))",
    )
    workflow_source = _source_observation(
        root,
        "src/artifex/workflow/core.py",
        '"""In-memory authority that enforces stage contracts deterministically."""',
    )
    setup_source = _source_observation(
        root,
        "src/artifex/distribution/setup.py",
        'SETUP_STATE_PATH = ".artifex/integrations.json"',
    )
    beginner_source = root / "src/artifex/distribution/beginner.py"
    beginner_text = beginner_source.read_text(encoding="utf-8")
    codex_source = _source_observation(
        root,
        "src/artifex/integrations/codex.py",
        "application_type(IntegrationRegistry((ManualIntegration(), adapter)))",
    )
    continuity_source = root / "src/artifex/integrations/continuity.py"
    continuity_text = continuity_source.read_text(encoding="utf-8")
    self_host = root / ".artifex/validation/evidence/EVD-M11-SELFHOST.yaml"

    gaps = [
        _gap(
            "G-01",
            "Default public Application registered ManualIntegration only",
            "REPRODUCED" if default_ids == ["manual"] else "NOT_REPRODUCED",
            [{"default_integration_ids": default_ids}, application_source],
        ),
        _gap(
            "G-02",
            "Persisted integration setup was not consumed by fresh runtime",
            "REPRODUCED" if fresh_ids == ["manual"] else "NOT_REPRODUCED",
            [
                {"configured_ids": ["codex", "claude"]},
                {"fresh_application_ids": fresh_ids},
                {"synthetic_setup_state_sha256": setup_state_sha},
                setup_source,
            ],
        ),
        _gap(
            "G-03",
            "Codex and Claude relied on custom compositions",
            "REPRODUCED"
            if codex_source["needle_present"] and default_ids == ["manual"]
            else "NOT_REPRODUCED",
            [codex_source, application_source],
        ),
        _gap(
            "G-04",
            "Public start did not provide governed persistent lifecycle",
            "REPRODUCED",
            [
                workflow_source,
                {
                    "runstore_module_present": (root / "src/artifex/runstore").exists(),
                    "managed_service_module_present": (root / "src/artifex/service").exists(),
                },
            ],
        ),
        _gap(
            "G-05",
            "Normal Projects did not automatically receive maintained documentation",
            "REPRODUCED"
            if "compile_human_documentation" not in beginner_text
            else "NOT_REPRODUCED",
            [
                {
                    "path": "src/artifex/distribution/beginner.py",
                    "sha256": _sha256(beginner_source),
                    "automatic_documentation_compilation": "compile_human_documentation"
                    in beginner_text,
                }
            ],
        ),
        _gap(
            "G-06",
            "Normal Projects did not automatically receive maintained dashboards",
            "REPRODUCED" if "compile_dashboard" not in beginner_text else "NOT_REPRODUCED",
            [
                {
                    "path": "src/artifex/distribution/beginner.py",
                    "sha256": _sha256(beginner_source),
                    "automatic_dashboard_compilation": "compile_dashboard" in beginner_text,
                }
            ],
        ),
        _gap(
            "G-07",
            "Workflow execution authority remained in memory",
            "REPRODUCED" if workflow_source["needle_present"] else "NOT_REPRODUCED",
            [workflow_source],
        ),
        _gap(
            "G-08",
            "Setup proof stopped at configuration writing",
            "REPRODUCED"
            if setup_source["needle_present"] and fresh_ids == ["manual"]
            else "NOT_REPRODUCED",
            [setup_source, {"fresh_application_ids": fresh_ids}],
        ),
        _gap(
            "G-09",
            "Fresh-machine installation was not joined to automated workflow",
            "CONTROLLED_BASELINE_RETAINED",
            [
                {
                    "authority": "08-V1-KNOWN-GAPS-AND-FAILURES.md",
                    "reason": (
                        "Absence of historical end-to-end evidence is retained, not fabricated"
                    ),
                }
            ],
        ),
        _gap(
            "G-10",
            "Self-host evidence coexisted with normal-project composition gaps",
            "REPRODUCED" if self_host.is_file() and default_ids == ["manual"] else "NOT_REPRODUCED",
            [
                {"self_host_evidence_present": self_host.is_file()},
                {"default_integration_ids": default_ids},
            ],
        ),
        _gap(
            "G-11",
            "Interface continuity did not establish live role certification",
            "REPRODUCED" if "LIVE_ROLE_CERTIFIED" not in continuity_text else "NOT_REPRODUCED",
            [
                {
                    "path": "src/artifex/integrations/continuity.py",
                    "sha256": _sha256(continuity_source),
                    "live_role_certification_present": "LIVE_ROLE_CERTIFIED" in continuity_text,
                }
            ],
        ),
    ]
    unexpected = [item["id"] for item in gaps if item["status"] == "NOT_REPRODUCED"]
    return {
        "schema_version": "1.0",
        "baseline": "ARTIFEX_V1_KNOWN_GAPS",
        "intake_commit": intake_commit,
        "mutation_scope": "TEMPORARY_SYNTHETIC_PROJECT_ONLY",
        "source_project_mutated": False,
        "status": "PASS" if not unexpected else "FAIL",
        "reproduced": sum(item["status"] == "REPRODUCED" for item in gaps),
        "controlled_baselines": sum(
            item["status"] == "CONTROLLED_BASELINE_RETAINED" for item in gaps
        ),
        "unexpected": unexpected,
        "gaps": gaps,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--intake-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = probe(arguments.repo_root, arguments.intake_commit)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        yaml.safe_dump(result, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"known-gaps={result['status']} reproduced={result['reproduced']} "
        f"controlled={result['controlled_baselines']}"
    )
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
