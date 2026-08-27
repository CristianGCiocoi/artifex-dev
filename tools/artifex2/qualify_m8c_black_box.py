"""Qualify the M8C public DeepSeek boundary from a clean installed wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _call(
    python: Path,
    operation: str,
    arguments: dict[str, Any],
    *,
    expect_ok: bool = True,
) -> dict[str, Any]:
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
    if not completed.stdout.strip():
        raise AssertionError(
            f"{operation} returned no JSON: exit={completed.returncode} "
            f"stderr={completed.stderr[:500]}"
        )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise AssertionError(f"{operation} returned a non-object result")
    if bool(result["ok"]) is not expect_ok:
        raise AssertionError(f"{operation} expected ok={expect_ok}: {result}")
    if expect_ok != (completed.returncode == 0):
        raise AssertionError(f"{operation} process exit disagrees with semantic result")
    return dict(result)


def _installed_module(python: Path) -> str:
    completed = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import pathlib,artifex;print(pathlib.Path(artifex.__file__).resolve())",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return completed.stdout.strip()


def _value(result: dict[str, Any], name: str) -> dict[str, Any]:
    value = result.get("value", {}).get(name)
    if not isinstance(value, dict):
        raise AssertionError(f"public result omitted object {name}: {result}")
    return value


def _provider(graph: dict[str, Any], provider_id: str) -> dict[str, Any]:
    providers = graph.get("providers")
    if not isinstance(providers, list):
        raise AssertionError("Capability Graph provider list is malformed")
    for provider in providers:
        if isinstance(provider, dict) and provider.get("provider_id") == provider_id:
            return provider
    raise AssertionError(f"Capability Graph omitted configured provider: {provider_id}")


def _setup(python: Path, project: Path) -> dict[str, Any]:
    provider_spec = {
        "provider_id": "deepseek",
        "command": ["deepseek"],
        "roles": ["EXECUTION_IMPLEMENTER"],
        "governance_mode": "PROVIDER_MANAGED",
        "credential_reference": {
            "broker": "deepseek-native-session",
            "reference": "default",
            "provider_id": "deepseek",
            "scopes": ["EXECUTION_IMPLEMENTER"],
            "secret_material_present": False,
        },
    }
    arguments = {
        "project_root": str(project),
        "integration_ids": ["deepseek"],
        "provider_specs": [provider_spec],
    }
    plan = _call(python, "distribution.setup.plan", arguments)
    decision = _value(plan, "decision")
    token = decision.get("confirmation_token")
    if not isinstance(token, str) or not token.startswith("approve-"):
        raise AssertionError("DeepSeek setup did not issue a bounded approval token")
    _call(
        python,
        "distribution.setup.apply",
        {**arguments, "confirmation_token": token},
    )
    setup_path = project / ".artifex" / "integrations.json"
    setup_text = setup_path.read_text(encoding="utf-8")
    for pattern in (
        r'(?i)"token"\s*:',
        r'(?i)"password"\s*:',
        r'(?i)"api[_-]?key"\s*:',
        r'(?i)"secret"\s*:(?!\s*false)',
    ):
        if re.search(pattern, setup_text):
            raise AssertionError("DeepSeek setup persisted credential material")
    setup = json.loads(setup_text)
    if not isinstance(setup, dict):
        raise AssertionError("DeepSeek setup state is not an object")
    return dict(setup)


def qualify(python: Path, wheel: Path) -> dict[str, Any]:
    module_path = _installed_module(python)
    if "site-packages" not in module_path.replace("\\", "/"):
        raise AssertionError(f"ARTIFEX was not imported from site-packages: {module_path}")
    with tempfile.TemporaryDirectory(prefix="artifex-m8c-") as temporary:
        root = Path(temporary)
        project = root / "project"
        _call(
            python,
            "project.create",
            {
                "project_root": str(project),
                "catalog_path": str(root / "catalog.sqlite3"),
                "project_id": "m8c-public-project",
                "name": "M8C DeepSeek Public Qualification",
            },
        )
        setup = _setup(python, project)
        graph = _value(
            _call(python, "providers.graph", {"project_root": str(project)}),
            "graph",
        )
        node = _provider(graph, "deepseek")
        readiness = _value(
            _call(
                python,
                "providers.readiness",
                {"project_root": str(project), "provider_id": "deepseek"},
            ),
            "readiness",
        )
        decision = _value(
            _call(
                python,
                "providers.resolve",
                {
                    "project_root": str(project),
                    "provider_id": "deepseek",
                    "project_id": "m8c-public-project",
                    "project_job_id": "m8c-public-job",
                    "role": "EXECUTION_IMPLEMENTER",
                    "capabilities": ["repository_write", "test_execution"],
                    "envelope": {
                        "allowed_providers": ["deepseek"],
                        "allowed_capabilities": ["repository_write", "test_execution"],
                    },
                    "actor": {
                        "actor_id": "m8c-qualifier",
                        "actor_type": "ARTIFEX_SERVICE",
                        "delegated_roles": ["EXECUTION_IMPLEMENTER"],
                    },
                    "data_classification": "INTERNAL",
                },
            ),
            "decision",
        )
        certification = _value(
            _call(
                python,
                "providers.certifications",
                {
                    "provider_id": "deepseek",
                    "project_id": "m8c-public-project",
                },
            ),
            "certifications",
        )
        roles = certification.get("roles")
        if not isinstance(roles, list) or len(roles) != 1:
            raise AssertionError("DeepSeek execution certification projection is malformed")
        execution = roles[0]
        if execution.get("role") != "EXECUTION_IMPLEMENTER":
            raise AssertionError("DeepSeek projection conflated provider roles")
        if execution.get("state") == "LIVE_ROLE_CERTIFIED":
            raise AssertionError("non-live qualification inherited stale live evidence")
        omitted = certification.get("omitted_roles")
        if not isinstance(omitted, list) or {
            item.get("role") for item in omitted if isinstance(item, dict)
        } != {"INTERACTION", "HARNESS"}:
            raise AssertionError("DeepSeek omitted roles are not explicit")

        legacy = root / "legacy"
        (legacy / ".artifex").mkdir(parents=True)
        (legacy / ".artifex" / "integrations.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "authority": "ARTIFEX_PROJECT_STATE",
                    "enabled": ["deepseek"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        legacy_graph = _value(
            _call(python, "providers.graph", {"project_root": str(legacy)}),
            "graph",
        )
        migrated = _provider(legacy_graph, "deepseek")
        reference = migrated["configuration"].get("credential_reference")
        if not isinstance(reference, dict) or reference.get("secret_material_present") is not False:
            raise AssertionError("V1 DeepSeek setup did not migrate to a secret-free reference")

        available = readiness.get("state") == "AVAILABLE"
        blocker = (
            None
            if available
            else {
                "id": "BLK-M8C-DEEPSEEK-LIVE-PREREQUISITES",
                "class": "EXTERNAL_PREREQUISITE",
                "detail": readiness.get("detail"),
            }
        )
        return {
            "schema_version": "1.0",
            "milestone": "M8C",
            "status": (
                "READY_FOR_LIVE_EXECUTION_QUALIFICATION"
                if available
                else "BLOCKED_EXTERNAL_PREREQUISITE"
            ),
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_MULTI_PROCESS",
            "shipping_artifact": "INSTALLED_WHEEL",
            "artifact": wheel.name,
            "artifact_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "installed_module": module_path,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "credential_material_read": False,
            "credential_material_persisted": False,
            "setup": {
                "schema_version": setup["schema_version"],
                "fresh_process_consumed": True,
                "vendor_configuration_mutated": setup["vendor_configuration_mutated"],
                "secret_material_present": False,
            },
            "readiness": readiness,
            "capability_graph": {
                "provider_id": node["provider_id"],
                "globally_available": node["globally_available"],
                "certified_roles": node["certified_roles"],
            },
            "contextual_resolution": decision,
            "provider_certification": certification,
            "migration": {
                "v1_setup_revalidated": True,
                "runtime_history_fabricated": False,
                "secret_material_present": False,
                "state": migrated["readiness"]["state"],
            },
            "role_claims": {
                "EXECUTION_IMPLEMENTER": "NOT_LIVE_CERTIFIED",
                "INTERACTION": "EXPERIMENTAL_NOT_CLAIMED",
                "HARNESS": "EXPERIMENTAL_NOT_CLAIMED",
            },
            "blockers": [] if blocker is None else [blocker],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.python.resolve(), arguments.wheel.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


if __name__ == "__main__":
    main()
