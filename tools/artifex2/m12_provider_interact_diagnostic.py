"""Capture secret-safe shape evidence for one installed providers.interact call."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture provider interaction shape without retaining provider output."
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider-id", default="claude")
    parser.add_argument("--semantic-revision", type=int, default=1)
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    model = json.loads(
        (project_root / ".artifex" / "project-model.json").read_text(encoding="utf-8")
    )
    project = _mapping(_mapping(model).get("project") if _mapping(model) else None)
    project_id = project.get("id") if project else None
    if not isinstance(project_id, str) or not project_id:
        raise SystemExit("persisted Project id is unavailable")
    marker = (
        f"ARTIFEX_INTERACTION project_id={project_id} "
        f"semantic_revision={args.semantic_revision}"
    )
    arguments = {
        "provider_id": args.provider_id,
        "project_id": project_id,
        "role": "INTERACTION",
        "prompt": (
            f"Return exactly: {marker}. "
            "Do not call tools and do not modify files."
        ),
    }
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [
            str(args.executable.resolve()),
            "service",
            "call",
            "providers.interact",
            "--arguments",
            json.dumps(arguments, sort_keys=True, separators=(",", ":")),
            "--project-root",
            str(project_root),
            "--state-root",
            str(args.state_root.resolve()),
        ],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    public_value: Mapping[str, Any] | None = None
    try:
        parsed = json.loads(stdout)
        public_value = _mapping(parsed)
    except json.JSONDecodeError:
        pass
    value = _mapping(public_value.get("value")) if public_value else None
    interaction = _mapping(value.get("interaction")) if value else None
    response = interaction.get("response") if interaction else None
    response_text = response if isinstance(response, str) else None
    result = {
        "schema_version": "1.0",
        "status": (
            "PASS"
            if completed.returncode == 0
            and public_value is not None
            and public_value.get("ok") is True
            else "FAIL"
        ),
        "vm_id": 106,
        "provider_id": args.provider_id,
        "operation": "providers.interact diagnostic",
        "process_exit_code": completed.returncode,
        "public_cli_json_valid": public_value is not None,
        "public_cli_ok": public_value.get("ok") is True if public_value else False,
        "live": interaction.get("live") is True if interaction else False,
        "response_length": len(response_text) if response_text is not None else None,
        "marker_count": response_text.count(marker) if response_text is not None else None,
        "response_sha256": (
            _sha256_text(response_text) if response_text is not None else None
        ),
        "stdout_sha256": _sha256_text(stdout),
        "stderr_sha256": _sha256_text(stderr),
        "credential_files_read": False,
        "credential_material_extracted": False,
        "provider_output_retained": False,
        "canonical_acceptance": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
