"""Run bounded public-process outcomes and emit scrubbed, hash-bound evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

ALLOWED_COMPOSITIONS = frozenset({"PUBLIC_PROCESS", "PACKAGED_PROCESS"})
SENSITIVE_KEY = re.compile(r"(?:token|secret|password|credential|api[_-]?key)", re.I)
REDACTIONS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r'(?i)(["\']?(?:token|secret|password|api[_-]?key)["\']?\s*[:=]\s*["\']?)[^\s,"\']+'
    ),
)
MAX_EVIDENCE_TEXT = 16_384


class ScenarioError(ValueError):
    """Raised when an outcome scenario is unsafe or malformed."""


def _load_mapping(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ScenarioError(f"scenario must be a mapping: {path}")
    return value


def _resolve_inside(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ScenarioError(f"scenario cwd escapes repository root: {relative}")
    return candidate


def _expand(value: str, root: Path) -> str:
    return value.replace("${PYTHON}", sys.executable).replace("${REPO}", str(root))


def _scrub(value: str) -> str:
    scrubbed = value
    for pattern in REDACTIONS:
        scrubbed = pattern.sub(r"\1<redacted>", scrubbed)
    return scrubbed[:MAX_EVIDENCE_TEXT]


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _lookup(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.split("."):
        if isinstance(current, Mapping):
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(current, str):
            current = current[int(part)]
        else:
            raise KeyError(dotted_path)
    return current


def _evaluate_expectations(
    expect: Mapping[str, Any], returncode: int, stdout: str, stderr: str
) -> list[str]:
    failures: list[str] = []
    expected_exit = expect.get("exit_code", 0)
    if not isinstance(expected_exit, int):
        raise ScenarioError("expect.exit_code must be an integer")
    if returncode != expected_exit:
        failures.append(f"exit code {returncode} != {expected_exit}")

    for stream_name, stream in (("stdout", stdout), ("stderr", stderr)):
        stream_expect = expect.get(stream_name, {})
        if stream_expect is None:
            continue
        if not isinstance(stream_expect, Mapping):
            raise ScenarioError(f"expect.{stream_name} must be a mapping")
        for needle in stream_expect.get("contains", []):
            if not isinstance(needle, str) or needle not in stream:
                failures.append(f"{stream_name} missing required text: {needle!r}")
        for pattern in stream_expect.get("matches", []):
            if not isinstance(pattern, str) or re.search(pattern, stream) is None:
                failures.append(f"{stream_name} missing required pattern: {pattern!r}")

    json_expect = expect.get("stdout_json", {})
    if json_expect:
        if not isinstance(json_expect, Mapping):
            raise ScenarioError("expect.stdout_json must be a mapping")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as error:
            failures.append(f"stdout is not JSON: {error.msg}")
        else:
            for dotted_path, expected in json_expect.items():
                try:
                    actual = _lookup(payload, str(dotted_path))
                except (KeyError, IndexError, ValueError):
                    failures.append(f"stdout JSON path missing: {dotted_path}")
                else:
                    if actual != expected:
                        failures.append(f"stdout JSON {dotted_path}={actual!r} != {expected!r}")
    return failures


def run_scenario(scenario_path: Path, repo_root: Path) -> dict[str, Any]:
    """Execute one scenario without a shell and return scrubbed evidence."""

    root = repo_root.resolve()
    scenario = _load_mapping(scenario_path)
    scenario_id = scenario.get("id")
    composition = scenario.get("composition")
    command_value = scenario.get("command")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ScenarioError("scenario id is required")
    if composition not in ALLOWED_COMPOSITIONS:
        raise ScenarioError(f"unsupported composition: {composition!r}")
    if (
        not isinstance(command_value, list)
        or not command_value
        or any(not isinstance(item, str) or not item for item in command_value)
    ):
        raise ScenarioError("command must be a non-empty string list")
    command = [_expand(item, root) for item in command_value]

    relative_cwd = scenario.get("cwd", ".")
    if not isinstance(relative_cwd, str):
        raise ScenarioError("cwd must be a string")
    cwd = _resolve_inside(root, relative_cwd)
    if not cwd.is_dir():
        raise ScenarioError(f"scenario cwd does not exist: {cwd}")

    timeout_seconds = scenario.get("timeout_seconds", 30)
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 600:
        raise ScenarioError("timeout_seconds must be an integer from 1 to 600")

    environment_value = scenario.get("environment", {})
    if not isinstance(environment_value, Mapping):
        raise ScenarioError("environment must be a mapping")
    environment = os.environ.copy()
    explicit_environment_keys: list[str] = []
    for key, raw_value in environment_value.items():
        if not isinstance(key, str) or not isinstance(raw_value, str):
            raise ScenarioError("environment keys and values must be strings")
        if SENSITIVE_KEY.search(key):
            raise ScenarioError(f"sensitive environment key is forbidden in scenario: {key}")
        environment[key] = _expand(raw_value, root)
        explicit_environment_keys.append(key)

    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        returncode = -1
        stdout = (
            error.stdout.decode("utf-8", "replace")
            if isinstance(error.stdout, bytes)
            else (error.stdout or "")
        )
        stderr = (
            error.stderr.decode("utf-8", "replace")
            if isinstance(error.stderr, bytes)
            else (error.stderr or "")
        )

    expect = scenario.get("expect", {})
    if not isinstance(expect, Mapping):
        raise ScenarioError("expect must be a mapping")
    failures = (
        ["process timed out"]
        if timed_out
        else _evaluate_expectations(expect, returncode, stdout, stderr)
    )
    scrubbed_stdout = _scrub(stdout)
    scrubbed_stderr = _scrub(stderr)
    command_fingerprint = hashlib.sha256(
        json.dumps(command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "scenario_id": scenario_id,
        "composition": composition,
        "status": "PASS" if not failures else "FAIL",
        "command_sha256": command_fingerprint,
        "cwd": relative_cwd.replace("\\", "/"),
        "explicit_environment_keys": sorted(explicit_environment_keys),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_sha256": _sha256_text(stdout),
        "stderr_sha256": _sha256_text(stderr),
        "stdout_excerpt": scrubbed_stdout,
        "stderr_excerpt": scrubbed_stderr,
        "failures": failures,
        "scrubbed": True,
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence", type=Path)
    arguments = parser.parse_args()
    result = run_scenario(arguments.scenario, arguments.repo_root)
    if arguments.evidence is not None:
        _write_json(arguments.evidence, result)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
