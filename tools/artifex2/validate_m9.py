"""Validate the shipping-composition M9/J09 qualification evidence."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

V1_COMMIT = "317ec177df8655ae4f94e24162107fd2acecceec"
V1_TREE = "ef130f94c2ef8f4d98ae925cd6e59e259b94b473"
V1_MODEL_SHA256 = "e970778462f6639675c8f862c0b1ca3247830e5a2290085ea3e95b90c4703394"
COMPOSITION = "INSTALLED_NATIVE_PUBLIC_CLI_REAL_V1_GIT_COPY_MULTI_PROCESS"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_APPROVAL_TOKEN = re.compile(r"approve-[A-Za-z0-9_-]+")
_SENSITIVE_KEY = re.compile(
    r"^(?:access_token|refresh_token|authorization|password|api_key|secret|"
    r"secret_value|credential_value)$",
    re.IGNORECASE,
)


class M9EvidenceError(ValueError):
    """Raised when J09 evidence could overstate the shipping outcome."""


def _object(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise M9EvidenceError(f"{name} must be an object")
    return cast(Mapping[str, Any], value)


def _sequence(value: object, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise M9EvidenceError(f"{name} must be an array")
    return value


def _exact(value: Mapping[str, Any], keys: set[str], name: str) -> None:
    if set(value) != keys:
        raise M9EvidenceError(f"{name} fields are invalid")


def _equal(value: object, expected: object, name: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise M9EvidenceError(f"{name} must equal {expected!r}")


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise M9EvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _secret_safe(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _SENSITIVE_KEY.fullmatch(str(key)):
                raise M9EvidenceError(f"secret-bearing evidence key at {path}.{key}")
            _secret_safe(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _secret_safe(child, f"{path}[{index}]")


def validate_outcome(
    value: Mapping[str, Any],
    *,
    expected_artifact_sha256: str,
    expected_source_commit: str,
) -> dict[str, Any]:
    _digest(expected_artifact_sha256, "expected artifact SHA-256")
    if not _COMMIT.fullmatch(expected_source_commit):
        raise M9EvidenceError("expected source commit must be a full Git SHA-1")
    _exact(
        value,
        {
            "approval_tokens_retained",
            "candidate",
            "composition",
            "custom_application_factory_used",
            "journeys",
            "provider_setup_invented",
            "public_process_calls",
            "schema_version",
            "simulated_migration",
            "source_tree_imported",
            "status",
            "v1_fixture",
        },
        "outcome",
    )
    _equal(value.get("schema_version"), "artifex.m9-j09-qualification/v1", "schema")
    _equal(value.get("status"), "PASS", "status")
    _equal(value.get("composition"), COMPOSITION, "composition")
    for field in (
        "approval_tokens_retained",
        "custom_application_factory_used",
        "provider_setup_invented",
        "simulated_migration",
        "source_tree_imported",
    ):
        _equal(value.get(field), False, field)
    _secret_safe(value)
    if _APPROVAL_TOKEN.search(json.dumps(value, sort_keys=True)):
        raise M9EvidenceError("approval token material is retained")

    candidate = _object(value.get("candidate"), "candidate")
    _exact(
        candidate,
        {"artifact_bytes", "artifact_name", "artifact_sha256", "installed", "source_commit"},
        "candidate",
    )
    if str(candidate.get("artifact_name", "")).casefold() != "artifex-setup.exe":
        raise M9EvidenceError("candidate artifact name is not the Windows shipping installer")
    artifact_bytes = candidate.get("artifact_bytes")
    if (
        not isinstance(artifact_bytes, int)
        or isinstance(artifact_bytes, bool)
        or artifact_bytes < 1
    ):
        raise M9EvidenceError("candidate artifact size must be positive")
    _equal(candidate.get("artifact_sha256"), expected_artifact_sha256, "candidate digest")
    _equal(candidate.get("source_commit"), expected_source_commit, "candidate source commit")
    installed = _object(candidate.get("installed"), "installed candidate")
    _exact(
        installed,
        {"executable_sha256", "manifest_sha256", "native", "source_commit"},
        "installed candidate",
    )
    _digest(installed.get("executable_sha256"), "installed executable digest")
    _digest(installed.get("manifest_sha256"), "installed manifest digest")
    _equal(installed.get("native"), True, "installed native")
    _equal(installed.get("source_commit"), expected_source_commit, "installed source commit")

    journeys = _object(value.get("journeys"), "journeys")
    _exact(journeys, {"J09"}, "journeys")
    j09 = _object(journeys.get("J09"), "J09")
    _exact(
        j09,
        {
            "activation_state",
            "backup_sha256",
            "dry_run_read_only",
            "empty_legacy_runtime_history",
            "exact_rollback",
            "first_new_2_0_run",
            "git_head_after",
            "git_head_before",
            "inspect_read_only",
            "real_v1_git_copy",
            "semantic_fingerprint_after",
            "semantic_fingerprint_before",
            "status",
        },
        "J09",
    )
    _equal(j09.get("status"), "PASS", "J09 status")
    _equal(j09.get("activation_state"), "ACTIVE", "J09 activation state")
    _equal(j09.get("first_new_2_0_run"), "PASS", "J09 first new run")
    for field in (
        "dry_run_read_only",
        "empty_legacy_runtime_history",
        "exact_rollback",
        "inspect_read_only",
        "real_v1_git_copy",
    ):
        _equal(j09.get(field), True, f"J09 {field}")
    _digest(j09.get("backup_sha256"), "J09 backup digest")
    before = _digest(j09.get("semantic_fingerprint_before"), "J09 semantic fingerprint before")
    after = _digest(j09.get("semantic_fingerprint_after"), "J09 semantic fingerprint after")
    _equal(after, before, "J09 semantic fingerprint preservation")
    _equal(j09.get("git_head_before"), V1_COMMIT, "J09 Git head before")
    _equal(j09.get("git_head_after"), V1_COMMIT, "J09 Git head after")

    fixture = _object(value.get("v1_fixture"), "V1 fixture")
    _exact(fixture, {"head", "model_sha256", "status", "tree"}, "V1 fixture")
    _equal(fixture.get("head"), V1_COMMIT, "V1 fixture head")
    _equal(fixture.get("tree"), V1_TREE, "V1 fixture tree")
    _equal(fixture.get("model_sha256"), V1_MODEL_SHA256, "V1 model digest")
    _equal(fixture.get("status"), "", "V1 fixture status")

    calls = _sequence(value.get("public_process_calls"), "public process calls")
    observed: list[str] = []
    for index, item in enumerate(calls):
        call = _object(item, f"public process call {index}")
        _exact(
            call,
            {"operation", "returncode", "stderr_sha256", "stdout_sha256"},
            "public process call",
        )
        operation = call.get("operation")
        if not isinstance(operation, str) or not operation:
            raise M9EvidenceError("public process operation must be text")
        observed.append(operation)
        _equal(call.get("returncode"), 0, f"{operation} returncode")
        _digest(call.get("stdout_sha256"), f"{operation} stdout digest")
        _equal(call.get("stderr_sha256"), EMPTY_SHA256, f"{operation} stderr digest")
    required = Counter(
        {
            "migration.inspect": 2,
            "migration.plan": 2,
            "migration.apply": 2,
            "migration.rollback.plan": 1,
            "migration.rollback": 1,
            "runtime.bootstrap": 1,
            "runtime.attempt.finish": 1,
            "runtime.accept": 1,
            "migration.validate": 1,
        }
    )
    if Counter(observed) != required:
        raise M9EvidenceError("public process calls do not match the J09 shipping sequence")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "journey": "J09",
        "composition": COMPOSITION,
        "candidate": {
            "source_commit": expected_source_commit,
            "artifact_sha256": expected_artifact_sha256,
            "artifact_bytes": artifact_bytes,
            "installed_executable_sha256": installed["executable_sha256"],
        },
        "v1": {"commit": V1_COMMIT, "tree": V1_TREE, "model_sha256": V1_MODEL_SHA256},
        "semantic_fingerprint": before,
        "backup_sha256": j09["backup_sha256"],
        "public_process_call_count": len(calls),
        "approval_tokens_retained": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        source = _object(json.loads(arguments.outcome.read_text(encoding="utf-8")), "outcome")
        result = validate_outcome(
            source,
            expected_artifact_sha256=arguments.expected_artifact_sha256,
            expected_source_commit=arguments.expected_source_commit,
        )
    except (OSError, json.JSONDecodeError, M9EvidenceError) as exc:
        result = {"schema_version": "1.0", "status": "FAIL", "error": type(exc).__name__}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
