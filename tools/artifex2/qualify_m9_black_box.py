"""Qualify J09 through an installed ARTIFEX shipping executable.

The harness imports no ARTIFEX product modules. Every product interaction uses
the public native CLI in a fresh process. It clones a real V1 Git Project,
proves inspect/dry-run read-only behavior, applies and exactly rolls back one
migration, reapplies it, and accepts exactly one new ARTIFEX 2.0 Run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

V1_COMMIT = "317ec177df8655ae4f94e24162107fd2acecceec"
V1_TREE = "ef130f94c2ef8f4d98ae925cd6e59e259b94b473"
V1_MODEL_SHA256 = "e970778462f6639675c8f862c0b1ca3247830e5a2290085ea3e95b90c4703394"
COMPOSITION = "INSTALLED_NATIVE_PUBLIC_CLI_REAL_V1_GIT_COPY_MULTI_PROCESS"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_APPROVAL_TOKEN = re.compile(r"approve-[A-Za-z0-9_-]+")


class QualificationFailure(RuntimeError):
    """A fail-closed J09 qualification outcome."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scrub(value: str) -> str:
    text = re.sub(r"approve-[A-Za-z0-9_-]+", "<approval-redacted>", value)
    text = re.sub(
        r'(?i)(["\']?(?:token|secret|password|credential|api[_-]?key)["\']?\s*[:=]\s*["\']?)[^\s,"\']+',
        r"\1<redacted>",
        text,
    )
    return text[:2_048]


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


def _git(
    root: Path,
    *arguments: str,
    environment: Mapping[str, str],
    cwd: Path | None = None,
) -> str:
    completed = _run(
        ["git", "-C", str(root), *arguments],
        cwd=cwd or root,
        environment=environment,
    )
    if completed.returncode != 0:
        raise QualificationFailure(
            "Git operation failed: " + _scrub(completed.stderr or completed.stdout)
        )
    return completed.stdout.strip()


def _object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationFailure(f"{name} is not a JSON object")
    return cast(dict[str, Any], value)


def _installed_identity(
    executable: Path,
    *,
    expected_source_commit: str,
    forbidden_repo_root: Path | None,
) -> dict[str, Any]:
    executable = executable.resolve(strict=True)
    install_root = executable.parent
    manifest_path = install_root / "artifex-install-manifest.json"
    if not manifest_path.is_file():
        raise QualificationFailure("installed ARTIFEX manifest is unavailable")
    try:
        manifest = _object(json.loads(manifest_path.read_text(encoding="utf-8")), "manifest")
        artifact = _object(manifest["artifact_manifest"], "artifact manifest")
        files = manifest["files"]
        if not isinstance(files, list):
            raise TypeError("files must be an array")
        relative = executable.relative_to(install_root).as_posix()
        entry = next(
            item
            for item in files
            if isinstance(item, dict) and item.get("path") == relative
        )
    except (OSError, KeyError, TypeError, ValueError, StopIteration, json.JSONDecodeError) as exc:
        raise QualificationFailure("installed ARTIFEX manifest is invalid") from exc
    executable_sha = _sha256_file(executable)
    if (
        manifest.get("install_root") != str(install_root)
        or artifact.get("artifact") != relative
        or artifact.get("sha256") != executable_sha
        or entry.get("sha256") != executable_sha
        or artifact.get("source_commit") != expected_source_commit
    ):
        raise QualificationFailure("installed manifest does not bind the expected native candidate")
    if forbidden_repo_root is not None:
        forbidden = forbidden_repo_root.resolve()
        if executable == forbidden or forbidden in executable.parents:
            raise QualificationFailure("native executable originated from the source repository")
    return {
        "executable_sha256": executable_sha,
        "manifest_sha256": _sha256_file(manifest_path),
        "source_commit": expected_source_commit,
        "native": True,
    }


class NativeCLI:
    def __init__(
        self,
        executable: Path,
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> None:
        self.executable = executable.resolve(strict=True)
        self.cwd = cwd
        self.environment = dict(environment)
        self.calls: list[dict[str, Any]] = []

    def call(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        *,
        project_root: Path,
        timeout: int = 120,
    ) -> dict[str, Any]:
        rendered_arguments = json.dumps(
            dict(arguments), separators=(",", ":"), ensure_ascii=False
        )
        completed = _run(
            [
                str(self.executable),
                "call",
                operation,
                "--arguments",
                rendered_arguments,
                "--project-root",
                str(project_root),
            ],
            cwd=self.cwd,
            environment=self.environment,
            timeout=timeout,
        )
        self.calls.append(
            {
                "operation": operation,
                "returncode": completed.returncode,
                "stdout_sha256": _sha256_text(completed.stdout),
                "stderr_sha256": _sha256_text(completed.stderr),
            }
        )
        try:
            payload = _object(json.loads(completed.stdout), f"{operation} output")
        except (json.JSONDecodeError, QualificationFailure) as exc:
            raise QualificationFailure(
                f"{operation} did not return public JSON: "
                + _scrub(completed.stderr or completed.stdout)
            ) from exc
        if completed.returncode != 0 or payload.get("ok") is not True:
            raise QualificationFailure(
                f"{operation} failed through the public CLI: " + _scrub(json.dumps(payload))
            )
        return _object(payload.get("value"), f"{operation}.value")


def _prepare_root(root: Path) -> Path:
    root = root.expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise QualificationFailure("qualification root must be new or empty")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _clone_v1(
    source_repository: Path,
    destination: Path,
    *,
    environment: Mapping[str, str],
) -> dict[str, str]:
    source_repository = source_repository.expanduser().resolve(strict=True)
    clone = _run(
        [
            "git",
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            str(source_repository),
            str(destination),
        ],
        cwd=destination.parent,
        environment=environment,
    )
    if clone.returncode != 0:
        raise QualificationFailure("V1 Git clone failed: " + _scrub(clone.stderr))
    _git(destination, "checkout", "--detach", V1_COMMIT, environment=environment)
    identity = {
        "head": _git(destination, "rev-parse", "HEAD", environment=environment),
        "tree": _git(destination, "rev-parse", "HEAD^{tree}", environment=environment),
        "status": _git(
            destination,
            "status",
            "--porcelain",
            "--untracked-files=all",
            environment=environment,
        ),
        "model_sha256": _sha256_file(destination / ".artifex/project-model.json"),
    }
    if identity != {
        "head": V1_COMMIT,
        "tree": V1_TREE,
        "status": "",
        "model_sha256": V1_MODEL_SHA256,
    }:
        raise QualificationFailure("real V1 Project copy does not match the frozen fixture")
    return identity


def _envelope(project_id: str) -> dict[str, Any]:
    return {
        "envelope_id": "m9-first-envelope",
        "version": 1,
        "project_id": project_id,
        "objective": "First new ARTIFEX 2.0 Run after V1 shipping migration",
        "baseline_revision": 1,
        "actor_id": "m9-acceptance-authority",
        "allowed_paths": [".artifex/project-model.json"],
        "allowed_capabilities": ["filesystem:workspace"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
    }


def _assert_migration_validation(value: Mapping[str, Any], *, first_run: str) -> None:
    checks = value.get("checks")
    if (
        value.get("migration_validation") != "PASS"
        or not isinstance(checks, dict)
        or not checks
        or not all(check is True for check in checks.values())
    ):
        raise QualificationFailure("shipping migration validation did not pass every check")
    observed = value.get("first_new_run")
    if not isinstance(observed, dict) or observed.get("status") != first_run:
        raise QualificationFailure(f"first new 2.0 Run expected {first_run}")


def _migration_common(
    project: Path, catalog: Path, runstore: Path, state_root: Path
) -> dict[str, str]:
    return {
        "project_root": str(project),
        "catalog_path": str(catalog),
        "runstore_path": str(runstore),
        "state_root": str(state_root),
    }


def qualify(
    *,
    artifex_executable: Path,
    candidate_artifact: Path,
    expected_artifact_sha256: str,
    expected_source_commit: str,
    v1_repository: Path,
    qualification_root: Path,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    if not _DIGEST.fullmatch(expected_artifact_sha256):
        raise QualificationFailure("expected candidate artifact SHA-256 is invalid")
    if not _COMMIT.fullmatch(expected_source_commit):
        raise QualificationFailure("expected candidate source commit is invalid")
    candidate_artifact = candidate_artifact.expanduser().resolve(strict=True)
    observed_artifact_sha = _sha256_file(candidate_artifact)
    if observed_artifact_sha != expected_artifact_sha256:
        raise QualificationFailure("candidate artifact digest does not match")
    installed = _installed_identity(
        artifex_executable,
        expected_source_commit=expected_source_commit,
        forbidden_repo_root=repo_root,
    )
    root = _prepare_root(qualification_root)
    project = root / "v1-project"
    instance = root / "instance"
    catalog = instance / "catalog.sqlite3"
    runstore = instance / "runstore.sqlite3"
    migration_state = instance / "migration"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["LOCALAPPDATA"] = str(root / "user-state")
    environment["XDG_STATE_HOME"] = str(root / "user-state")
    v1_identity = _clone_v1(v1_repository, project, environment=environment)
    cli = NativeCLI(
        artifex_executable,
        cwd=root,
        environment=environment,
    )
    common = _migration_common(project, catalog, runstore, migration_state)

    inspect_before = cli.call("migration.inspect", common, project_root=project)
    source = _object(inspect_before.get("source"), "inspection source")
    target = _object(inspect_before.get("target"), "inspection target")
    if (
        inspect_before.get("bounded_read_only") is not True
        or source.get("git_head") != V1_COMMIT
        or source.get("git_tree") != V1_TREE
        or source.get("project_model_sha256") != V1_MODEL_SHA256
        or source.get("git_clean") is not True
        or target.get("already_migrated") is not False
        or catalog.exists()
        or runstore.exists()
    ):
        raise QualificationFailure("read-only V1 inspection did not preserve the baseline")

    plan = cli.call("migration.plan", common, project_root=project)
    decision = _object(plan.get("decision"), "migration decision")
    token = decision.get("confirmation_token")
    if (
        plan.get("operation") != "DRY_RUN"
        or plan.get("applied") is not False
        or decision.get("approval_required") is not True
        or not isinstance(token, str)
        or catalog.exists()
        or runstore.exists()
        or _git(project, "status", "--porcelain", "--untracked-files=all", environment=environment)
    ):
        raise QualificationFailure("migration dry-run was not approval-bound and read-only")

    applied = cli.call(
        "migration.apply",
        {**common, "confirmation_token": token},
        project_root=project,
        timeout=300,
    )
    validation = _object(applied.get("validation"), "migration validation")
    if applied.get("status") != "PASS":
        raise QualificationFailure("shipping migration apply did not pass")
    _assert_migration_validation(validation, first_run="PENDING")
    record_path = str(applied.get("record_path", ""))
    backup = _object(
        _object(
            json.loads(Path(record_path).read_text(encoding="utf-8")), "migration record"
        ).get("backup"),
        "migration backup",
    )

    rollback_plan = cli.call(
        "migration.rollback.plan",
        {**common, "record_path": record_path},
        project_root=project,
    )
    rollback_decision = _object(rollback_plan.get("decision"), "rollback decision")
    rollback_token = rollback_decision.get("confirmation_token")
    if not isinstance(rollback_token, str):
        raise QualificationFailure("rollback dry-run did not issue an approval")
    rollback = cli.call(
        "migration.rollback",
        {
            **common,
            "record_path": record_path,
            "confirmation_token": rollback_token,
        },
        project_root=project,
        timeout=300,
    )
    rollback_checks = rollback.get("checks")
    if (
        rollback.get("status") != "PASS"
        or not isinstance(rollback_checks, dict)
        or not all(value is True for value in rollback_checks.values())
        or catalog.exists()
        or runstore.exists()
        or _git(project, "rev-parse", "HEAD", environment=environment) != V1_COMMIT
        or _git(project, "rev-parse", "HEAD^{tree}", environment=environment) != V1_TREE
        or _git(project, "status", "--porcelain", "--untracked-files=all", environment=environment)
    ):
        raise QualificationFailure("exact V1 rollback did not restore the frozen baseline")

    second_plan = cli.call("migration.plan", common, project_root=project)
    second_token = _object(second_plan.get("decision"), "second migration decision").get(
        "confirmation_token"
    )
    if not isinstance(second_token, str):
        raise QualificationFailure("second migration plan did not issue an approval")
    second_apply = cli.call(
        "migration.apply",
        {**common, "confirmation_token": second_token},
        project_root=project,
        timeout=300,
    )
    second_record = str(second_apply.get("record_path", ""))
    _assert_migration_validation(
        _object(second_apply.get("validation"), "second migration validation"),
        first_run="PENDING",
    )

    runtime_common: dict[str, Any] = {
        "store_path": str(runstore),
        "service_id": "m9-shipping-qualification",
    }
    cli.call(
        "runtime.bootstrap",
        {
            **runtime_common,
            "envelope": _envelope(str(source["project_id"])),
            "workstream_id": "m9-first-workstream",
            "run_id": "m9-first-run",
            "project_job_id": "m9-first-project-job",
            "attempt_id": "m9-first-attempt",
            "purpose": "First new 2.0 Run after shipping migration",
        },
        project_root=project,
    )
    cli.call(
        "runtime.attempt.finish",
        {
            **runtime_common,
            "attempt_id": "m9-first-attempt",
            "result_claim": "shipping migration validation passed",
        },
        project_root=project,
    )
    cli.call(
        "runtime.accept",
        {
            **runtime_common,
            "project_job_id": "m9-first-project-job",
            "evidence_valid": True,
            "reason": "independent M9 shipping qualification",
        },
        project_root=project,
    )
    final_validation = cli.call(
        "migration.validate",
        {**common, "record_path": second_record},
        project_root=project,
    )
    _assert_migration_validation(final_validation, first_run="PASS")
    if final_validation.get("activation_state") != "ACTIVE":
        raise QualificationFailure("migration did not activate after the first new 2.0 Run")
    inspect_after = cli.call("migration.inspect", common, project_root=project)
    source_after = _object(inspect_after.get("source"), "final inspection source")
    if (
        source_after.get("semantic_fingerprint") != source.get("semantic_fingerprint")
        or source_after.get("git_head") != V1_COMMIT
        or source_after.get("git_tree") != V1_TREE
    ):
        raise QualificationFailure("final migration state changed V1 semantic or Git identity")

    result = {
        "schema_version": "artifex.m9-j09-qualification/v1",
        "status": "PASS",
        "composition": COMPOSITION,
        "candidate": {
            "artifact_name": candidate_artifact.name,
            "artifact_sha256": observed_artifact_sha,
            "artifact_bytes": candidate_artifact.stat().st_size,
            "source_commit": expected_source_commit,
            "installed": installed,
        },
        "source_tree_imported": False,
        "custom_application_factory_used": False,
        "simulated_migration": False,
        "journeys": {
            "J09": {
                "status": "PASS",
                "real_v1_git_copy": True,
                "inspect_read_only": True,
                "dry_run_read_only": True,
                "backup_sha256": backup.get("sha256"),
                "exact_rollback": True,
                "semantic_fingerprint_before": source.get("semantic_fingerprint"),
                "semantic_fingerprint_after": source_after.get("semantic_fingerprint"),
                "git_head_before": V1_COMMIT,
                "git_head_after": _git(project, "rev-parse", "HEAD", environment=environment),
                "empty_legacy_runtime_history": True,
                "first_new_2_0_run": "PASS",
                "activation_state": "ACTIVE",
            }
        },
        "v1_fixture": v1_identity,
        "public_process_calls": cli.calls,
        "approval_tokens_retained": False,
        "provider_setup_invented": False,
    }
    serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
    if _APPROVAL_TOKEN.search(serialized):
        raise QualificationFailure("qualification result contains sensitive material")
    return result


def _blocked(code: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": "artifex.m9-j09-qualification/v1",
        "status": "BLOCKED",
        "composition": COMPOSITION,
        "blockers": [{"code": code, "detail": _scrub(detail)}],
        "journeys": {"J09": {"status": "BLOCKED"}},
        "approval_tokens_retained": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifex-executable", type=Path, required=True)
    parser.add_argument("--candidate-artifact", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--v1-repository", type=Path, required=True)
    parser.add_argument("--qualification-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = qualify(
            artifex_executable=arguments.artifex_executable,
            candidate_artifact=arguments.candidate_artifact,
            expected_artifact_sha256=arguments.expected_artifact_sha256,
            expected_source_commit=arguments.expected_source_commit,
            v1_repository=arguments.v1_repository,
            qualification_root=arguments.qualification_root,
            repo_root=arguments.repo_root,
        )
    except (OSError, subprocess.SubprocessError, QualificationFailure, json.JSONDecodeError) as exc:
        result = _blocked("J09_SHIPPING_QUALIFICATION_FAILED", str(exc))
    rendered = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 2)


if __name__ == "__main__":
    main()
