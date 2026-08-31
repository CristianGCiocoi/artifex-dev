"""Reversible shipping migration for a real ARTIFEX V1 Project."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import uuid
import zipfile
from collections.abc import Mapping
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from artifex.capabilities import ProviderCompositionLoader
from artifex.compilation._util import model_fingerprint
from artifex.distribution.approvals import (
    ApprovalStore,
    consume_decision,
    issue_decision,
)
from artifex.distribution.models import DecisionExplanation, RiskLevel
from artifex.distribution.setup import SETUP_STATE_PATH
from artifex.documentation import DocumentationLifecycle
from artifex.project import ProjectAuthority, ProjectCatalog, ProjectControlService
from artifex.project.repository import MODEL_PATH, ProjectRepository
from artifex.runtime import SQLiteRunStore

MIGRATION_SCHEMA = "artifex.v1-migration/v1"
_TARGET_PROJECT_PREFIXES = (
    ".artifex/authority/",
    ".artifex/dashboard/",
    ".artifex/docs/",
    ".artifex/reality/",
)
_RUNTIME_TABLES = (
    "workstreams",
    "runs",
    "project_jobs",
    "attempts",
    "workspaces",
    "acceptance_decisions",
    "dispatch_authorizations",
    "evidence_records",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(_json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return completed.stdout.strip()


def _tree_inventory(root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    if root.exists():
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
            if path.is_symlink():
                raise ValueError(f"migration source contains an ineligible symlink: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            files.append(
                {
                    "path": relative,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    aggregate = _sha256_bytes(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return {"file_count": len(files), "aggregate_sha256": aggregate, "files": files}


def _db_family(path: Path) -> tuple[Path, ...]:
    return (path, Path(f"{path}-wal"), Path(f"{path}-shm"))


def _file_state(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "exists": path.is_file(),
        "bytes": path.stat().st_size if path.is_file() else 0,
        "sha256": _sha256_file(path) if path.is_file() else None,
    }


def _runtime_inventory(path: Path) -> dict[str, Any]:
    counts = {name: 0 for name in _RUNTIME_TABLES}
    states: dict[str, list[str]] = {"runs": [], "project_jobs": [], "attempts": []}
    if path.is_file():
        uri = f"file:{path.as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            existing = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            for name in _RUNTIME_TABLES:
                if name in existing:
                    counts[name] = int(
                        connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                    )
            for name in states:
                if name in existing:
                    states[name] = [
                        str(row[0])
                        for row in connection.execute(
                            f"SELECT state FROM {name} ORDER BY rowid"
                        ).fetchall()
                    ]
    return {"counts": counts, "states": states}


def _sqlite_logical_state(path: Path) -> dict[str, Any]:
    """Fingerprint durable SQLite content without depending on WAL/SHM bytes."""

    if not path.is_file():
        return {"path": str(path), "exists": False, "logical_sha256": None}
    uri = f"file:{path.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        dump = "\n".join(connection.iterdump()).encode("utf-8")
    return {
        "path": str(path),
        "exists": True,
        "logical_sha256": _sha256_bytes(dump),
    }


def _preservation_inventory(
    source_inventory: Mapping[str, Any],
    target_inventory: Mapping[str, Any],
    *,
    verified_extensions: tuple[str, ...] = (),
) -> dict[str, Any]:
    source_files = {
        str(item["path"]): str(item["sha256"])
        for item in source_inventory.get("files", [])
        if isinstance(item, Mapping)
    }
    target_files = {
        str(item["path"]): str(item["sha256"])
        for item in target_inventory.get("files", [])
        if isinstance(item, Mapping)
    }
    preserved = sorted(
        path for path, digest in source_files.items() if target_files.get(path) == digest
    )
    observed_changed = {
        path
        for path, digest in source_files.items()
        if path in target_files and target_files[path] != digest
    }
    extended = sorted(observed_changed & set(verified_extensions))
    changed = sorted(observed_changed - set(extended))
    missing = sorted(set(source_files) - set(target_files))
    added = sorted(set(target_files) - set(source_files))
    return {
        "preserved": preserved,
        "changed": changed,
        "extended": extended,
        "missing": missing,
        "bootstrap_added": added,
        "stale": [],
    }


def _inside(candidate: Path, root: Path) -> bool:
    return candidate == root or candidate.is_relative_to(root)


class V1MigrationService:
    """Own the inspect/dry-run/backup/migrate/validate/activate lifecycle.

    The Project repository remains semantic authority. Catalog and RunStore are
    external instance authorities, and V1 runtime history is never synthesized.
    """

    def __init__(
        self,
        project_root: str | Path,
        *,
        catalog_path: str | Path,
        runstore_path: str | Path,
        state_root: str | Path,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        self.catalog_path = Path(catalog_path).expanduser().resolve()
        self.runstore_path = Path(runstore_path).expanduser().resolve()
        self.state_root = Path(state_root).expanduser().resolve()
        self.approval_store = approval_store
        for label, path in (
            ("catalog", self.catalog_path),
            ("RunStore", self.runstore_path),
            ("migration state", self.state_root),
        ):
            if _inside(path, self.project_root):
                raise ValueError(f"{label} authority must remain outside the Project repository")
        if self.catalog_path == self.runstore_path:
            raise ValueError("Catalog and RunStore must use separate authority files")

    def inspect(self) -> dict[str, Any]:
        """Read and classify a V1 source without mutating Project or instance state."""

        if not self.project_root.is_dir():
            raise FileNotFoundError(f"V1 Project does not exist: {self.project_root}")
        if not (self.project_root / ".git").exists():
            raise ValueError("V1 migration requires a real Git repository with history")
        model_path = self.project_root / MODEL_PATH
        if not model_path.is_file():
            raise ValueError("V1 Project Model is missing")
        repository = ProjectRepository(self.project_root)
        model = repository.load()
        model_bytes = model_path.read_bytes()
        head = _git(self.project_root, "rev-parse", "HEAD")
        tree = _git(self.project_root, "rev-parse", "HEAD^{tree}")
        status = _git(self.project_root, "status", "--porcelain", "--untracked-files=all")
        artifex_inventory = _tree_inventory(self.project_root / ".artifex")
        target_paths = [
            item["path"]
            for item in artifex_inventory["files"]
            if any(
                str(item["path"]).startswith(prefix.removeprefix(".artifex/"))
                for prefix in _TARGET_PROJECT_PREFIXES
            )
        ]
        return {
            "schema_version": MIGRATION_SCHEMA,
            "operation": "INSPECT",
            "bounded_read_only": True,
            "source": {
                "classification": "ARTIFEX_V1_PROJECT",
                "project_id": model.project.id,
                "project_name": model.project.name,
                "project_model_schema": model.schema_version,
                "project_model_sha256": _sha256_bytes(model_bytes),
                "semantic_fingerprint": model_fingerprint(model.to_dict()),
                "git_head": head,
                "git_tree": tree,
                "git_clean": not bool(status),
                "artifex_inventory": {
                    "file_count": artifex_inventory["file_count"],
                    "aggregate_sha256": artifex_inventory["aggregate_sha256"],
                    "files": artifex_inventory["files"],
                },
            },
            "target": {
                "already_migrated": bool(target_paths),
                "target_paths_present": target_paths,
                "catalog": _file_state(self.catalog_path),
                "runstore": _file_state(self.runstore_path),
                "runtime_inventory": _runtime_inventory(self.runstore_path),
            },
            "provider_setup": self._provider_setup_state(),
        }

    def plan(self, *, issue_token: bool = True) -> dict[str, Any]:
        inspection = self.inspect()
        self._require_applicable(inspection)
        decision = self._migration_decision(inspection, issue_token=issue_token)
        return {
            "schema_version": MIGRATION_SCHEMA,
            "operation": "DRY_RUN",
            "applied": False,
            "inspection": inspection,
            "lifecycle": [
                "INSPECT",
                "DRY_RUN",
                "BASELINE_BACKUP",
                "MIGRATE",
                "VALIDATE",
                "ACTIVATE",
            ],
            "decision": decision.to_dict(),
            "runtime_history_policy": "EMPTY_NEW_RUNSTORE_NO_LEGACY_IMPORT",
        }

    def apply(self, confirmation_token: str | None) -> dict[str, Any]:
        inspection = self.inspect()
        self._require_applicable(inspection)
        decision = self._migration_decision(inspection, issue_token=False)
        consume_decision(
            decision,
            confirmation_token,
            approval_store=self.approval_store,
        )
        fingerprint = str(inspection["source"]["semantic_fingerprint"])
        migration_id = f"MIG-{fingerprint[:12]}-{uuid.uuid4().hex[:12]}"
        migration_root = self.state_root / migration_id
        migration_root.mkdir(parents=True, exist_ok=False)
        backup_path = migration_root / "backup.zip"
        record_path = migration_root / "record.json"
        backup = self._backup(backup_path, inspection)
        try:
            adopted = ProjectControlService(self.catalog_path).adopt(
                self.project_root,
                actor="artifex-v1-migration",
            )
            SQLiteRunStore(self.runstore_path)
            empty_runtime = _runtime_inventory(self.runstore_path)
            if any(empty_runtime["counts"].values()):
                raise ValueError("new M9 RunStore is not empty before the first 2.0 Run")
            post_inventory = _tree_inventory(self.project_root / ".artifex")
            external_post = self._external_states()
            provider_setup = self._revalidate_provider_setup(
                self._required_mapping(inspection, "provider_setup")
            )
            preservation = _preservation_inventory(
                self._required_mapping(
                    self._required_mapping(inspection, "source"),
                    "artifex_inventory",
                ),
                post_inventory,
                verified_extensions=self._verified_semantic_extensions(backup_path),
            )
            record = {
                "schema_version": MIGRATION_SCHEMA,
                "migration_version": MIGRATION_SCHEMA,
                "migration_id": migration_id,
                "state": "ACTIVE_PENDING_FIRST_NEW_RUN",
                "recorded_at": _now(),
                "project_root": str(self.project_root),
                "catalog_path": str(self.catalog_path),
                "runstore_path": str(self.runstore_path),
                "source": inspection["source"],
                "backup": backup,
                "post_migration": {
                    "semantic_revision": adopted["semantic_revision"],
                    "semantic_fingerprint": adopted["semantic_fingerprint"],
                    "artifex_inventory": {
                        "file_count": post_inventory["file_count"],
                        "aggregate_sha256": post_inventory["aggregate_sha256"],
                    },
                    "external_state": external_post,
                    "runtime_inventory_before_first_run": empty_runtime,
                    "provider_setup": provider_setup,
                    "preservation_inventory": preservation,
                    "documentation_disposition": {
                        "legacy_docs_reused": False,
                        "bootstrap_documents_generated": True,
                        "stale_inventory": [],
                    },
                    "target_runtime_bootstrap_actions": [
                        "PROJECT_AUTHORITY_REVISION_ACCEPTED",
                        "PROJECT_CATALOG_REGISTERED",
                        "DOCUMENTATION_LIFECYCLE_INITIALIZED",
                        "DASHBOARD_PROJECTION_INITIALIZED",
                        "EMPTY_RUNSTORE_INITIALIZED",
                        "PROVIDER_SETUP_READINESS_REVALIDATED",
                    ],
                },
                "rollback": {
                    "status": "AVAILABLE",
                    "requires_unchanged_post_migration_state": True,
                },
            }
            _atomic_json(record_path, record)
            validation = self.validate(record_path)
            if validation["migration_validation"] != "PASS":
                failed = sorted(
                    name for name, passed in validation["checks"].items() if not passed
                )
                raise ValueError(
                    "post-migration validation failed: " + ", ".join(failed)
                )
            recorded = dict(record)
            recorded["validation"] = {
                "initial_outcome": validation["migration_validation"],
                "checks": validation["checks"],
                "first_new_run": validation["first_new_run"],
                "recorded_at": _now(),
            }
            _atomic_json(record_path, recorded)
            return {
                "schema_version": MIGRATION_SCHEMA,
                "operation": "MIGRATE",
                "status": "PASS",
                "record_path": str(record_path),
                "migration_id": migration_id,
                "validation": validation,
            }
        except Exception:
            self._restore_backup(backup_path, inspection["source"], enforce_post=None)
            raise

    def validate(self, record_path: str | Path) -> dict[str, Any]:
        record_file, record = self._record(record_path)
        source = self._required_mapping(record, "source")
        repository = ProjectRepository(self.project_root)
        model_path = self.project_root / MODEL_PATH
        model = repository.load()
        revision = ProjectAuthority(self.project_root).current()
        entry = ProjectCatalog(self.catalog_path).get(str(source["project_id"]))
        documents = DocumentationLifecycle(self.project_root).status(revision)
        dashboard_path = self.project_root / ".artifex/dashboard/project.json"
        runtime = _runtime_inventory(self.runstore_path)
        pre_run = self._required_mapping(
            self._required_mapping(record, "post_migration"),
            "runtime_inventory_before_first_run",
        )
        pre_counts = self._required_mapping(pre_run, "counts")
        zero_legacy_runtime = not any(int(value) for value in pre_counts.values())
        first_run = self._first_new_run(runtime)
        post = self._required_mapping(record, "post_migration")
        preservation = self._required_mapping(post, "preservation_inventory")
        provider_setup = self._required_mapping(post, "provider_setup")
        checks = {
            "git_head_preserved": _git(self.project_root, "rev-parse", "HEAD")
            == source["git_head"],
            "project_model_bytes_preserved": _sha256_file(model_path)
            == source["project_model_sha256"],
            "semantic_fingerprint_preserved": model_fingerprint(model.to_dict())
            == source["semantic_fingerprint"]
            == revision.fingerprint,
            "project_identity_preserved": revision.project_id == source["project_id"],
            "accepted_target_semantic_revision": revision.number
            == post["semantic_revision"],
            "catalog_registered": entry.project_id == source["project_id"]
            and str(self.project_root) in entry.locations,
            "documentation_current": bool(documents)
            and all(item.state.value == "CURRENT" for item in documents),
            "dashboard_initialized": dashboard_path.is_file(),
            "no_fabricated_runtime_history": zero_legacy_runtime,
            "backup_verified": self._backup_valid(record),
            "semantic_asset_inventory_preserved": not preservation.get("changed")
            and not preservation.get("missing"),
            "bootstrap_state_marked": bool(preservation.get("bootstrap_added"))
            and bool(post.get("target_runtime_bootstrap_actions")),
            "provider_setup_truthful": self._provider_setup_valid(provider_setup),
        }
        migration_pass = all(checks.values())
        return {
            "schema_version": MIGRATION_SCHEMA,
            "operation": "VALIDATE",
            "record_path": str(record_file),
            "migration_validation": "PASS" if migration_pass else "FAIL",
            "checks": checks,
            "runtime_inventory": runtime,
            "first_new_run": first_run,
            "activation_state": (
                "ACTIVE"
                if migration_pass and first_run["status"] == "PASS"
                else "PENDING_FIRST_NEW_RUN"
            ),
        }

    def rollback_plan(self, record_path: str | Path, *, issue_token: bool = True) -> dict[str, Any]:
        record_file, record = self._record(record_path)
        decision = issue_decision(
            "rollback ARTIFEX V1 migration",
            RiskLevel.REVERSIBLE,
            effects=(
                "restore the exact pre-migration .artifex snapshot",
                "restore or remove the migration-owned Catalog and RunStore files",
            ),
            rollback="rerun the approved migration after inspecting the restored V1 Project",
            binding={
                "record_path": str(record_file),
                "migration_id": record["migration_id"],
                "backup_sha256": self._required_mapping(record, "backup")["sha256"],
            },
            approval_store=self.approval_store,
            issue_token=issue_token,
        )
        return {
            "schema_version": MIGRATION_SCHEMA,
            "operation": "ROLLBACK_DRY_RUN",
            "decision": decision.to_dict(),
        }

    def rollback(self, record_path: str | Path, confirmation_token: str | None) -> dict[str, Any]:
        record_file, record = self._record(record_path)
        planned = self.rollback_plan(record_file, issue_token=False)
        decision = DecisionExplanation(
            action=str(planned["decision"]["action"]),
            risk=RiskLevel(str(planned["decision"]["risk"])),
            effects=tuple(str(item) for item in planned["decision"]["effects"]),
            rollback=str(planned["decision"]["rollback"]),
            approval_required=True,
            plan_fingerprint=str(planned["decision"]["plan_fingerprint"]),
        )
        consume_decision(
            decision,
            confirmation_token,
            approval_store=self.approval_store,
        )
        post = self._required_mapping(record, "post_migration")
        expected_post = self._required_mapping(post, "artifex_inventory")[
            "aggregate_sha256"
        ]
        current_post = _tree_inventory(self.project_root / ".artifex")["aggregate_sha256"]
        if current_post != expected_post:
            raise ValueError("rollback refused because Project state changed after migration")
        if self._external_states() != post["external_state"]:
            raise ValueError("rollback refused because Catalog or RunStore changed after migration")
        backup = self._required_mapping(record, "backup")
        self._restore_backup(
            Path(str(backup["path"])),
            self._required_mapping(record, "source"),
            enforce_post=str(expected_post),
        )
        restored = self.inspect()
        source = self._required_mapping(record, "source")
        checks = {
            "git_head_restored": restored["source"]["git_head"] == source["git_head"],
            "project_model_restored": restored["source"]["project_model_sha256"]
            == source["project_model_sha256"],
            "artifex_inventory_restored": restored["source"]["artifex_inventory"]
            == source["artifex_inventory"],
            "target_state_removed": not restored["target"]["already_migrated"],
        }
        updated = dict(record)
        updated["state"] = "ROLLED_BACK"
        updated["rolled_back_at"] = _now()
        updated["rollback"] = {"status": "PASS", "checks": checks}
        _atomic_json(record_file, updated)
        return {
            "schema_version": MIGRATION_SCHEMA,
            "operation": "ROLLBACK",
            "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks,
            "record_path": str(record_file),
        }

    def _migration_decision(
        self, inspection: Mapping[str, Any], *, issue_token: bool
    ) -> DecisionExplanation:
        source = self._required_mapping(inspection, "source")
        return issue_decision(
            "migrate ARTIFEX V1 Project to 2.0 bootstrap state",
            RiskLevel.REVERSIBLE,
            effects=(
                "create a verified external backup of the V1 .artifex state",
                "bootstrap Project Authority revision 1 without changing V1 semantics",
                "register the stable Project identity in the external Catalog",
                "initialize documentation and dashboard projections",
                "create an empty external RunStore with no imported runtime history",
            ),
            rollback="restore the verified V1 snapshot and prior external authority files",
            binding={
                "project_root": str(self.project_root),
                "project_id": source["project_id"],
                "git_head": source["git_head"],
                "project_model_sha256": source["project_model_sha256"],
                "catalog_path": str(self.catalog_path),
                "runstore_path": str(self.runstore_path),
            },
            approval_store=self.approval_store,
            issue_token=issue_token,
        )

    @staticmethod
    def _require_applicable(inspection: Mapping[str, Any]) -> None:
        source = V1MigrationService._required_mapping(inspection, "source")
        target = V1MigrationService._required_mapping(inspection, "target")
        if not source.get("git_clean"):
            raise ValueError("V1 migration requires a clean source Git worktree")
        if target.get("already_migrated"):
            raise ValueError("Project already contains ARTIFEX 2.0 bootstrap state")
        if target.get("catalog", {}).get("exists") or target.get("runstore", {}).get("exists"):
            raise ValueError("migration target authority paths must be new or restored first")

    def _backup(
        self, backup_path: Path, inspection: Mapping[str, Any]
    ) -> dict[str, Any]:
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        external = [*_db_family(self.catalog_path), *_db_family(self.runstore_path)]
        with zipfile.ZipFile(backup_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            artifex_root = self.project_root / ".artifex"
            for item in _tree_inventory(artifex_root)["files"]:
                relative = str(item["path"])
                archive.write(artifex_root / PurePosixPath(relative), f"project/{relative}")
            for index, path in enumerate(external):
                if path.is_file():
                    archive.write(path, f"external/{index}")
            archive.writestr(
                "manifest.json",
                _json_bytes(
                    {
                        "schema_version": MIGRATION_SCHEMA,
                        "source": inspection["source"],
                        "external": [_file_state(path) for path in external],
                    }
                ),
            )
        return {
            "path": str(backup_path),
            "bytes": backup_path.stat().st_size,
            "sha256": _sha256_file(backup_path),
        }

    def _restore_backup(
        self,
        backup_path: Path,
        source: Mapping[str, Any],
        *,
        enforce_post: str | None,
    ) -> None:
        if not backup_path.is_file():
            raise ValueError("migration backup is missing")
        artifex_root = (self.project_root / ".artifex").resolve()
        if not _inside(artifex_root, self.project_root):
            raise ValueError("migration restore target escaped Project root")
        if enforce_post is not None:
            observed = _tree_inventory(artifex_root)["aggregate_sha256"]
            if observed != enforce_post:
                raise ValueError("migration restore target no longer matches the recorded state")
        with zipfile.ZipFile(backup_path, "r") as archive:
            manifest = json.loads(archive.read("manifest.json"))
            for path in sorted(artifex_root.rglob("*"), reverse=True):
                if path.is_symlink() or path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            artifex_root.mkdir(parents=True, exist_ok=True)
            for info in archive.infolist():
                if not info.filename.startswith("project/") or info.is_dir():
                    continue
                relative = PurePosixPath(info.filename).relative_to("project")
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("migration backup contains an unsafe Project path")
                target = artifex_root.joinpath(*relative.parts).resolve(strict=False)
                if not _inside(target, artifex_root):
                    raise ValueError("migration backup extraction escaped Project state")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
            external = manifest.get("external", [])
            expected_paths = [*_db_family(self.catalog_path), *_db_family(self.runstore_path)]
            if len(external) != len(expected_paths):
                raise ValueError("migration backup external authority manifest is invalid")
            for index, (item, path) in enumerate(zip(external, expected_paths, strict=True)):
                if bool(item["exists"]):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.read(f"external/{index}"))
                else:
                    path.unlink(missing_ok=True)
        restored = _tree_inventory(artifex_root)
        expected = self._required_mapping(source, "artifex_inventory")
        if (
            restored["file_count"] != expected["file_count"]
            or restored["aggregate_sha256"] != expected["aggregate_sha256"]
        ):
            raise ValueError("restored V1 Project snapshot failed verification")

    def _external_states(self) -> list[dict[str, Any]]:
        return [
            _sqlite_logical_state(self.catalog_path),
            _sqlite_logical_state(self.runstore_path),
        ]

    def _verified_semantic_extensions(self, backup_path: Path) -> tuple[str, ...]:
        """Recognize the append-only audit event emitted by Project adoption."""

        relative = "audit.jsonl"
        current = self.project_root / ".artifex" / relative
        if not current.is_file():
            return ()
        with zipfile.ZipFile(backup_path, "r") as archive:
            try:
                baseline = archive.read(f"project/{relative}")
            except KeyError:
                return ()
        observed = current.read_bytes()
        extended = len(observed) > len(baseline) and observed.startswith(baseline)
        return (relative,) if extended else ()

    def _provider_setup_state(self) -> dict[str, Any]:
        path = self.project_root / SETUP_STATE_PATH
        if not path.is_file():
            return {
                "legacy_persisted_setup_detected": False,
                "source_path": SETUP_STATE_PATH,
                "source_sha256": None,
                "enabled": [],
                "disposition": "NOT_PRESENT_NO_PROVIDER_SETUP_INVENTED",
            }
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("legacy provider setup is unreadable") from exc
        if not isinstance(value, Mapping) or value.get("schema_version") not in {"1.0", "2.0"}:
            raise ValueError("legacy provider setup schema is unsupported")
        enabled = value.get("enabled")
        if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
            raise ValueError("legacy provider setup enabled inventory is invalid")
        return {
            "legacy_persisted_setup_detected": True,
            "source_path": SETUP_STATE_PATH,
            "source_schema": value["schema_version"],
            "source_sha256": _sha256_file(path),
            "enabled": sorted(set(enabled)),
            "disposition": "PRESERVE_AND_FRESH_READINESS_REVALIDATE",
        }

    def _revalidate_provider_setup(
        self, source: Mapping[str, Any]
    ) -> dict[str, Any]:
        if source.get("legacy_persisted_setup_detected") is not True:
            return {
                **dict(source),
                "fresh_runtime_consumed": False,
                "readiness_revalidation": "NOT_APPLICABLE_ABSENT",
                "certification_carried_forward": False,
            }
        graph = ProviderCompositionLoader().load(self.project_root)
        providers = [
            {
                "provider_id": provider.provider_id,
                "readiness": provider.readiness.to_dict(),
                "certified_roles": [],
            }
            for provider in graph.providers
        ]
        return {
            **dict(source),
            "fresh_runtime_consumed": True,
            "readiness_revalidation": "PERFORMED",
            "providers": providers,
            "certification_carried_forward": False,
        }

    def _provider_setup_valid(self, state: Mapping[str, Any]) -> bool:
        detected = state.get("legacy_persisted_setup_detected") is True
        if not detected:
            return (
                state.get("disposition") == "NOT_PRESENT_NO_PROVIDER_SETUP_INVENTED"
                and state.get("readiness_revalidation") == "NOT_APPLICABLE_ABSENT"
                and state.get("certification_carried_forward") is False
            )
        path = self.project_root / SETUP_STATE_PATH
        return (
            path.is_file()
            and _sha256_file(path) == state.get("source_sha256")
            and state.get("fresh_runtime_consumed") is True
            and state.get("readiness_revalidation") == "PERFORMED"
            and state.get("certification_carried_forward") is False
        )

    @staticmethod
    def _first_new_run(runtime: Mapping[str, Any]) -> dict[str, Any]:
        counts = V1MigrationService._required_mapping(runtime, "counts")
        states = V1MigrationService._required_mapping(runtime, "states")
        if not int(counts.get("runs", 0)):
            return {"status": "PENDING", "reason": "no post-migration 2.0 Run exists"}
        passed = (
            int(counts.get("runs", 0)) == 1
            and int(counts.get("project_jobs", 0)) == 1
            and int(counts.get("attempts", 0)) == 1
            and states.get("runs") == ["COMPLETED"]
            and states.get("project_jobs") == ["ACCEPTED"]
            and states.get("attempts") == ["FINISHED"]
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "run_count": int(counts.get("runs", 0)),
            "project_job_count": int(counts.get("project_jobs", 0)),
            "attempt_count": int(counts.get("attempts", 0)),
            "states": dict(states),
        }

    @staticmethod
    def _required_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        candidate = value.get(name)
        if not isinstance(candidate, Mapping):
            raise ValueError(f"migration record field is invalid: {name}")
        return candidate

    def _record(self, record_path: str | Path) -> tuple[Path, dict[str, Any]]:
        path = Path(record_path).expanduser().resolve()
        if not _inside(path, self.state_root):
            raise ValueError("migration record must remain inside the configured state root")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != MIGRATION_SCHEMA:
            raise ValueError("migration record is invalid")
        if Path(str(value.get("project_root"))).resolve() != self.project_root:
            raise ValueError("migration record belongs to a different Project")
        if Path(str(value.get("catalog_path"))).resolve() != self.catalog_path:
            raise ValueError("migration record belongs to a different Catalog")
        if Path(str(value.get("runstore_path"))).resolve() != self.runstore_path:
            raise ValueError("migration record belongs to a different RunStore")
        return path, value

    @staticmethod
    def _backup_valid(record: Mapping[str, Any]) -> bool:
        backup = V1MigrationService._required_mapping(record, "backup")
        path = Path(str(backup["path"]))
        return (
            path.is_file()
            and path.stat().st_size == int(backup["bytes"])
            and _sha256_file(path) == backup["sha256"]
        )


__all__ = ["V1MigrationService"]
