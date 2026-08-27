"""Persistent isolated Execution Workspaces and guarded semantic promotion."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from time import time

from artifex.project import ProjectAuthority, ProjectModel
from artifex.runtime.models import (
    AcceptanceDecision,
    AcceptanceOutcome,
    ActorLike,
    FenceToken,
    ProjectJobState,
    PromotionConflictError,
    RuntimeAuthorizationError,
    RuntimeTransitionError,
    actor_principal,
)
from artifex.runtime.store import SQLiteRunStore


def _clock() -> int:
    return int(time())


class WorkspaceManager:
    def __init__(
        self,
        store: SQLiteRunStore,
        token: FenceToken,
        workspace_root: str | Path,
        *,
        clock: Callable[[], int] = _clock,
    ) -> None:
        self.store = store
        self.token = token
        self.root = Path(workspace_root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.clock = clock

    def create(
        self,
        workspace_id: str,
        attempt_id: str,
        project_root: str | Path,
        baseline_revision: int,
        *,
        actor_id: ActorLike,
    ) -> Path:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", workspace_id) is None:
            raise RuntimeAuthorizationError("Execution Workspace ID is not a safe path component")
        source = Path(project_root).expanduser().resolve()
        target = (self.root / workspace_id).resolve()
        if target.parent != self.root:
            raise RuntimeAuthorizationError("Execution Workspace path escapes managed root")
        if target.exists():
            raise FileExistsError(f"Execution Workspace already exists: {workspace_id}")
        attempt = self.store.get("attempts", "attempt_id", attempt_id)
        if attempt is None:
            raise RuntimeTransitionError("Execution Workspace Attempt is missing")
        job = self.store.get("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        if job is None:
            raise RuntimeTransitionError("Execution Workspace ProjectJob is missing")
        run = self.store.get("runs", "run_id", str(job["run_id"]))
        if run is None:
            raise RuntimeTransitionError("Execution Workspace Run is missing")
        envelope = self.store.envelope(str(run["envelope_id"]), int(str(run["envelope_version"])))
        if envelope is None:
            raise RuntimeTransitionError("Execution Workspace Envelope is missing")
        if baseline_revision != int(envelope["baseline_revision"]):
            raise RuntimeAuthorizationError("workspace baseline does not match Execution Envelope")
        authority = ProjectAuthority(source)
        current = authority.current()
        if current.project_id != str(run["project_id"]):
            raise RuntimeAuthorizationError("workspace Project does not match Run Project")
        if current.number != baseline_revision:
            raise RuntimeAuthorizationError("workspace baseline does not match Project Authority")
        expected_fingerprint = envelope.get("baseline_fingerprint")
        if expected_fingerprint is not None and current.fingerprint != expected_fingerprint:
            raise RuntimeAuthorizationError(
                "workspace semantic fingerprint does not match Envelope"
            )
        principal = actor_principal(actor_id)
        principal.require("workspace:create", current.project_id, now=self.clock())
        git_created = False
        clone_created = False
        try:
            git_root = _git_root(source)
            if git_root == source:
                try:
                    head = _git_output(source, "rev-parse", "HEAD")
                except subprocess.CalledProcessError:
                    if envelope.get("allowed_providers"):
                        raise RuntimeAuthorizationError(
                            "provider execution requires a committed Git baseline"
                        ) from None
                    shutil.copytree(source, target, ignore=shutil.ignore_patterns(".git"))
                    head = ""
                expected_commit = envelope.get("baseline_commit")
                if head and expected_commit is not None and head != expected_commit:
                    raise RuntimeAuthorizationError("workspace Git HEAD does not match Envelope")
                if (
                    head
                    and envelope.get("allowed_providers")
                    and _git_output(source, "status", "--porcelain")
                ):
                    raise RuntimeAuthorizationError(
                        "provider execution requires a clean Git baseline"
                    )
                if head:
                    if envelope.get("allowed_providers"):
                        # Provider sandboxes must not need to traverse a .git
                        # indirection back into the canonical repository.  A
                        # no-local clone keeps Git metadata and objects inside
                        # the authorized Execution Workspace.
                        subprocess.run(
                            (
                                "git",
                                "clone",
                                "--no-local",
                                "--no-checkout",
                                "--quiet",
                                str(source),
                                str(target),
                            ),
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        clone_created = True
                        subprocess.run(
                            ("git", "-C", str(target), "checkout", "--detach", "--quiet", head),
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                    else:
                        subprocess.run(
                            (
                                "git",
                                "-C",
                                str(source),
                                "worktree",
                                "add",
                                "--detach",
                                str(target),
                                head,
                            ),
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        git_created = True
            else:
                shutil.copytree(source, target, ignore=shutil.ignore_patterns(".git"))
            _assert_no_symlink_escape(target)
        except Exception:
            if git_created:
                subprocess.run(
                    ("git", "-C", str(source), "worktree", "remove", "--force", str(target)),
                    check=False,
                    capture_output=True,
                    text=True,
                )
            elif clone_created or target.exists():
                shutil.rmtree(target)
            raise
        now = self.clock()
        self.store.insert(
            "workspaces",
            {
                "workspace_id": workspace_id,
                "attempt_id": attempt_id,
                "project_root": str(source),
                "workspace_root": str(target),
                "baseline_revision": baseline_revision,
                "state": "ACTIVE",
                "created_at": now,
            },
            self.token,
            now=now,
            actor_id=principal,
            event_type="WORKSPACE_CREATED",
        )
        return target

    def assert_allowed_path(
        self,
        workspace_id: str,
        relative_path: str,
        *,
        permission: str,
        actor_id: ActorLike,
    ) -> Path:
        workspace = self.store.get("workspaces", "workspace_id", workspace_id)
        if workspace is None or workspace["state"] != "ACTIVE":
            raise RuntimeTransitionError("Execution Workspace is not active")
        root = Path(str(workspace["workspace_root"])).resolve()
        candidate = (root / relative_path).resolve()
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise RuntimeAuthorizationError("workspace path escapes managed root") from exc
        envelope = self.store.envelope_for_attempt(str(workspace["attempt_id"]))
        allowed_permissions = tuple(envelope.get("filesystem_permissions", ()))
        if permission not in allowed_permissions:
            raise RuntimeAuthorizationError(
                f"{permission} is not allowed by the Execution Envelope"
            )
        owners = tuple(
            str(value).replace("\\", "/").removeprefix("./") for value in envelope["allowed_paths"]
        )
        if not any(
            owner == "." or relative == owner or relative.startswith(f"{owner}/")
            for owner in owners
        ):
            raise RuntimeAuthorizationError("workspace path is outside Execution Envelope scope")
        principal = actor_principal(actor_id)
        run = self._run_for_workspace(workspace)
        principal.require("workspace:access", str(run["project_id"]), now=self.clock())
        return candidate

    def promote(
        self,
        workspace_id: str,
        model: ProjectModel,
        decision: AcceptanceDecision,
        *,
        actor_id: ActorLike,
    ) -> int:
        workspace = self.store.get("workspaces", "workspace_id", workspace_id)
        if workspace is None or workspace["state"] != "ACTIVE":
            raise RuntimeTransitionError("Execution Workspace is not active")
        attempt = self.store.get("attempts", "attempt_id", str(workspace["attempt_id"]))
        if attempt is None:
            raise RuntimeTransitionError("Execution Workspace Attempt is missing")
        job_id = str(attempt["project_job_id"])
        if decision.project_job_id != job_id or decision.outcome is not AcceptanceOutcome.ACCEPT:
            raise RuntimeTransitionError("promotion requires matching Acceptance Authority ACCEPT")
        stored_decision = self.store.acceptance(job_id)
        if stored_decision is None or str(stored_decision["decision_id"]) != decision.decision_id:
            raise RuntimeAuthorizationError(
                "promotion requires the persisted Acceptance Authority decision"
            )
        job = self.store.get("project_jobs", "project_job_id", job_id)
        if job is None or job["state"] != ProjectJobState.ACCEPTED.value:
            raise RuntimeTransitionError("ProjectJob has not been accepted")

        run = self._run_for_workspace(workspace)
        envelope = self.store.envelope(str(run["envelope_id"]), int(str(run["envelope_version"])))
        if envelope is None or decision.envelope_fingerprint not in {
            None,
            str(envelope["fingerprint"]),
        }:
            raise RuntimeAuthorizationError("Acceptance decision does not match Run Envelope")
        principal = actor_principal(actor_id)
        principal.require("project:promote", str(run["project_id"]), now=self.clock())
        dispatch = self.store.dispatch_authorization(str(workspace["attempt_id"]))
        if dispatch is not None and str(dispatch["actor_id"]) == principal.actor_id:
            raise RuntimeAuthorizationError("dispatch authority cannot promote its own result")

        authority = ProjectAuthority(str(workspace["project_root"]))
        current = authority.current()
        now = self.clock()
        baseline = int(str(workspace["baseline_revision"]))
        if current.number != baseline:
            self.store.set_workspace_state(
                workspace_id,
                "ACTIVE",
                "PROMOTION_CONFLICT",
                self.token,
                now=now,
                actor_id=principal,
            )
            self.store.transition(
                "project_jobs",
                "project_job_id",
                job_id,
                expected_state=ProjectJobState.ACCEPTED.value,
                target_state=ProjectJobState.PROMOTION_CONFLICT.value,
                token=self.token,
                now=now,
                actor_id=principal,
            )
            raise PromotionConflictError(
                f"workspace baseline {baseline} is stale; current revision is {current.number}"
            )
        proposal = authority.propose(
            model,
            expected_revision=baseline,
            actor=principal.actor_id,
            source="EXECUTION_WORKSPACE_PROMOTION",
        )
        revision = authority.accept(
            proposal.id,
            expected_revision=baseline,
            actor=principal.actor_id,
        )
        self.store.set_workspace_state(
            workspace_id,
            "ACTIVE",
            "PROMOTED",
            self.token,
            now=now,
            actor_id=principal,
        )
        return revision.number

    def _run_for_workspace(self, workspace: dict[str, object]) -> dict[str, object]:
        attempt = self.store.get("attempts", "attempt_id", str(workspace["attempt_id"]))
        if attempt is None:
            raise RuntimeTransitionError("Execution Workspace Attempt is missing")
        job = self.store.get("project_jobs", "project_job_id", str(attempt["project_job_id"]))
        if job is None:
            raise RuntimeTransitionError("Execution Workspace ProjectJob is missing")
        run = self.store.get("runs", "run_id", str(job["run_id"]))
        if run is None:
            raise RuntimeTransitionError("Execution Workspace Run is missing")
        return run


def _git_root(path: Path) -> Path | None:
    completed = subprocess.run(
        ("git", "-C", str(path), "rev-parse", "--show-toplevel"),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return Path(completed.stdout.strip()).resolve()


def _git_output(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(path), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _assert_no_symlink_escape(root: Path) -> None:
    for candidate in root.rglob("*"):
        if not candidate.is_symlink():
            continue
        try:
            candidate.resolve().relative_to(root)
        except (OSError, ValueError) as exc:
            raise RuntimeAuthorizationError(
                f"Execution Workspace contains escaping symlink: {candidate.relative_to(root)}"
            ) from exc


__all__ = ["WorkspaceManager"]
