"""Read-only Git provenance inspection plus safe repository initialization."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from artifex.project.errors import GitCommandError


class DirtyStatePolicy(StrEnum):
    """Explicit policy for operations that may or may not tolerate local edits."""

    ALLOW = "ALLOW"
    REQUIRE_CLEAN = "REQUIRE_CLEAN"


@dataclass(frozen=True, slots=True)
class GitRemote:
    """Non-secret Git remote metadata."""

    name: str
    url: str


@dataclass(frozen=True, slots=True)
class GitState:
    """Observed repository state and its managed baseline."""

    initialized: bool
    branch: str | None
    baseline_commit: str | None
    current_commit: str | None
    dirty: bool | None
    remotes: tuple[GitRemote, ...] = ()

    @property
    def remote_status(self) -> str:
        return "CONFIGURED" if self.remotes else "NONE"

    def to_dict(self) -> dict[str, object]:
        return {
            "initialized": self.initialized,
            "branch": self.branch,
            "baseline_commit": self.baseline_commit,
            "current_commit": self.current_commit,
            "dirty": self.dirty,
            "remote_status": self.remote_status,
            "remotes": [{"name": remote.name, "url": remote.url} for remote in self.remotes],
        }

    def enforce(self, policy: DirtyStatePolicy) -> None:
        if policy is DirtyStatePolicy.REQUIRE_CLEAN and self.dirty is not False:
            raise GitCommandError("operation requires a clean Git worktree")


class GitRepository:
    """A narrow Git adapter; it never stages or commits user content."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    @property
    def initialized(self) -> bool:
        result = self._run("rev-parse", "--is-inside-work-tree", check=False)
        return result.returncode == 0 and result.stdout.strip() == "true"

    def initialize(self, *, branch: str = "main") -> None:
        """Initialize Git when absent, preserving every existing file."""

        self.root.mkdir(parents=True, exist_ok=True)
        if self.initialized:
            return
        result = self._run("init", "-b", branch, check=False)
        if result.returncode != 0:
            self._run("init")
            self._run("branch", "-M", branch)

    def inspect(self, *, baseline_commit: str | None = None) -> GitState:
        if not self.initialized:
            return GitState(False, None, baseline_commit, None, None)
        branch_result = self._run("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
        head_result = self._run("rev-parse", "--verify", "HEAD", check=False)
        head = head_result.stdout.strip() if head_result.returncode == 0 else None
        dirty = bool(self._run("status", "--porcelain=v1").stdout)
        remote_names = sorted(filter(None, self._run("remote").stdout.splitlines()))
        remotes = tuple(
            GitRemote(name, _sanitize_remote(self._run("remote", "get-url", name).stdout.strip()))
            for name in remote_names
        )
        return GitState(True, branch, baseline_commit, head, dirty, remotes)

    def current_commit(self) -> str | None:
        return self.inspect().current_commit

    def _run(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), *arguments],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise GitCommandError(f"cannot execute Git: {exc}") from exc
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown Git failure"
            raise GitCommandError(f"git {' '.join(arguments)} failed: {detail}")
        return result


def _sanitize_remote(url: str) -> str:
    """Remove HTTP(S) userinfo because it may contain embedded credentials."""

    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        return url
    split = urlsplit(url)
    host = split.hostname or ""
    try:
        port = split.port
    except ValueError:
        return ""
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit((split.scheme, host, split.path, split.query, split.fragment))
