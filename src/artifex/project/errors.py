"""Project Model and Store errors with stable, testable semantics."""

from __future__ import annotations


class ProjectError(Exception):
    """Base class for Project Model and Store failures."""


class UnsafePathError(ProjectError, ValueError):
    """A requested path is not a safe repository-relative path."""


class ArtifactNotFoundError(ProjectError, FileNotFoundError):
    """A requested canonical artifact does not exist."""


class ArtifactCorruptError(ProjectError, ValueError):
    """An artifact cannot be parsed as its declared format."""


class DuplicateArtifactError(ProjectError, ValueError):
    """Two canonical artifacts claim the same stable identifier."""


class InvalidTransitionError(ProjectError, ValueError):
    """A lifecycle transition is not permitted."""


class GitCommandError(ProjectError, RuntimeError):
    """A Git operation failed or Git is unavailable."""
