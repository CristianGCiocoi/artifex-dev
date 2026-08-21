"""Project Model and canonical filesystem/Git store."""

from artifex.project.audit import AuditEvent, AuditLog
from artifex.project.changeset import ChangeSet, ChangeSetRepository, ChangeSetStatus
from artifex.project.contracts import ProjectStore, RunStore
from artifex.project.errors import (
    ArtifactCorruptError,
    ArtifactNotFoundError,
    DuplicateArtifactError,
    GitCommandError,
    InvalidTransitionError,
    ProjectError,
    UnsafePathError,
)
from artifex.project.git import DirtyStatePolicy, GitRemote, GitRepository, GitState
from artifex.project.index import ArtifactIndex, ReconciliationEvent
from artifex.project.model import (
    Artifact,
    ArtifactStatus,
    EntityKind,
    ProjectInfo,
    ProjectLifecycle,
    ProjectModel,
    Provenance,
    StructuredEntity,
    WorkflowDepth,
)
from artifex.project.parser import ArtifactParser
from artifex.project.paths import normalize_relative_path
from artifex.project.repository import (
    ProjectRepository,
    adopt_project,
    initialize_project,
)
from artifex.project.store import FileSystemProjectStore

__all__ = [
    "Artifact",
    "ArtifactCorruptError",
    "ArtifactIndex",
    "ArtifactNotFoundError",
    "ArtifactParser",
    "ArtifactStatus",
    "AuditEvent",
    "AuditLog",
    "ChangeSet",
    "ChangeSetRepository",
    "ChangeSetStatus",
    "DirtyStatePolicy",
    "DuplicateArtifactError",
    "EntityKind",
    "FileSystemProjectStore",
    "GitCommandError",
    "GitRemote",
    "GitRepository",
    "GitState",
    "InvalidTransitionError",
    "ProjectError",
    "ProjectInfo",
    "ProjectLifecycle",
    "ProjectModel",
    "ProjectRepository",
    "ProjectStore",
    "Provenance",
    "ReconciliationEvent",
    "RunStore",
    "StructuredEntity",
    "UnsafePathError",
    "WorkflowDepth",
    "adopt_project",
    "initialize_project",
    "normalize_relative_path",
]
