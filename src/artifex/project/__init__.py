"""Project Model and canonical filesystem/Git store."""

from artifex.project.audit import AuditEvent, AuditLog
from artifex.project.authority import ProjectAuthority, SemanticProposal, SemanticRevision
from artifex.project.catalog import CatalogEntry, ProjectCatalog, default_catalog_path
from artifex.project.changeset import ChangeSet, ChangeSetRepository, ChangeSetStatus
from artifex.project.contracts import ProjectStore, RunStore
from artifex.project.errors import (
    ArtifactCorruptError,
    ArtifactNotFoundError,
    CatalogConflictError,
    DuplicateArtifactError,
    ExternalMutationError,
    GitCommandError,
    InvalidTransitionError,
    ProjectError,
    ProjectUnreachableError,
    SemanticConflictError,
    UnsafePathError,
)
from artifex.project.git import DirtyStatePolicy, GitRemote, GitRepository, GitState
from artifex.project.index import ArtifactIndex, ReconciliationEvent
from artifex.project.model import (
    Artifact,
    ArtifactStatus,
    EntityKind,
    KnowledgeAdoptionProvenance,
    LifecycleContribution,
    LifecycleStage,
    ProjectGovernanceState,
    ProjectInfo,
    ProjectKnowledgeAdoption,
    ProjectLifecycle,
    ProjectModel,
    Provenance,
    StructuredEntity,
    WorkflowDepth,
)
from artifex.project.parser import ArtifactParser
from artifex.project.paths import normalize_relative_path
from artifex.project.projections import (
    ProjectionFramework,
    render_project_baseline,
    render_project_projection,
)
from artifex.project.repository import (
    ProjectRepository,
    adopt_project,
    initialize_project,
)
from artifex.project.service import ProjectControlService
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
    "CatalogConflictError",
    "CatalogEntry",
    "ChangeSet",
    "ChangeSetRepository",
    "ChangeSetStatus",
    "DirtyStatePolicy",
    "DuplicateArtifactError",
    "EntityKind",
    "ExternalMutationError",
    "FileSystemProjectStore",
    "GitCommandError",
    "GitRemote",
    "GitRepository",
    "GitState",
    "InvalidTransitionError",
    "KnowledgeAdoptionProvenance",
    "LifecycleContribution",
    "LifecycleStage",
    "ProjectAuthority",
    "ProjectCatalog",
    "ProjectControlService",
    "ProjectError",
    "ProjectGovernanceState",
    "ProjectInfo",
    "ProjectKnowledgeAdoption",
    "ProjectLifecycle",
    "ProjectModel",
    "ProjectRepository",
    "ProjectStore",
    "ProjectUnreachableError",
    "ProjectionFramework",
    "Provenance",
    "ReconciliationEvent",
    "RunStore",
    "SemanticConflictError",
    "SemanticProposal",
    "SemanticRevision",
    "StructuredEntity",
    "UnsafePathError",
    "WorkflowDepth",
    "adopt_project",
    "default_catalog_path",
    "initialize_project",
    "normalize_relative_path",
    "render_project_baseline",
    "render_project_projection",
]
