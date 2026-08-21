"""Knowledge and controlled evolution package boundary."""

from .evolution import (
    DivergenceReport,
    OverlayPrivilegeError,
    PromotionDeniedError,
    inspect_divergence,
    promote_knowledge,
)
from .model import (
    CandidateOverlay,
    ImprovementProposal,
    KnowledgeItem,
    KnowledgeKind,
    KnowledgeProvenance,
    KnowledgeScope,
    KnowledgeState,
    OverlayUpdateAssessment,
    OverlayValidationStatus,
    PromotionPolicy,
    RevisitKind,
    RevisitTrigger,
    Sensitivity,
    UpdateClassification,
    VerifiedAgainst,
)
from .store import InstanceKnowledgeStore, KnowledgeIsolationError, ProjectLessonStore

__all__ = [
    "CandidateOverlay",
    "DivergenceReport",
    "ImprovementProposal",
    "InstanceKnowledgeStore",
    "KnowledgeIsolationError",
    "KnowledgeItem",
    "KnowledgeKind",
    "KnowledgeProvenance",
    "KnowledgeScope",
    "KnowledgeState",
    "OverlayPrivilegeError",
    "OverlayUpdateAssessment",
    "OverlayValidationStatus",
    "ProjectLessonStore",
    "PromotionDeniedError",
    "PromotionPolicy",
    "RevisitKind",
    "RevisitTrigger",
    "Sensitivity",
    "UpdateClassification",
    "VerifiedAgainst",
    "inspect_divergence",
    "promote_knowledge",
]
