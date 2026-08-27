"""Contextual provider capability composition."""

from artifex.capabilities.certification import (
    CERTIFICATION_LADDER,
    CLAUDE_DISPATCH_AUTHORIZED_ROLES,
    CLAUDE_SUPPORTED_VERSION_RANGE,
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    CODEX_SUPPORTED_VERSION_RANGE,
    DEEPSEEK_DISPATCH_AUTHORIZED_ROLES,
    DEEPSEEK_SUPPORTED_VERSION_RANGE,
    claude_certification_projection,
    codex_certification_projection,
    deepseek_certification_projection,
    provider_certification_projection,
)
from artifex.capabilities.composition import ProviderCompositionLoader, ProviderSetupError
from artifex.capabilities.credentials import AuthenticationAssertion, CredentialBroker
from artifex.capabilities.evidence import (
    CapabilityEvidenceStore,
    CapabilityReceipt,
    default_capability_evidence_path,
    record_execution_implementer_evidence,
    shipping_artifact_sha256,
)
from artifex.capabilities.interaction import ProviderInteractionService, RepositoryBaseline
from artifex.capabilities.models import (
    ActorContext,
    CapabilityRequest,
    CredentialReference,
    DataClassification,
    EligibilityDecision,
    GovernanceMode,
    ProviderConfiguration,
    ProviderInstance,
    ProviderReadiness,
    ProviderRole,
    ReadinessState,
)
from artifex.capabilities.registry import CapabilityGraph, CapabilityRegistry
from artifex.capabilities.resolver import CapabilityResolver

__all__ = [
    "CERTIFICATION_LADDER",
    "CLAUDE_DISPATCH_AUTHORIZED_ROLES",
    "CLAUDE_SUPPORTED_VERSION_RANGE",
    "CODEX_DISPATCH_AUTHORIZED_ROLES",
    "CODEX_SUPPORTED_VERSION_RANGE",
    "DEEPSEEK_DISPATCH_AUTHORIZED_ROLES",
    "DEEPSEEK_SUPPORTED_VERSION_RANGE",
    "ActorContext",
    "AuthenticationAssertion",
    "CapabilityEvidenceStore",
    "CapabilityGraph",
    "CapabilityReceipt",
    "CapabilityRegistry",
    "CapabilityRequest",
    "CapabilityResolver",
    "CredentialBroker",
    "CredentialReference",
    "DataClassification",
    "EligibilityDecision",
    "GovernanceMode",
    "ProviderCompositionLoader",
    "ProviderConfiguration",
    "ProviderInstance",
    "ProviderInteractionService",
    "ProviderReadiness",
    "ProviderRole",
    "ProviderSetupError",
    "ReadinessState",
    "RepositoryBaseline",
    "claude_certification_projection",
    "codex_certification_projection",
    "deepseek_certification_projection",
    "default_capability_evidence_path",
    "provider_certification_projection",
    "record_execution_implementer_evidence",
    "shipping_artifact_sha256",
]
