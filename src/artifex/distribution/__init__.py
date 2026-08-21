"""Installable-product and beginner-experience services."""

from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.beginner import BeginnerJourneyResult, start_beginner_journey
from artifex.distribution.discovery import SUPPORTED_TOOLS, detect_resources, discover_environment
from artifex.distribution.doctor import run_distribution_doctor
from artifex.distribution.lifecycle import (
    InstallResult,
    complete_deferred_uninstall,
    install,
    install_plan,
    uninstall,
    uninstall_plan,
    upgrade,
    upgrade_plan,
)
from artifex.distribution.models import (
    DecisionExplanation,
    DistributionDoctorReport,
    DoctorFinding,
    EnvironmentDiscovery,
    ExperienceMode,
    ResourceEnvelope,
    RiskLevel,
    SetupAction,
    SetupPlan,
    ToolDiscovery,
)
from artifex.distribution.presentation import (
    explain_decision,
    presentation_policy,
    require_approval,
)
from artifex.distribution.setup import apply_integration_setup, plan_integration_setup

__all__ = [
    "SUPPORTED_TOOLS",
    "ApprovalStore",
    "BeginnerJourneyResult",
    "DecisionExplanation",
    "DistributionDoctorReport",
    "DoctorFinding",
    "EnvironmentDiscovery",
    "ExperienceMode",
    "InstallResult",
    "ResourceEnvelope",
    "RiskLevel",
    "SetupAction",
    "SetupPlan",
    "ToolDiscovery",
    "apply_integration_setup",
    "complete_deferred_uninstall",
    "detect_resources",
    "discover_environment",
    "explain_decision",
    "install",
    "install_plan",
    "plan_integration_setup",
    "presentation_policy",
    "require_approval",
    "run_distribution_doctor",
    "start_beginner_journey",
    "uninstall",
    "uninstall_plan",
    "upgrade",
    "upgrade_plan",
]
