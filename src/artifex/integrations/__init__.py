"""Replaceable integration contracts and the V1 manual reference adapter."""

from artifex.integrations.conformance import (
    ConformanceCheck,
    ConformanceReport,
    ConformanceSuite,
    IntegrationConformanceSuite,
)
from artifex.integrations.continuity import (
    ALTERNATE_CONTINUITY_ROUTE,
    PRIMARY_CONTINUITY_ROUTE,
    ContinuityObservation,
    ContinuityRouteReport,
    CrossInterfaceContinuityReport,
    verify_continuity_route,
    verify_cross_interface_continuity,
)
from artifex.integrations.contracts import (
    Capability,
    CompatibilityRange,
    ConfigurationProvenance,
    ExecutionPacket,
    ExecutionResult,
    HealthReport,
    HealthStatus,
    IntegrationError,
    IntegrationMetadata,
    IntegrationRole,
)
from artifex.integrations.doctor import DoctorCheck, DoctorReport, run_doctor
from artifex.integrations.manual import ManualIntegration
from artifex.integrations.registry import Integration, IntegrationRegistry
from artifex.integrations.research import (
    ResearchBundle,
    ResearchClaim,
    ResearchRequest,
    ResearchSource,
)
from artifex.integrations.selection import (
    SelectionDecision,
    SelectionPolicy,
    SelectionRequest,
    select_integration,
)

__all__ = [
    "ALTERNATE_CONTINUITY_ROUTE",
    "PRIMARY_CONTINUITY_ROUTE",
    "Capability",
    "CompatibilityRange",
    "ConfigurationProvenance",
    "ConformanceCheck",
    "ConformanceReport",
    "ConformanceSuite",
    "ContinuityObservation",
    "ContinuityRouteReport",
    "CrossInterfaceContinuityReport",
    "DoctorCheck",
    "DoctorReport",
    "ExecutionPacket",
    "ExecutionResult",
    "HealthReport",
    "HealthStatus",
    "Integration",
    "IntegrationConformanceSuite",
    "IntegrationError",
    "IntegrationMetadata",
    "IntegrationRegistry",
    "IntegrationRole",
    "ManualIntegration",
    "ResearchBundle",
    "ResearchClaim",
    "ResearchRequest",
    "ResearchSource",
    "SelectionDecision",
    "SelectionPolicy",
    "SelectionRequest",
    "run_doctor",
    "select_integration",
    "verify_continuity_route",
    "verify_cross_interface_continuity",
]
