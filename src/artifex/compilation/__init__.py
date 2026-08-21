"""Human and machine generated-view compilation package boundary."""

from artifex.compilation.comprehension import (
    COMPREHENSION_TOPICS,
    PaperCompiler,
    build_comprehension_gate,
    compile_comprehension_gate,
    compile_optional_paper,
    evaluate_comprehension,
    evaluate_paper_eligibility,
    paper_eligibility_gate,
)
from artifex.compilation.dashboard import (
    compile_dashboard,
    derive_dashboard_metrics,
    render_dashboard,
)
from artifex.compilation.freshness import (
    GeneratedViewState,
    classify_documentation,
    classify_generated_view,
    fingerprint_sources,
    generation_manifest,
)
from artifex.compilation.packets import compile_context_packet, compile_execution_packet
from artifex.compilation.renderers import (
    ADAPTIVE_HUMAN_DOCUMENTS,
    BASE_HUMAN_DOCUMENTS,
    compile_human_documentation,
    compile_human_documents,
    compile_machine_pack,
    compile_machine_understanding_pack,
    render_agent_shim,
    render_human_document,
    serialize_machine_view,
)

__all__ = [
    "ADAPTIVE_HUMAN_DOCUMENTS",
    "BASE_HUMAN_DOCUMENTS",
    "COMPREHENSION_TOPICS",
    "GeneratedViewState",
    "PaperCompiler",
    "build_comprehension_gate",
    "classify_documentation",
    "classify_generated_view",
    "compile_comprehension_gate",
    "compile_context_packet",
    "compile_dashboard",
    "compile_execution_packet",
    "compile_human_documentation",
    "compile_human_documents",
    "compile_machine_pack",
    "compile_machine_understanding_pack",
    "compile_optional_paper",
    "derive_dashboard_metrics",
    "evaluate_comprehension",
    "evaluate_paper_eligibility",
    "fingerprint_sources",
    "generation_manifest",
    "paper_eligibility_gate",
    "render_agent_shim",
    "render_dashboard",
    "render_human_document",
    "serialize_machine_view",
]
