# Organizational Knowledge Guide

Use Organizational Knowledge when a validated lesson from one Project may help another Project.
It is a recommendation workflow, not shared mutable memory.

1. Record a validated Project-scoped lesson with `knowledge.project.lesson.record`.
2. Promote it with `knowledge.organizational.promote`, providing evidence digests, a validator,
   explicit applicability, and a freshness horizon.
3. Search as an authenticated reader whose clearance is sufficient for the record sensitivity.
4. Create an advisory recommendation for the exact target Project baseline.
5. Review the recommendation. The target Project is unchanged at this point.
6. An authorized Project actor calls `knowledge.project.adopt` with the recommendation and current
   `expected_revision`. ARTIFEX proposes and accepts the resulting model only through Project
   Authority.

Do not copy Organizational Knowledge directly into a Project model, provider prompt, or interaction
context. Do not broaden applicability after promotion. If the target baseline advances or freshness
expires, create a new reviewed recommendation. Treat V1 migration quarantine as inspection evidence
only; it is never searchable or accepted knowledge.
