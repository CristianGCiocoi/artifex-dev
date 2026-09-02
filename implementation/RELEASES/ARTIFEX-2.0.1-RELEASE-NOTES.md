# ARTIFEX 2.0.1

ARTIFEX 2.0.1 is a narrowly scoped maintenance release over the immutable
ARTIFEX 2.0.0 GA baseline.

## Maintenance changes

- Normalizes the full Windows, Ubuntu and macOS CI and packaging lanes while
  preserving the required 85% coverage threshold.
- Makes Windows process capability probing safe to import and type-check on
  Linux and macOS without advertising Windows-only capabilities there.
- Hardens Windows managed-service state and provider-workspace ACL handling.
- Rejects Windows absolute and drive-qualified distribution paths on every
  host.
- Adds exact-candidate release validation and packaged public-composition
  smoke coverage.

## Qualification

The exact qualified source is
`366d72139ba4dcaaa2495836ab5863c7d14ce5fb`. All 11 required GitHub Actions
jobs passed on that source. The impact-based black-box set J01, J02, J10, J11,
J16 and J20 passed, including real standalone Codex, standalone Claude, the
no-provider fallback and combined Codex plus Claude composition.

Windows, Linux and macOS native packages, wheel and source distribution were
validated against the exact source identity. The Windows installer is an
unsigned Nuitka standalone plus NSIS package, as authorized for this release.

V1-R01 remains reproduced historical evidence. It was not fixed, waived or
marked expected-failure. ARTIFEX 2.0.0, its tag and its published artifacts
remain unchanged.
