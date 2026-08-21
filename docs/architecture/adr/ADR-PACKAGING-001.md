# ADR-PACKAGING-001 — Frozen Native Distribution

## Status

ACCEPTED for V1 implementation.

## Context

V1 must be installable without asking an end user to install Python, pip, or a
virtual environment. Development remains Python 3.12+ with `uv`. The selected
freezer must support Windows, Linux, and macOS and must not change Core storage
or authority boundaries.

## Decision

Use PyInstaller one-directory builds as the V1 reference distribution, built
natively on each target operating system in CI. A one-file variant may be
offered after platform validation, but is not the acceptance baseline.

## Alternatives

- Nuitka: potentially better startup/performance, but adds a compiler toolchain
  and more platform-specific operational complexity.
- zipapp/PEX: portable only where a compatible Python runtime already exists,
  so it cannot meet beginner installation requirements by itself.
- PyOxidizer: viable in principle, but has a smaller current integration and
  maintenance surface for this package.

## Consequences

- Each OS artifact is built and tested on that OS; cross-compilation is not
  claimed.
- The repository and wheel remain canonical development/source distributions.
- Frozen-build provenance records Python, PyInstaller, platform, commit, and
  artifact digest.
- Platform CI evidence is required before a platform is marked PASS.

## Revisit triggers

Revisit if PyInstaller cannot bundle a required V1 dependency, cannot pass a
clean-machine journey, or materially prevents signing/notarization.

