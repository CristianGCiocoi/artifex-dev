# ADR-PACKAGING-002 — ARTIFEX 2.0 Core Windows Distribution

## Status

ACCEPTED by Architect/Product decision for M7 on 2026-08-29.

## Context

The preserved PyInstaller one-directory candidate was quarantined by Microsoft
Defender as `Behavior:Win32/Execution.A!ml` on the clean Windows qualification
baseline. PyInstaller is not a frozen ARTIFEX semantic invariant, and the
failure evidence remains immutable M7 provenance.

## Decision

The primary Windows shipping candidate is a Nuitka standalone distribution
wrapped in an NSIS installer named `ARTIFEX-Setup.exe`.

- Nuitka onefile is not authorized for the primary candidate.
- The normal application layout is `C:\Program Files\ARTIFEX`.
- The installer uses the authenticated ARTIFEX lifecycle to initialize state,
  register and start the managed service, upgrade transactionally, and remove
  only manifest-owned files during uninstall.
- Provider authentication remains a separate provider setup flow.
- Microsoft Defender remains enabled without exclusions, restoration,
  allow-listing, or local trust bypasses during qualification.

## Preserved boundaries

This decision changes packaging only. Project Authority, RunStore authority,
managed-service persistence, Capability Graph composition, Execution Envelope,
Actor attribution, Acceptance Authority, Project Catalog, dashboards, journey
semantics, and ADR-T001 through ADR-T024 remain unchanged.

## Fallback and gates

`cx_Freeze + MSI` is permitted only if the Nuitka standalone + NSIS candidate
cannot satisfy the frozen M7 Windows contract. Broader packaging research is
not authorized. A human gate remains necessary for signing identity purchase or
legal verification, irreducible account authentication, or a genuine frozen
architecture contradiction.
