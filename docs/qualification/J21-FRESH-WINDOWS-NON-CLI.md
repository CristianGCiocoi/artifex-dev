# J21 — Fresh Windows non-CLI qualification

J21 qualifies the shipping Windows installer as a user product. It is not a
source-checkout test and it is not a scripted substitute for the user journey.
The clean VM must remain on Windows 11 24H2 x64 with Defender enabled.

## Separation of actions and inspection

Every required stage is recorded in contract order. `USER_UI_ACTION` means the
operator used only the installer, Start menu, Platform Dashboard, Project
Dashboard, Codex, Claude, or normal Windows restart/uninstall UI. It requires a
screen capture. `EVIDENCE_ONLY_INSPECTION` may read service state, receipts,
logs, or file inventory after the user action; it must not mutate the product,
open a terminal on the clean VM, or repair a failed stage.

The capture processor runs after the journey on the qualification control
host. Its use is not remediation. If a command, manual PATH edit, manual vendor
configuration edit, source checkout, or post-failure repair was needed on the
clean VM, preserve the failed capture and start a new candidate/run.

## Evidence package

Prepare one evidence root containing secret-safe screenshots, recordings,
installer logs, ARTIFEX receipt exports, Windows event exports, service-status
exports, or file inventories. Use normalized relative paths. Every reference
in the capture manifest includes its SHA-256 digest and
`contains_secret_material: false`.

The capture manifest uses `artifex.j21-capture/v1` and contains:

- the exact source commit plus declared installer and provenance hashes;
- VM and clean-snapshot identities;
- the no-shortcut operator attestation;
- exactly 20 ordered stage observations with channel, UTC time, status and
  evidence references;
- real Codex and Claude client versions, approval facts, live read-only result,
  and persistent receipt hashes; and
- install, dashboard, reboot, uninstall, resource-removal and retained-data
  outcomes.

Seal it with `tools/artifex2/capture_j21.py`, supplying the actual
`ARTIFEX-Setup.exe`, its provenance JSON and the evidence root. Then validate
the resulting `artifex.j21-qualification/v2` record with
`tools/artifex2/validate_j21.py` and the same files. Both commands fail closed
on an altered file, path escape, reordered stage, missing visual proof,
forbidden shortcut, incomplete provider proof, or provenance mismatch.

No repository evidence claims a real J21 pass until a clean-VM run produces
this complete package and the independent validator returns `ok: true`.
