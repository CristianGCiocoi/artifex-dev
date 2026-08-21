# M09 Acceptance Report

M09 — Beginner Mode & Distribution is **ACCEPTED** at
`8ccd2c75f39774ec797cc50d5424b349d4babdf0`. All 11 tasks pass. Exact-SHA
GitHub Actions run `32533785668` passed all nine jobs: full test, static, and
coverage gates on Windows, Linux, and macOS with Python 3.12/3.13, plus native
PyInstaller one-directory build and install → self-upgrade → self-uninstall
smoke on all three operating systems.

The distribution lifecycle requires strict adjacent artifact provenance,
single-use expiring plan-bound approvals, authenticated manifests, and
transactional rollback. POSIX internal links are manifest-bound and preserved;
Windows link-bearing bundles are intentionally rejected fail-closed while the
official regular-file Windows bundle passes its complete lifecycle. Evidence:
`EVD-M09-001`. No blockers or waivers.
