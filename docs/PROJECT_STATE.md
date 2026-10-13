# Project state

**Date:** 2026-10-13
**Goal:** Secure, one-install access to approved LAN-only device operations.
**Active branch:** `feat/r1j-reconciliation-hardening`
**Phase:** R1J narrow late-outcome reconciliation and request parser fix.
**Baseline:** `feat/r1i-reconciliation-runner` PR #11; upstream PRs #1–#10 remain open. Main has starter README only; no merges or deployments.

## Changes
- Previous R0–R1I: UX and architecture docs; mock command broker; Ed25519 enrollment; TLS session test handler; edge journal; outbound HTTPS mock agent; reconnect polling.
- R1J: corrected gateway trailing/malformed JSON detection.
- Added broker `ReconcileObservedResult` for only an expired RECEIVED→INDETERMINATE command, restricted to its existing tenant/agent/original lease and final observed state. Added scope/rewrite tests.
- Documented that this is only an internal primitive: **no evidence verification or public reconciliation endpoint**; see `docs/R1J_RECONCILIATION.md`.

## Verification
Files pushed to GitHub. **Go tests/vet/race, multi-process, real-network, CGNAT, hardware and installer/UX tests not run**. Source code publication is not runtime verification.

## Security and reliability risks
- Lease token alone does not prove physical outcome. The new method must be invoked only behind independent evidence validation, which is not yet implemented.
- Agent poller does not perform late-result reconciliation; no durable signed edge evidence.
- Single-writer file stores have no OS locks, partial-write recovery or compaction.
- No durable authenticated workspace-admin enrollment, TLS-channel identity binding, rate limits or public-safe listener.
- No actual one-click installation/discovery or physical device capability. No deployment.

## Next phase
Prioritize cross-process storage safety and a reproducible separate-process TLS test harness, followed by authenticated evidence reconciliation and consolidated Go verification. Keep real hardware and public exposure disabled until required security gates pass.
