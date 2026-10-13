# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, approve strictly scoped LAN-device capabilities.
**Active branch:** `feat/r2g-pairing-tls-transport`
**Phase:** R2G TLS pairing transport experiment, CI verified.
**Base:** `feat/r2f-proof-bound-pairing-handoff` PR #21. PRs #1–#22 remain open and unmerged. No deployment.

## Verified CI
- Earlier R1L Go test/vet/race/build and R2A independent-process HTTPS mock smoke test succeeded.
- R2C–R2F prior CI defects corrected in their respective stacked branches; newest CI runs for PR branches #18–#21 concluded SUCCESS.
- R2G GitHub Actions run **38356105419** concluded **SUCCESS** for Go tests, vet, race tests, lab build and separate-process HTTPS mock smoke test.
- R2G branch was safely rebased against the corrected R2F head; PR #22 had no merge conflicts at latest check.
- No live WAN, CGNAT, physical-device, signed-installer or browser end-to-end verification.

## R2G changes
- Repaired R2F malformed Go source in the approval handoff.
- Corrected upstream unused localstatus test import and localsetup index-page redirect loop in PR branches #18–#22.
- Added TLS-only `internal/pairtransport` handler with preprovisioned Ed25519 administrator signing keys, authenticated tenant-scoped signed admin decisions, single-use admin nonce, fresh signed agent challenge, approved invitation retrieval and one-time enrollment proof.
- Added negative tests for plaintext/browser-origin requests, wrong admin/agent keys, cross-tenant approval, replay, expiry and enrollment reuse.
- `docs/R2G_TLS_PAIRING.md` describes non-production safety boundaries.

## Release blockers
- This handler starts **no internet listener** and supports only test-injected admin keys. Pair request creation is still in-process.
- No real administrator login, persistent tenant policy, audit trail, durable approval/identity store, OS-managed agent key storage, rate limits beyond bounded state, TLS channel binding or multi-instance replay tracking.
- No live pairing UI, real device grants, signed installer, discovery, printers or attendance device communication.
- A legacy static request-ID handoff method remains available internally; do not use it as a network authentication method.
- Mock lab transport is loopback only. Do not expose it publicly.

## Next
R2H: durable and auditable tenant-admin approval with protected agent key storage, then integrate paired status into the local agent/UX. Keep command capabilities disabled and require security review and network/hardware acceptance before public deployment.
