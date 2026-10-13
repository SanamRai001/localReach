# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, explicitly approve secure LAN-device capabilities.
**Active branch:** `feat/r2c-local-status-pairing-gate`
**Phase:** R2C read-only localhost agent-status contract and pairing trust specification.
**Base:** `feat/r2b-setup-experience` PR #17; upstream PRs #1–#16 stacked and unmerged.

## Previously verified
R1L Go test/vet/race/build workflow successful; R2A distinct gateway/agent loopback HTTPS CI smoke run 38351933557 successful. This does not prove real internet connectivity or hardware support.

## R2C changes
- Added `internal/localstatus` with GET `/v1/local/status`; no listener is started, loopback-only peer check, restricted local setup origin and zero mutation routes.
- Added Go tests for local/remote access, read-only method, allowed/disallowed origins.
- Setup walkthrough now attempts a read-only status fetch when the Connect preview is shown; if absent or loaded from local file, explicitly says unavailable.
- `docs/R2C_STATUS_PAIRING_CONTRACT.md` specifies admin-authorized single-use pairing, agent-held signing keys, verification and per-capability approval. **No real pairing, installation or discovery implemented.**

## Verification
R2C files published to GitHub, **no R2C CI result verified yet**. Earlier R2A successful. No live status service, browser integration/e2e test, device or WAN test.

## Security limitations
A local status contract is not a secure admin approval flow. No browser-native bridge, real local agent service, durable admin identity policy, secure OS key store, public deployment, channel-bound session or actual capability grants. No hardware may be exposed. Avoid portraying simulated preview as actual connection.

## Next
R2D: serve trusted local setup UI and status together using a dedicated loopback-only process, strengthen Origin/Host validation against rebinding, then build admin-authorized pairing protocol with secure key storage. Verify CI and avoid exposing public services.
