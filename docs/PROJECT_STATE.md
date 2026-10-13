# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect and authorize scoped LAN-only device capabilities.
**Active branch:** `feat/r2d-loopback-setup-service`
**Phase:** R2D local setup page and read-only status served from the same trusted loopback origin.
**Base:** `feat/r2c-local-status-pairing-gate` (PR #18); stacked PRs #1–#18 remain open. No merge/deploy.

## Prior confirmed verification
Go CI test/vet/race/build passed in R1L; loopback separate-process HTTPS mock acceptance passed in R2A. No actual internet network or device verification.

## R2D changes
- `internal/localsetup` serves exact static setup assets and existing `/v1/local/status` handler from `127.0.0.1:18788`.
- Strict Host, loopback peer, optional Origin, read-only method and asset path checks; CSP and other conservative response headers.
- `cmd/localreach-setup` standalone preview entrypoint, started by `go run ./cmd/localreach-setup`.
- Added tests for invalid host, nonloopback peer, origin, mutation and static allowlist, plus `docs/R2D_LOCAL_SETUP.md`.

## Verification
R2D implementation committed, new CI not confirmed yet. No local process was started, nor real UI browser or OS service tested during authoring.

## Security / functionality limitations
This is a read-only local preview service, not an installed agent or actual connection. Default status remains NOT_PAIRED/OFFLINE. No authorization-backed pairing, native secure key store, user grants, signed installer, device discovery, physical adapters, WAN listener or CGNAT verification. Same-origin status doesn't authenticate malicious local software. Keep real devices and public exposure disabled.

## Next
Confirm current PR CI, then implement admin-approved pairing as a separate transactional security boundary. Only after that: first real installer/agent status, explicit capability grants and supported discovery. Preserve PR stack without unauthorized merges.
