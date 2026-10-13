# Project state

**Date:** 2026-10-13
**Goal:** Install once, securely connect approved LAN device capabilities.
**Active branch:** `feat/r2e-admin-pairing-approval`
**Phase:** R2E tenant-scoped pairing approval policy primitive (not end-to-end pairing).
**Base:** `feat/r2d-loopback-setup-service` PR #19; upstream PRs #1–#18 open. No merge/deploy.

## Implemented
R0–R2D architecture and UX docs, identity and signed sessions, mock HTTPS command transport, crash-aware journals, reconnection, loopback status and setup UI. R2E adds `internal/pairing` with pending/rejected/approved/expired/enrolled state checks, tenant-scoped independently authorized admin decisions, one-time invitation issuance only after approval, and tests for denied unauthorized/cross-tenant and expired approvals.

## Verified baseline
Prior CI Go tests/vet/race/build passed and two-process mock loopback HTTPS test passed. R2E CI not confirmed; new Go tests not run here.

## Blocking limitations
R2E is **not usable pairing**: identity token is hidden and no secure agent delivery exists; no authenticated admin HTTP route, persistent approvals, safe OS key storage or independent signed agent consent. No capabilities granted. Local setup UI remains NOT_PAIRED/OFFLINE. Browser status is not linked to a real installed agent. No public-safe WAN service, hardware, signed installer or discovery. In-memory pairing and identity stores restart empty.

## Next
Verify R2E CI; design a durable tenant-admin identity/authorization interface and secure one-time invitation transfer, with independently approved capabilities. Do not expose pairing endpoints publicly or use hardware until end-to-end security gates pass.
