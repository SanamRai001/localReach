# Project state

**Date:** 2026-10-13
**Project:** LocalReach — safe and simple connectivity for LAN-only device capabilities.
**Active branch:** `feat/r1g-mock-delivery-integration`
**Phase:** R1G in-process authenticated mock broker-to-edge integration authored.
**Branch:** Based on `feat/r1f-mock-broker` PR #8, dependent on PRs #1–#7; `main` remains starter README. No merges/deployments.

## Changes
- Existing R0–R1F: architecture/UX docs, local mock relay, Ed25519 identity, one-use signed session, TLS-only test handler, fsynced edge journal and broker.
- R1G: `internal/integration/delivery.go` orchestrates signed TLS agent handshake/heartbeat, registry-scoped broker Claim, durable edge Submit, broker Receive, edge Begin/Finish and broker Complete on mock.ping only.
- Added integration tests for successful mock delivery, cross-tenant isolation, revoked identity and safe duplicate edge ID rejection.
- Added `docs/R1G_MOCK_DELIVERY.md` detailing correctness and recovery gaps.

## Verification
GitHub files committed; `go test ./...`, `go vet ./...` and race/build checks NOT executed. User requested batching substantial manual verification. No WAN, CGNAT, hardware, UI or installation tests.

## Known risks
- Execution remains **in-process**, not cloud-to-agent transport.
- No admin auth, persistent identity registry, channel binding, audited grants or WAN-safe listener.
- Edge and broker journal records can diverge; reconciliation not implemented.
- Both file journals are single-writer, not corruption-repairable or multi-node safe.
- No public networking, real device adapter or one-click UX achieved.

## Next phase
R1H: outbound-only TLS mock message transport with bounded polling or streaming, strict per-agent authorization and reconnect semantics. Build reconciliation before any hardware operations; run consolidated Go suite at meaningful acceptance gate. Preserve single project-state file and existing branch work.
