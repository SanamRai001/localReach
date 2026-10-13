# Project state

**Date:** 2026-10-13
**Goal:** Install once and connect approved LAN device capabilities with minimal configuration.
**Current branch:** `feat/r1f-mock-broker`
**Phase:** R1F mock broker implemented, awaiting combined acceptance.
**Base:** `feat/r1e-mock-integration` (PR #7), stacked on PRs #1–#6; `main` has only starter README. No merging or deployment.

## Implemented this phase
- `internal/broker`: durable single-writer append-only, fsynced mock.ping command records scoped by tenant/agent.
- State separation: QUEUED, LEASED, RECEIVED, SUCCEEDED, FAILED and INDETERMINATE.
- Leases use random fencing tokens. Re-lease only prior to receipt; uncertain acknowledged operations are not automatically replayed.
- Added tests for duplicate handling, tenant/agent isolation, expiration, stale tokens and crash/restart reconciliation.
- Added `docs/R1F_BROKER.md` with delivery semantics, boundaries and future integration.

## Earlier work
R0 UX/architecture docs; R1A local mock relay; R1B agent identity; R1C signed sessions and TLS-only handler; R1D edge journal; R1E TLS-authenticated local mock integration.

## Verification
GitHub writes completed. Go tests, vet, race tests, WAN, hardware, installer and UX checks **not executed**; user requested batched manual acceptance. No claim of runtime readiness.

## Risks
The new broker is not wired to TLS transport, edge journal or public API. Go package parameters are NOT authentication. No production persistence strategy, locking, compaction, capacity recovery, multi-node delivery, rate limiting or audited tenant grants. Partial disk writes fail closed; no recovery tooling. Existing demo relay remains loopback-only and development-token-protected. No internet, real device or one-click setup achieved.

## Next
R1G: integrate secure mock delivery broker-to-outbound-agent with separate durable edge receipt/journal, no arbitrary LAN socket access. Establish correct end-to-end recovery and permission gates before any test public listener. Maintain `docs/PROJECT_STATE.md` as the single current state file. Batch verification into a meaningful complete-flow test gate.
