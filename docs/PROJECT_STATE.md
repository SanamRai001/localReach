# Project state

**Date:** 2026-10-13
**Goal:** Minimal-click, secure application-to-LAN-device capabilities.
**Active branch:** `feat/r1h-outbound-mock-transport`
**Phase:** R1H outbound HTTPS mock transport authored.
**Dependency chain:** `main` starter README -> open PRs #1–#9 -> this branch based on `feat/r1g-mock-delivery-integration`. No merges/deployments performed.

## Code changes
- Preserved R0 vision/UX, R1A mock, R1B identity, R1C session/TLS, R1D journal, R1E local integration, R1F broker and R1G in-process delivery.
- Added `internal/transport`: TLS-only mock claim/receive/complete endpoints; scope derived from verified enrolled agent identity; authenticated/revocable session required for operations.
- Added outbound agent HTTPS poller: identity handshake -> claim -> durable edge Submit -> broker Receive -> durable Begin/Finish -> broker Complete, only `mock.ping`.
- Added tests for TLS round trip, other-tenant isolation, revoked agent, plaintext denial and duplicate prevention.
- Added `docs/R1H_OUTBOUND_TRANSPORT.md` documenting limits and next requirements.

## Verification
GitHub commits created. **No Go tests, go vet, browser UX, installer, cross-network, CGNAT or hardware verification executed.** User prefers batch acceptance after cohesive milestones.

## Remaining risks
- Tests use loopback test TLS server; not a live WAN gateway and no independent runnable agent service.
- Not a persistent outbound socket; reconnect/session refresh supervisor missing.
- Cloud/edge reconciliation incomplete when acknowledgements are lost; unsafe for physical devices.
- Identity, sessions and broker are per-process experiments; no hardened tenant/app auth, channel-bound TLS identity, persistent registry or rate limiting.
- No signing/auto-update, discovery or one-click user interface yet; production/public exposure prohibited.

## Next phase
R1I: build reconciliation protocol and agent runner lifecycle, then provide a reproducible local multi-process test harness and consolidated verification checklist. Defer WAN and real hardware until threat model/security gates pass.
