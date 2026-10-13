# Project state

**Date:** 2026-10-13
**Goal:** One-install, minimal-click, securely scoped connectivity for LAN-only device capabilities.
**Current branch:** `feat/r1a-command-prototype`
**Phase:** R1A — local mock lifecycle implementation; R1B secure enrollment and cross-network experiment not started.
**Baseline:** `docs/foundation-rfc` (documentation PR #1 remains open); `main` contains initial README only.

## Changes this phase
- Added Go 1.22 module, loopback-only mock relay and polling agent.
- Created typed mock.ping command endpoint, simple QUEUED -> DISPATCHED -> SUCCEEDED lifecycle, status query, unauthorized/unsupported/duplicate rejection.
- Added httptest coverage and PowerShell manual reproduction guide at `docs/R1A_LOCAL_PROTOTYPE.md`.
- Deliberately limited to loopback. No actual secure remote access, signed installation, device discovery or tenant model.

## Verification
- GitHub writes verified during creation; tests **not executed in this environment**.
- User acceptance required: `go test ./...` followed by manual mock round-trip.
- No network/hardware/UX test completed.

## Risks / deviations
- Shared development bearer token, no identity enrollment, no TLS termination.
- In-memory queue loses jobs and may strand DISPATCHED items on agent crash.
- Polling is only a disposable protocol experiment, not RFC transport.
- Acknowledged device state cannot prove physical printer completion.
- No production usage of this branch; never expose localhost relay publicly.

## Next phase
1. User runs commands in R1A guide and reports actual test output.
2. Review enrollment identity, tenant authorization and crash-safe command model.
3. Build R1B on a safe branch: secure outbound connection over TLS, mock cross-network scenario, failure injection.
4. Preserve one-click setup as release UX target, not an R1A achievement.
