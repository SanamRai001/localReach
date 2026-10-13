# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, access approved LAN device capabilities.
**Current branch:** `feat/r2a-one-command-local-lab`
**Phase:** R2A automated separate-process mock verification, not a customer installer.
**Base:** `test/r1l-consolidated-acceptance` (PR #15). All previous PRs stacked and open; main still starter README.

## Verified
GitHub Actions verification runs 38351624562, 38351620338 and 38351586937 concluded SUCCESS on R1L, covering `go test -count=1 ./...`, `go vet ./...`, race tests and lab compilation. These do not prove separate-process delivery.

## This phase
Added disposable OpenSSL TLS cert + Go build + separate gateway/agent process smoke test script `scripts/verify-two-process.sh`, automatically cleaned up on exit. Added this script to Go verification workflow and `docs/R2A_ONE_COMMAND_LAB.md`.
The R2A two-process smoke test has **not yet been confirmed passing**.

## Security / UX boundaries
All demo traffic is localhost TLS on fixed 127.0.0.1:18787 with mock.ping only. Not a real internet-connected bridge, one-click consumer installer, device discovery or OS service. In-memory identity and test-key file, single-writer journals, incomplete signed outcome reconciliation, no public-safe admin enrollment/channel binding/limits. Never expose the lab gateway publicly.

## Next
Confirm CI smoke result and fix actual failures, then design simplified onboarding and real installer architecture without compromising tenant policy, secure identity, or device safety. Reserve WAN/hardware tests until release gate.
