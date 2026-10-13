# Project state

**Date:** 2026-10-13
**Product:** LocalReach — outbound-only narrowly authorized LAN device access, designed to avoid agent-side router changes.
**Branch:** `test/r2j6-separate-process-tls-acceptance`
**Phase:** R2J.6A — separate OS process control-plane TLS endurance, crash and recovery acceptance.
**Base:** `feat/r2j5-authenticated-outbound-session` (PR #34). All earlier PRs #1–#34 remain open and stacked. No merge/deploy.

## Verified preceding baseline
R2J.5 latest final CI `38383543335` SUCCESS for all four jobs: Linux Go/vet/race, PostgreSQL connection leases and signed TLS streaming revocation, Windows DPAPI packages, macOS Keychain packages. No actual Internet pilot or physical devices.

## This branch
- **Bug fix:** `cmd/localreach-control` used HTTP server-global `WriteTimeout:10s`, disconnecting an otherwise healthy long-lived heartbeat stream. It now has no global response write timeout; streaming handler still bounds **each** write with its own 5-second per-frame deadline. Server read/header timeouts and client heartbeat watchdog remain.
- `internal/pilotacceptance/acceptance_test.go` compiles/launches the actual control-plane executable as a separate OS process, configures ephemeral PEM TLS trust, and uses a separate client with test-only Ed25519 credentials and no database password.
- Acceptance tests require disposable loopback PostgreSQL and run migration `060`–`065`. The test proves TLS certificate rejection, authenticated connection lasting **more than 12 seconds**, actual heartbeat, server process crash, client disconnect, 15s database lease expiry, server restart with the same agent key, successful reconnect, separately signed revocation cutting the stream, and denied revoked reconnect.
- CI adds the process-level TLS test after the regular PostgreSQL integration suite, using a compiled control-plane binary. Tests are opt-in by environment; local unit suites skip this intrusive integration if not explicitly configured.
- `docs/R2J6A_PROCESS_TLS_ACCEPTANCE.md` describes the test and exactly which real two-network requirements remain unverified.

## Verification
**R2J.6A CI VERIFIED GREEN:** GitHub Actions run `38387592837` SUCCESS across Linux Go/vet/race, Windows DPAPI/full packages, macOS Keychain/full packages, and disposable PostgreSQL tests plus the separate-process real-control-plane TLS acceptance. The acceptance test `TestSeparateProcessTLSCrashReclaimRevocation` actually ran and PASSED in 31.41s, proving the >12-second stream, process kill, lease timeout, process restart and separately signed revocation. This is not a two-network pilot. A documentation-only update triggers a subsequent CI run.

## Important limits
This runs separate processes on one CI machine, **not** on different networks. There has been **no** cloud deployment, DNS/certificate provisioning, remote client's public IP firewall test, CGNAT acceptance, external device installation, printer or attendance access. All command/device capabilities remain NONE. Real R2J.6B multi-network pilot requires explicit authorization, approved staging service, and operator-owned TLS/firewall/PostgreSQL environment; not performed. Production SSO, signed installer, scalable gateway, revocation metrics and device capability grants remain unfinished.

## Next
Verify CI; correct any discovered bugs. Then R2J.6B actual authorized two-network pilot, plus code work toward R2K.1 audited, separately approved per-device permission grants and read-only discovery. Do not deploy/merge or operate hardware without explicit approval.
