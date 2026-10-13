# Project state

**Date:** 2026-10-13
**Goal:** Install once, connect securely, authorize narrowly scoped LAN-only capabilities without router setup.
**Current branch:** `feat/r2j3-invitation-control-plane`
**Phase:** R2J.3 initial operator-only invitation/control-plane slice.
**Base:** `feat/r2j2-local-agent-verification` (PR #30). Prior PRs #1–#30 open and unmerged; main unchanged, no deployment.

## Verified baseline
R2J.2 latest CI run `38374321624` completed SUCCESS across Linux Go unit/vet/race, two-process mock TLS, PostgreSQL pairing integration, Windows DPAPI and macOS Keychain/native binaries. No installed service, deployed public gateway or real hardware.

## This branch
- `migrations/063_pairing_invitations.sql`: tenant/site-scoped 256-bit random invitation codes stored only as hashes, strict one-time redemption, 10-minute expiry, issuer scope, pending-request reference and audit.
- `internal/pgpairing`: atomic issue (live OWNER/ADMIN checked in SQL) and one-time redeem that produces **PENDING** request only, retaining separate signed approval.
- `internal/pairapi`: guarded HTTPS-native administrator key login, invite issue, invitation redemption. Role-bound `pgauth` bearer and separately signed decision remain required to approve. Fail-closed bounded local per-peer admission guard on new routes, no browser-origin access.
- `internal/agentremote.Client.RequestInvitation` and native `localreach-agent request`: existing OS-protected identity submits only its public key and short-lived secret read over stdin (never CLI argv); prints pending ID, not approval.
- `cmd/localreach-control`: **loopback-only** (127.0.0.1:19443) manually runnable TLS service requiring explicit operator certificate/key and PostgreSQL DSN, with `verify-full` by default. Only an explicitly authorized local `localreach_test` database may use opt-in plaintext PostgreSQL.
- PostgreSQL invitation concurrency, expiry, scope, admin revocation and replay tests; HTTPS login→invite→pending→signed approval→enrollment tests; limiter and operator config negative tests.
- `docs/R2J3_INVITATION_CONTROL.md` documents developer-local commands and release blockers.

## Verification
Code committed. **R2J.3 branch CI not yet confirmed**. Must verify all Linux/Windows/macOS/PostgreSQL jobs before accepting. No actual Internet ingress or end-user signed installation was exercised.

## Explicit remaining limitations
Invitation does **not** authorize pairing or device permissions. Admin public-key provisioning remains operator-managed and is not a consumer SSO/login portal. Control plane is localhost only, so it is not reachable from a remote agent over the Internet. No distributed throttling, authenticated remote proxy, certificate automation, OS service/installer, persistent active relay session, truthful ONLINE signal, real WAN/CGNAT tests, or explicit device grants. No printers/attendance hardware access. Do NOT expose via public port or proxy.

## Next
Confirm CI. R2J.4 true hardened cloud control plane + human approval workflow, then R2K separately authorized capability grants and read-only discovery. Merge and deployment require explicit approval.
