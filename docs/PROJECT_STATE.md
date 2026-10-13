# Project state

**Date:** 2026-10-13
**Goal:** Install once, approve securely and access only explicitly authorized LAN-only device capabilities.
**Current branch:** `feat/r2j2-local-agent-verification`
**Phase:** R2J.2 — manually runnable native agent, live HTTPS identity proof and read-only local status.
**Base:** `feat/r2j1-https-pairing-control-plane` (PR #29). Prior PRs #1–#29 remain open and stacked; main unchanged. Nothing deployed.

## Verified baseline
R2J.1 latest CI run `38369735674` SUCCESS across Linux Go unit/vet/race and mock TLS two-process smoke, real PostgreSQL pairing/TLS tests, Windows native DPAPI/full packages and macOS Keychain/full packages/fallback. No actual installed service or publicly deployed cloud control plane.

## New R2J.2 code
- `cmd/localreach-agent` adds manual native `init`, `enroll` and `serve` commands. `init` explicitly creates an OS-protected user-scoped Ed25519 identity and prints only public information. `enroll` requires a separately admin-approved request and a trusted HTTPS control-plane URL. `serve` loads an existing identity only, performs outbound identity verification, and runs the read-only localhost setup page. No plaintext keys, database credentials or device permissions.
- `internal/agentservice.Monitor` verifies identity immediately and periodically against `agentremote.Client.VerifyIdentity`, with a max 90-second recent-proof window. It reports PAIRED only when recently server verified; failure or expiry becomes UNVERIFIED. Cloud connection stays OFFLINE and devices NOT_DISCOVERED because a proof is not an online session.
- `internal/localstatus.Snapshot` adds explicit verification freshness and lastVerifiedAt UTC fields; no mutation endpoints. `localsetup.ServeContext` supports cancelable loopback-only HTTP, strict Host, peer address, and Origin guards.
- `web/setup/setup.js` displays identity proof accurately and never suggests device connectivity/permissions from a status GET.
- Added monitor/local handler tests, CLI fail-closed command tests and cross-platform native diagnostic binary compilation. `docs/R2J2_LOCAL_AGENT.md` provides explicit user instructions and limits.

## Verification
R2J.2 changes committed; **full branch CI result not yet verified**. Must pass all existing Go, PostgreSQL, Windows and macOS CI jobs before acceptance.

## Remaining production blockers
No signed installer/autostart service, actual deployed authenticated TLS control-plane, administrator consent and invitation UI, multi-tenant abuse rate limits, persistent authorized cloud command session, WAN/CGNAT acceptance, device grants/discovery/printer or attendance drivers, production OS service accounts, native vault live acceptance and recovery/rotation UI. An ephemeral successful identity proof is NOT an online cloud relay session.
The native diagnostic agent is manually runnable from the repo and fails closed when the key vault is unavailable; no production packaging or device command permissions exist.

## Next
Verify R2J.2 CI and resolve code/OS failures. Then R2J.3 hardened operator-hosted pairing service and trusted invitation/user UX, followed by R2K scoped device discovery and capability grants. Do not merge/deploy without explicit approval.
