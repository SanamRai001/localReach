# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect and explicitly approve scoped LAN-only device access.
**Current branch:** `feat/r2i3-agent-identity-binding`
**Phase:** R2I.3 backend-native identity enrollment and post-restart challenge recovery.
**Base:** `feat/r2i2-macos-linux-secret-stores` PR #27. All upstream PRs open/unmerged; nothing publicly deployed.

## Verified prior baseline
R2I.2 latest GitHub Actions run `38365823738` completed SUCCESS: Linux Go unit/vet/race + mock HTTPS, Windows DPAPI + package tests, macOS Security.framework CGo + packages + disabled-CGo fallback, PostgreSQL pairing/admin sessions. No live Keychain/Secret Service integration with customer desktops or real hardware.

## R2I.3 source
- `migrations/062_agent_resume.sql` creates one-use persisted SHA-256-hashed agent resume challenges and scoped successful-proof audit.
- `internal/pgpairing.ResolveIdentity`, `BeginResume`, `VerifyResume` bind agent recovery after restart to its ORIGINAL persisted unrevoked public key via a fresh domain-separated Ed25519 signature; organization BLOCKED and pairing REVOKED fail closed.
- `pgpairing.EnrollmentMessage` exports the existing exact enrollment message bytes so the native OS signer can sign directly without exporting private key bytes.
- `internal/agentlifecycle.Coordinator` composes a native OS protected `agentkeys.Identity`-compatible signer with the server-side PostgreSQL contract for RequestPairing, FinishPairing only after administrator approval, and VerifySavedIdentity after explicit native key Load. The coordinator never creates/replaces native signing keys.
- Unit and disposable real PostgreSQL integration tests verify unsigned/unapproved denials, correct Ed25519 message bindings, cross-tenant / wrong-key denial, restart proof, expiry, replay, block/revocation, and replacement identity without inherited trust.
- `docs/R2I3_AGENT_BINDING.md` documents explicit recovery/rotation policy and missing service wiring.

## Verification
**R2I.3 CI VERIFIED GREEN:** GitHub Actions run `38367233351` completed SUCCESS across Linux Go unit/vet/race + separate-process HTTPS mock, PostgreSQL pairing/login/native-coordinator integration, Windows DPAPI + full package tests, and macOS Security.framework CGo + full package tests + disabled-CGo fail-closed fallback. The preceding build failure was an unused test import and was corrected. PostgreSQL CI includes `internal/agentlifecycle` alongside pairing and login packages. A subsequent documentation-only update may trigger its own run.

## Security / product limitations
This coordinator is a **server-side in-process integration contract**, not an installed native agent calling a real HTTPS API. Database credentials must NEVER ship in the desktop app. No network pairing API, rate-limited ingress, authenticated cloud agent transport, active signed device sessions, revocation fanout, OS-native reset/rotation UI, installer, capability grants, discovery, cloud relay or physical hardware usage. Successful resume proof is NOT a device grant or ONLINE status.
The platform-specific macOS/Linux tests still lack real unlocked OS store acceptance on installed machines. Lost key/rotation requires audited admin-approved revocation and fresh identity + pairing; automatic replacement is forbidden.

## Next
Verify R2I.3 CI. Then R2J native-to-backend encrypted pairing contract and local setup UX, with an externally authenticated control plane and explicit device grants. Maintain unmerged PR stack until explicit approval.
