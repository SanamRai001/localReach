# Project state

**Date:** 2026-10-13
**Goal:** Install once, connect securely, and approve narrowly scoped local device capabilities.
**Current branch:** `feat/r2h2-durable-pairing-lifecycle`
**Phase:** R2H.2 prototype durable request/approval/enrollment/revocation lifecycle.
**Base:** `feat/r2h-durable-admin-trust-ledger` (PR #23). All upstream PRs #1–#23 stacked/open; main not changed, no deployment.

## Verified baseline

R2H.1 latest GitHub Actions run `38357488592` completed SUCCESS: Go tests, vet, race tests, lab compilation and local separate-process HTTPS mock smoke test. These do not prove production WAN or device capability access.

## R2H.2 changes

- `internal/pairledger` persists scoped pairing proposals, admin decisions, enrolled identities and revocations in one bounded, fsynced hash-chained journal. Public keys only; no private keys, invitation tokens or device grants. A restart discards ephemeral one-use agent proof challenges.
- `internal/pairpolicy.Controller` verifies signed, short-lived tenant/key-bound admin decisions using the previous persisted `admintrust` store and consumes nonces before recording a pairing decision. This is **fail-closed, not atomic across two journals**.
- Tests for restart survival, signature possession, expired/unauthorized requests, one-time challenge/replay, corrupted log, concurrent requests and admin revocation.
- `docs/R2H2_DURABLE_PAIRING.md` describes missing production security gates.

## Verification

R2H.2 code and tests passed GitHub Actions **run 38358204308** at commit `5d7c6216fd35c25cbc676b37a862282a31c3b885`: Go tests, vet, race detector, lab build, and two-process HTTPS mock smoke test. A documentation-only state update triggers a separate run. No real hardware, WAN, OS installer or public listener.

## Crucial limitations

- Still no actual authenticated administrator login/role verification; all public keys are trusted bootstrap data. No rate-limited externally authenticated pairing proposal service.
- Existing `pairing.Manager` / `pairtransport` still use the previous in-memory pairing model. New persistent ledger is independently tested and not yet wired to an installed agent or UI.
- File ownership is an O_EXCL sentinel, not a portable robust lock; no crash-safe recovery, compaction, multi-node operation or tamper-proof audit.
- No single transaction between administrator nonce consumption and pairing decision. A crash may consume the nonce without recording an approval; fail closed.
- No OS keychain, signed installer, discovery, device grants, real cross-network or hardware verification. Do not expose public gateway or allow physical effects.

## Next

Verify and fix R2H.2 CI. Follow with transactional DB-backed identity/admin policy and durable pairing integration (R2H.3), protected native agent key storage (R2I), real pairing UX (R2J), and consent-based discovery. Keep PRs unmerged pending explicit permission.
