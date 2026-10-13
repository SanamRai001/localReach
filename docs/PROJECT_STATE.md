# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, authorize only approved LAN device capabilities.
**Active branch:** `feat/r2h-durable-admin-trust-ledger`
**Phase:** R2H.1 persistent administrator public-key trust, revocation, and audit/replay ledger.
**Base:** `feat/r2g-pairing-tls-transport` (PR #22). All PRs #1–#22 remain stacked and open; no merges, deployments or real devices.

## Verified baseline
R2G full GitHub Actions verification passed on latest baseline SHA `0f027e3a69b106d71b0b0f2267ac4f023dc2ab80` (run 38356237707): Go tests, vet, race, lab build and separate-process HTTPS mock smoke test. These tests do not exercise public WAN or physical hardware.

## R2H.1 code
- New `internal/admintrust` file-backed, single-writer, fsynced append-only ledger stores scoped public keys, explicit revocations and consumed decision nonce hashes.
- Events form a SHA-256 hash chain; replay validates fields, hash linkage, state transitions and rejects partial/tampered records. Fixed 64 MiB cap, fail-closed ownership sentinel; no automatic recovery.
- `pairtransport.NewWithTrust` integrates persisted administrator key verification and replay denial, signed decision expiry bounds and per-tenant/key selection. Decisions are consumed before asking the in-memory pairing manager to approve.
- Added Go tests for restart survival, revocation, competing decisions, corruption, signing and TLS handler restart. Existing `New` in-memory test constructor remains for legacy isolated experiments.
- `docs/R2H_DURABLE_ADMIN_TRUST.md` details assumptions, limitations and next steps.

## Verification
R2H changes authored and published; **R2H CI verified green** for commit `d5dc260990e64986248c6a10700ebfa5979102b9`, run `38357367366`: unit/integration, vet, race tests, lab build and separate-process HTTPS smoke test. The resulting documentation-only update will be checked separately. No new release, desktop app, internet deployment or hardware acceptance.

## Security and remaining architectural gaps
- Admin public keys are provisioned and revoked by trusted in-process calls, not authenticated operator/admin services. Signatures do not themselves prove current tenant-admin membership.
- Hash chains detect ordinary corruption, not adversarial rewrites by filesystem owners. Audit needs external checkpointing/immutability for production.
- In-memory `pairing.Manager` and `identity.Registry` cannot recover pairing state after crashes. No atomic persistence across trust and pairing stores.
- No secure native key storage, key rotation, CSRF-safe real browser pairing, rate limiting/lockout, robust OS file locks, compaction or authorized capability grants.
- No public-safe gateway, real WAN/CGNAT verification, signed installer, discovery or printer/attendance adapter.

## Next
Proceed with durable transactional pairing/identity and real administrator authentication (R2H.2), followed by protected desktop agent identity (R2I). Keep public/device operations disabled pending independent acceptance.
