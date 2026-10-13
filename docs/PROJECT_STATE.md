# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, and authorize only approved local-device capabilities.
**Active branch:** `feat/r2f-proof-bound-pairing-handoff`
**Phase:** R2F approved invitation handoff, internal primitive.
**Base:** `feat/r2e-admin-pairing-approval` (PR #20); PRs #1–#20 remain stacked and unmerged. No deployment.

## Verified history
Prior R1L Go CI tests, vet, race and lab compilation succeeded. R2A two-process loopback HTTPS smoke CI succeeded. Neither verifies internet connectivity, UI pairing nor physical devices.

## New R2F work
- `internal/pairing.Manager.InvitationForAgent` makes the invitation obtainable after approval only when a candidate demonstrates possession of its originally submitted Ed25519 private key by signing the random request ID under an independent domain separator.
- `SignHandoff` client helper for signed proof.
- The returned invitation remains one-time at the registry enrollment boundary; the agent signs the invitation with the existing identity proof and Redeem consumes it atomically within the in-memory registry.
- Added tests for unapproved/wrong-key handoff denial, successful approval/enrollment, wrong-key enrollment, replay rejection and expiry.
- `docs/R2F_PAIRING_HANDOFF.md` specifies security assumptions and remaining work.

## Verification
GitHub source committed; **R2F CI result not yet confirmed**. No user manual tests requested.

## Security limitations
The pairing manager is not an authenticated service: its authorization boolean is trusted input, not real user login/role verification. No actual HTTPS invitation transfer, secure OS key vault, durable approval/audit, tenant admin policy, transport binding, rate limits, browser pairing, or capability grants. No public networking, hardware or installer integration. The current setup UI must continue to show NOT_PAIRED until a real authenticated status exists.

## Next
Verify R2F CI; implement separately authenticated tenant-admin decision grants and a confidential authenticated invitation delivery endpoint with abuse resistance, then durable state and a real agent key store. Keep public listeners and physical commands disabled until security review and integration acceptance.
