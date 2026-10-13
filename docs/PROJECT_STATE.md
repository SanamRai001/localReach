# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, approve scoped LAN-device access.
**Active branch:** `feat/r2g-pairing-tls-transport`
**Phase:** R2G TLS pairing handler, replay controls and pairing handoff source correction.
**Base:** `feat/r2f-proof-bound-pairing-handoff` PR #21; PRs #1–#21 remain open and unmerged. No deployments.

## Verified baseline
R1L Go test/vet/race/build succeeded; R2A localhost separate-process HTTPS mock smoke run 38351933557 succeeded.

## CI finding
R2F CI run 38354615681 concluded FAILURE at unit/integration tests. R2F handoff source contained literal `\\n` sequences instead of Go newlines. Corrected in this new branch; R2G CI MUST be checked before reporting a passing result.

## Work authored in R2G
- Fixed handoff method malformed source text.
- New `internal/pairtransport` test-only TLS HTTP handler for preprovisioned admin Ed25519 signed decisions, nonce replay rejection, one-use agent challenge and invitation handoff, and key-proof enrollment.
- Bound JSON sizes, disallowed browser origins and plaintext transport.
- Added tests for signing/tenant isolation, replay, incorrect keys and challenge expiry.
- `docs/R2G_TLS_PAIRING.md` records intended trust boundary and limitations.

## Remaining gaps
- HTTP transport does not start a listener; tests use httptest TLS. Pair request creation remains in-process.
- No production login/SSO or durable admin identity, persisted approvals, secure OS key vault, rate limits, audit, multi-node state, channel-bound sessions, signed installers, device grants or discovery.
- R2G CI results not yet confirmed; no real pairing UI, WAN/CGNAT verification or hardware use.
- Earlier static-ID handoff primitive remains unsafe for exposed network use and is not used in new transport.
- All upstream PRs are stacked; main remains unchanged. Do not merge or deploy without approval.

## Next
Confirm R2G CI green, repair failures if necessary, then implement durable/admin-authenticated pairing and secure local agent key storage before integrating Connect UX. Keep physical capability execution disabled.
