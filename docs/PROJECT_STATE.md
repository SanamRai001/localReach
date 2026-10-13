# Project state

**Date:** 2026-10-13
**Goal:** Secure device capabilities with install-once, one-click operator UX.
**Current branch:** `feat/r1c-session-handshake`
**Phase:** R1C.1 identity session primitives committed, not integrated.
**Branch chain:** `main` (README) <- `docs/foundation-rfc` (PR #1) <- `feat/r1a-command-prototype` (PR #2) <- `feat/r1b-agent-identity` (PR #3) <- this branch.

## Work completed
- R0 proposed UX, architecture RFC, security requirements, roadmap.
- R1A Go localhost-only mock relay/agent and simple command lifecycle.
- R1B short-lived one-time tenant/site invitation and Ed25519 proof-of-possession.
- R1C.1 single-use expiring session challenges, opaque hashed ephemeral session tokens, replay rejection, revocation checked on each authorization, bounded in-memory state and tests.

## Verification
- GitHub source and docs committed; PR publication pending at last update.
- Go tests **not run**; user requested batching local verification later.
- No real network, TLS, OS installer, device discovery, physical hardware or usability verification.

## Security limitations / risks
- R1A shared-token HTTP relay remains loopback only and must not be exposed.
- R1B/R1C are independent in-memory packages, NOT connected to HTTP transport.
- Session tokens are bearer credentials not yet channel-bound or backed by durable revocation.
- No transactional persistent enrollment, authenticated administrator route, nonce rate limiting, distributed challenge state, secure key storage or authenticated TLS.
- No command journal/leases; non-idempotent physical effects not safe.
- `Begin` is intentionally a primitive and must be wrapped with rate limits and secure transport before public use.

## Next phase
R1C.2: authenticated encrypted gateway and edge connection using these primitives, denial-by-default network exposure, tightly scoped mock operation, and failure tests. Do not claim one-click or WAN compatibility until the installer and two-network test succeed. Batch substantial local acceptance rather than requiring user action after each commit.
