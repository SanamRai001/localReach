# Project state

**Date:** 2026-10-13
**Goal:** Secure, simple one-install connectivity for LAN-only device capabilities.
**Current branch:** `feat/r1c2-tls-gateway-spike`
**Phase:** R1C.2 — protected TLS transport boundary proof (code committed, unverified).

## Actual baseline
Dependent branch chain: `main` (starter README) -> `docs/foundation-rfc` (PR #1) -> `feat/r1a-command-prototype` (PR #2) -> `feat/r1b-agent-identity` (PR #3) -> `feat/r1c-session-handshake` (PR #4) -> current branch. No merges or deployments performed.

## Changes
- R0: vision, architecture RFC, user-first setup UX, security baseline and roadmap.
- R1A: loopback-only Go mock relay/agent and mock.ping lifecycle with local tests authored.
- R1B: Ed25519 agent enrollment with short-lived single-use tenant/site invitation model.
- R1C.1: signed, single-use expiring handshake challenges, short-lived hashed session tokens, per-operation revocation checks.
- R1C.2: TLS-only HTTP handler for challenge/session/heartbeat, rejecting plaintext, with tests for TLS handshake, replay and revocation. No public listener or integration with existing mock relay.

## Verification
GitHub writes completed; automated Go tests, vet, race tests, cross-network, installer, hardware and UX tests **not executed**. User has asked to batch manual testing for a larger acceptance gate.

## Security / design risks
- No admin authorization, durable storage, credential handling, request rate limits, channel-bound sessions, persistent outbound transport, reliable command journal or distributed revocation.
- The original R1A shared-token mock relay is still localhost-only. Do not expose it or the new handler publicly.
- No physical-device execution, signed installers, discovery or user console yet.
- Sessions and challenges are per-process ephemeral, not suitable for multi-instance deployment.
- Command outcome semantics for irreversible printing are unproven.

## Next phase
Design and implement a durable, per-device command journal and explicit retry semantics before live commands. In parallel, specify a properly authenticated admin-authorized enrollment and TLS identity trust model. Only then integrate an outbound gateway in a restricted cross-network test. Batch meaningful local verification before merge/release.
