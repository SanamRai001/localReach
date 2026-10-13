# Project state

**Date:** 2026-10-13
**Goal:** One-install, minimal-click, securely scoped access to local device capabilities.
**Active branch:** `feat/r1b-agent-identity`
**Baseline:** `feat/r1a-command-prototype`; dependent documentation PR #1 and implementation PR #2 are open. Main has starter README only.
**Current phase:** R1B identity spike written; not integrated into an internet-facing transport.

## Implemented
- R0 proposed product vision, UX, architecture, security, research and roadmap.
- R1A localhost-only Go mock relay/agent, typed mock command, in-memory state, httptest example.
- R1B `internal/identity`: one-time short-TTL scope-bound invitation, token hashing, Ed25519 proof-of-possession, unique pubkey binding, in-memory revocation, unit test cases for expiry, replay redemption, wrong key, concurrency and defensive copies.
- R1B threat-boundary notes at `docs/R1B_IDENTITY_SPIKE.md`.

## Verification
- GitHub files pushed; test suite **not executed** by GitHub connector and **not reported as passing**.
- User prefers batching local/manual verification until meaningful integration milestones.
- No external network proof, production enrollment, installer, discovery, tenant integration, or hardware verification.

## Risks / blockers
- R1A remains loopback-only and authenticated by shared development token; **never expose its HTTP listener to the internet**.
- R1B is an isolated in-memory identity primitive; no admin authorization, persistence, TLS, secure agent key storage, challenge replay tracking, certificate identity binding, or active-session revocation.
- Agent commands have no durable journal/lease model; crash boundaries unsafe for physical effects.
- Dependency PRs #1 and #2 are still open; do not merge without approval.
- Current UI does not exist. One-click UX remains the product target, not proven behavior.

## Next implementation slice
R1C: independently authenticated TLS outbound transport with persisted transactional enrollment and strict session binding; preserve mock-only capability and bounded queues. Add security and recovery tests before any public bind or real hardware. Reserve longer manual verification for a cohesive end-to-end test gate. Maintain `docs/PROJECT_STATE.md` only as the phase record.
