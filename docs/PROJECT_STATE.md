# Project state

**Date:** 2026-10-13
**Goal:** Secure one-install, one-click connectivity for LAN-only device capabilities.
**Active branch:** `feat/r1d-durable-command-journal`
**Phase:** R1D edge command journal prototype; implementation committed, pending verification.
**Base:** `feat/r1c2-tls-gateway-spike` (PR #5), based on PRs #1–#4. Main unchanged beyond initial README.

## Changes
- R0 documented product, architecture, UX, security and roadmap.
- R1A localhost mock agent/relay.
- R1B Ed25519 invitation enrollment; R1C signed session challenges and isolated TLS-only handler.
- R1D new `internal/journal`: bounded fsynced append-only command events, duplicate-ID rejection, explicit state transitions, startup recovery marking interrupted EXECUTING as INDETERMINATE, corruption fails closed.
- Added tests for restart recovery, invalid transition, journal corruption and capacity, and design/limitation guide in `docs/R1D_COMMAND_JOURNAL.md`.

## Verification
- GitHub writes completed; Go tests, vet and crash injection **not yet run**.
- User prefers batching verification after implementation milestones.
- No WAN, physical printer, attendance terminal, installer or browser UX test executed.

## Risks
- Journal is an isolated single-writer spike: no file lock, compaction, encryption, repair path, distributed acknowledgements or production coordination.
- Disk-full/partial writes fail closed; bounded journal needs deliberate maintenance.
- Original mock relay remains loopback-only and shares a development token.
- R1B/R1C identity modules remain unintegrated with R1A command route; no internet-ready security, admin-authenticated enrollment or durable control-plane database.
- All dependency PRs remain open; no merges or deployment.

## Next phase
Define typed capability manifests and safe retry classes; durable cloud-side command protocol and mock-only end-to-end integration with identity/TLS. Before any public exposure or hardware use, implement OS-key storage, admin authorization, session channel binding, rate limiting and recoverable journal operations. Maintain user-facing one-click UX as the governing acceptance criterion.
