# Project state

**Date:** 2026-10-13
**Goal:** Install once, securely access explicitly approved LAN-device capabilities.
**Branch:** `feat/r1i-reconciliation-runner`
**Current phase:** R1I mock recovery and outbound polling supervisor authored.
**Baseline:** `feat/r1h-outbound-mock-transport` (PR #10), stacked on PRs #1–#9. Main remains starter README. No merges/deployments.

## Changes
- R0–R1H: UX/architecture documentation, mock relay, agent identity and TLS tests, scoped broker, local journal and outbound HTTPS mock transport.
- R1I: repeated claims inspect existing edge journal. Known final results are reported without executing twice; nonterminal previous intent becomes cloud INDETERMINATE instead of a physical retry.
- Added cancellable polling Runner with bounded exponential backoff and jitter.
- Updated tests for final-result reconciliation, uncertain prior intent, and cancellation. Added `docs/R1I_RECOVERY.md`.

## Verification
GitHub files published; **Go tests, vet, race tests, fault injection and hardware/network testing have not run**. User requests batch manual verification after a complete useful milestone.

## Risks
- The cloud may already have a terminal INDETERMINATE result and cannot yet reconcile it from a later edge success.
- No production agent service or public WAN listener, trusted enrollment API, agent OS key storage, channel-bound sessions, rate limits, audit records or real tenant admin grants.
- Per-process registries and single-writer journals are prototypes; no cross-process locking, partial-write repair or durable transactional command coordination.
- No tested CGNAT, OS installer, printer, attendance terminal or UI. Mock operation only.

## Next phase
R1J: resolve broker/edge terminal reconciliation with signed scoped evidence, persistence safety and testable two-process harness. Hold public access until security design gates and batched acceptance pass. Preserve all open PRs pending explicit merge approval.
