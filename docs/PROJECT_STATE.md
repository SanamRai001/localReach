# Project state

**Date:** 2026-10-13
**Goal:** One-install, simple and secure access to explicitly approved LAN device capabilities.
**Active branch:** `feat/r1k-storage-ownership-harness`
**Phase:** R1K.1 storage ownership gate (code written, tests not run).
**Base:** `feat/r1j-reconciliation-hardening` (open PR #12), dependent on previous stacked PRs #1–#11. Main remains starter README, no merges/deployments.

## Changes
- Existing R0–R1J: product/UX RFC, identity and signed challenges, TLS mock handler, single-writer broker and journal, mock outbound HTTPS delivery, reconnect polling, late-result reconciliation primitive.
- R1K.1: `internal/ownership` creates an exclusive .owner sentinel with OS O_EXCL semantics. Journal and broker obtain it before opening storage, release it on clean close or open failure, and deny second writers.
- Added unit/integration tests for double-open and clean reopen.
- Added `docs/R1K_STORAGE_OWNERSHIP.md` with operational risks and next steps.

## Verification
GitHub files published. No `go test ./...`, `go vet ./...`, race, process, WAN/CGNAT, installer, UX or hardware tests executed. Actual behavior is unverified.

## Risks
Sentinels are not robust OS locks; crashed writers leave stale files, and manual deletion while a writer is alive breaks exclusivity. No automated stale recovery or repair. Existing fsynced event logs can fail closed on partial writes; no compaction or backup. This is still an in-process/httptest mock platform, not separately deployable secure networking. Identity persistence, admin auth, TLS channel binding, rate limiting, release signing, UX and actual discovery all remain incomplete.

## Next phase
R1K.2 standalone gateway and agent local-process harness, explicit mock-only TLS trust and consolidated Go acceptance. Then build the first usable one-click installation prototype after security and network gates. Preserve the stacked PRs pending explicit merge authorization.
