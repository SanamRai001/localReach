# Project state

**Date:** 2026-10-13
**Goal:** Secure one-install approved device capabilities over outbound-only connectivity.
**Active branch:** `feat/r1k2-two-process-harness`
**Phase:** R1K.2 independent local gateway and agent processes, code written.
**Baseline:** `feat/r1k-storage-ownership-harness` (PR #13), stacked PRs #1–#12 open, main starter README. No merges/deployments.

## Changes
- Retains prior R0–R1K.1 architecture/UX docs, Ed25519 identity, TLS mock gateway, durable broker, edge journal, outbound agent poller, late-result reconciliation primitive and fail-closed storage ownership sentinel.
- Adds `cmd/localreach-lab` with gateway and agent modes. Gateway binds hardcoded `127.0.0.1:18787` and uses explicitly provided development TLS keypair; agent runs as a distinct OS process, verifies TLS certificate and establishes signed session to poll exactly one mock.ping command.
- Adds `docs/R1K2_LAB.md` with PowerShell runbook, trust prerequisite, expected output and limits.
- Adds .gitignore entry for `.localreach-lab/` credential/journal artifacts.

## Verification
GitHub files published. **No Go test, vet, separate-process command run, real WAN/CGNAT, installer or physical-device test executed.** This is a runnable harness proposal, not a verified test outcome.

## Security and reliability gaps
- Local test gateway only; never make its listener public. Identity is ephemeral and provisioning writes a test private key to disk; unsuitable for production deployment.
- Ownership sentinel can remain after crashes; no automated safe recovery. No database transactions, journal repair, cross-node reliability or signed evidence verification.
- No authenticated user admin enrollment, durable scope policy, channel-bound sessions, rate limits, certificate management, OS secure key store or production agent daemon.
- No one-click installer/UX, real discovery or printer/attendance integration.
- Restarting gateway with same directory fails on duplicated fixed command ID; lab reset procedures are not automatic.

## Next phase
Run consolidated Go test/vet acceptance plus local two-process lab after security review. Fix discovered defects before expanding to WAN or real devices. Then prioritize first safe onboarding and installer UX prototype.
