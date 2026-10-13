# Project state

**Date:** 2026-10-13
**Goal:** Secure one-install access to narrowly approved LAN-device operations.
**Active branch:** `test/r1l-consolidated-acceptance`
**Phase:** R1L Go verification automation and acceptance checkpoint.
**Base:** `feat/r1k2-two-process-harness` (PR #14); PRs #1–#14 remain stacked and unmerged.

## Added in R1L
- `.github/workflows/go-verify.yml`: on pull requests and selected pushes, run Go package tests, Go vet, race detector and compile the two-process lab using Ubuntu GitHub Actions.
- Verification jobs provide a durable pass/fail gate; source publication alone does not indicate passing tests.

## Earlier changes
Architecture/UX spec; mock relay; Ed25519 identity; short-lived signed sessions; TLS test-only gateway; durable broker and edge journals; authenticated outbound mock command polling; replay, recovery and reconciliation logic; exclusive ownership sentinels; loopback gateway/agent two-process lab.

## Verification status
**UNKNOWN / NOT VERIFIED:** GitHub Actions execution and test outcomes have not yet been confirmed. A local git network checkout attempt failed because github.com could not be resolved, and the prior phases have not been runtime-tested in this environment. No two-process lab, WAN, real printer, attendance device, or installer usability gate executed.

## Risks / limitations
- Current lab is loopback only; test-only credentials and in-memory registry.
- Gateway is not appropriate for public deployment; lacks full admin policy authorization, durable enrollment, bound sessions, rate limits and secure agent key storage.
- Journal ownership sentinel lacks safe automated stale recovery; append journals lack repair/compaction.
- Independent signed edge evidence and general safe reconciliation remain incomplete; no physical command allowed.
- Missing one-click installer/discovery, real WAN/CGNAT verification and device adapters.

## Next
Read the actual GitHub Actions result, fix failures before progressing, then run the local two-process lab through a reproducible acceptance gate. Keep all PRs unmerged pending approval and do not expose the gateway.
