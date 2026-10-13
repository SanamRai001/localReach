# Project state

**Date:** 2026-10-13
**Project goal:** One-install, low-friction, securely scoped LAN-device capabilities.
**Current branch:** `feat/r1e-mock-integration`
**Phase:** R1E local authenticated mock integration authored; acceptance deferred.

## Baseline and branches
`main` contains the starter README only. Pending dependent PRs: #1 docs, #2 R1A localhost relay, #3 R1B identity, #4 R1C sessions, #5 R1C.2 TLS handler, #6 R1D journal; this branch is based on `feat/r1d-durable-command-journal`. Nothing merged or deployed.

## Changes
- R0 documentation covers product, capability-first architecture, UX and research.
- R1A isolated loopback mock relay; R1B Ed25519 enrollment; R1C signed sessions; R1C.2 TLS-only gateway handshake and heartbeat.
- R1D bounded fsynced single-writer journal, with interrupted execution quarantined as INDETERMINATE.
- R1E `internal/integration`: client combines TLS signed handshake, scoped heartbeat and locally executed `mock.ping` protected by the journal. Tests cover TLS success, duplicate ID, crash quarantine, revoked agent, plaintext guard and wrong key. See `docs/R1E_INTEGRATION_BOUNDARY.md`.

## Verification
GitHub files created and retrieved in development; **Go tests and vet not executed**. No external network, GUI, installer, hardware or user study validation. User requests batched acceptance checks later; no claim of successful runtime integration.

## Risks and constraints
This is **not remote command delivery**: mock execution originates on the local client, not a cloud broker. No safe internet-exposed listener, transport session channel binding, admin authentication, persistent registries, rate limiting, durable cloud queue or real device adapter. Agent journal assumes a single writer, no OS file lock or compaction, and fail-closed handling for partial writes. R1A development bearer token is loopback-only. Do not expose these prototypes to the internet.

## Next phase
Design a small durable mock command broker with separate accepted/delivered/executed states, command lease expiry and reconciliation; only then connect an outbound agent channel. Preserve typed allowlisted capabilities and crash-safe semantics. Before public connectivity, finish tenant/app auth, channel-bound identity, key storage, replay controls, rate limiting and security tests. R2 remains the one-click UX/installer milestone.
