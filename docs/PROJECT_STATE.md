# Project state

**Date:** 2026-10-13
**Product:** LocalReach — easy, outbound-only, tightly authorized LAN device access without device-side router configuration.
**Branch:** `feat/r2j5-authenticated-outbound-session`
**Phase:** R2J.5 — signed agent long-lived outbound HTTPS presence, heartbeat and revocation.
**Base:** `feat/r2j4b-restricted-staging-gateway` (PR #33). All preceding PRs are open and stacked. No merge or deployment.

## Verified baseline
R2J.4B final CI run `38380986752` succeeded across Linux Go/vet/race and local HTTPS, PostgreSQL tests, Windows native DPAPI and macOS native Keychain, including the restricted staging allowlist/TLS checks. No actual remote-Wi-Fi pilot or public deployment.

## This branch
- Migration `065_agent_connections.sql`: one active per-org/per-agent random session ID and 15s lease, heartbeat freshness, and scoped OPEN/CLOSE audit.
- `pgpairing.OpenConnection`, `RenewConnection`, `CloseConnection`, `ConnectionOnline`: transactional lease ownership, expiry and reclaims. Renewal checks agent revocation, pairing and organization status before every live heartbeat. No device permissions or commands.
- `pairapi.POST /v1/agent/session`: a fresh, one-use signed Ed25519 resume proof **on the same TLS request** opens a long-lived NDJSON stream of `connected`, `heartbeat`, `closed` frames; each has `capabilities=NONE`. Existing native-origin, JSON limits and PostgreSQL admission apply.
- `agentremote.Client.StreamSession`: existing OS-protected signing key and authenticated HTTPS only. Strict stream-frame validation, no redirect, bounded frames, 12s stall watchdog, on-disconnect offline callback.
- `agentservice.LiveMonitor`: ONLINE derives only from a fresh authenticated frame on a live stream, OFFLINE on stream loss/staleness; bounded reconnect/backoff and cancellation.
- Native `localreach-agent serve` runs the stream monitor; the read-only loopback status/UI distinguishes genuine ONLINE session from identity-only verification and always reports no discovered/authorized devices.
- Real PostgreSQL tests cover single-owner lease, another database connection, expiry/reclaim, incorrect session ID, revocation, and a live TLS stream closing after administrator revocation. Local monitor tests cover genuine frame presence, stale/failed state and shutdown.
- `docs/R2J5_OUTBOUND_SESSIONS.md` documents protocol, timing, operator constraints and readiness blockers.

## Verification
R2J.5 code authored. **Final branch CI not yet confirmed.** Must check Linux Go/vet/race, real PostgreSQL stream/lease tests, Windows native DPAPI and full packages, macOS native Keychain/full packages before treating the phase as verified.

## Important limits
This is a **read-only persistent presence session**. No printer/attendance device commands, generic reverse proxy, TCP forwarding, terminal, LAN discovery or device capability grants are available. No production public gateway or actual WAN pilot was executed. The restricted staging listener still requires operator-controlled DNS/TLS/source-IP firewall and only supports a tiny maximum of 16 concurrent routed requests. Crash cleanup waits for the 15s lease timeout; status is not security authorization. Signed installers, true user SSO, revocation fanout, multi-region streaming scale, production abuse protection and hardware acceptance remain unfinished.

## Next
CI first. Then R2J.6 real approved cross-network acceptance, R2K explicit capability grants and read-only discovery. Main merge and deployment require explicit approval.
