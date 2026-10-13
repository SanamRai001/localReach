# Project state

**Date:** 2026-10-13
**Goal:** LocalReach — simple, outbound-only and narrowly authorized LAN device sharing.
**Branch:** `feat/r2k1-device-discovery-read-grants`
**Phase:** R2K.1 — independently approved discovery-only permission ledger plus passive local printer mDNS observation.
**Base:** `test/r2j6-separate-process-tls-acceptance` (PR #35). Prior 35 PRs remain stacked/open; no main merge or deployment.

## Verified preceding foundation
R2J.6A final GitHub CI `38387888892` SUCCESS: Linux Go/race, PostgreSQL signed sessions, real TLS control-plane process crash/lease recovery and revocation, Windows DPAPI, macOS Keychain. The separate-process test is on one VM; real cross-network R2J.6B acceptance remains unperformed.

## R2K.1 code authored
- Migration `066_device_read_grants.sql` adds one-hour, tenant/site/agent/device/capability-scoped, ACTIVE/REVOKED policies, nonce replay ledger and transactional audit. Only `PRINTER_DISCOVERY_READ` and `ATTENDANCE_DISCOVERY_READ` policy labels exist. They grant NO hardware operations.
- `internal/pgcapability`: separate Ed25519-signed grant/revoke decision domain. Must be preprovisioned live OWNER/ADMIN, independently signed, same enrolled active agent/site, unique nonce. Deny by default. Expiry, revoked organization/admin/agent/pairing, tenant/site/device/capability mismatch all deny.
- `internal/pairapi` admin-only `/v1/control/device-read-decision` route requires tenant OWNER/ADMIN bearer with exact matching signed admin ID and a separate device grant signature. Always responds `deviceOperations=DISABLED`.
- Native `internal/adminremote` and `cmd/localreach-admin grant-read|revoke-read` sign decisions with the separate OS-protected admin key. Operator must type exact full discovery fingerprint; no auto-grant after pairing.
- `internal/landiscovery` observes unsolicited mDNS SRV printer advertisements with **no packets sent or device connected to**; strict bounded parser; candidate SHA256 fingerprints are UNTRUSTED DNS-SD hints, not hardware identity. Attendance reader discovery not implemented.
- `cmd/localreach-agent discover -duration 5s` performs an explicitly requested 1–30 second, max-20-item, passive local-only observation. No pairing credentials, cloud uploads or device commands.
- Tests: malformed/spoofable mDNS handling, strict listen duration, real PostgreSQL signatures/expiry/replay/cross-tenant/agent/admin revocation, native HTTPS signed grant/revoke and no implicit device capability.
- `docs/R2K1_DISCOVERY_READ_GRANTS.md` details security boundaries.

## Verification
R2K.1 committed; **new branch CI pending**. Must verify Linux tests/vet/race, serial disposable PostgreSQL pairing/auth/device-grant/TLS acceptance, Windows native DPAPI builds, macOS Keychain builds. This is policy and passive discovery, NOT usable hardware access.

## Blockers
No actual WAN two-network R2J.6B pilot, public deployment, production SSO/abuse protection, signed installer or native background service, secure hardware identity binding, validated active printer discovery, attendance protocols, per-operation grant enforcement, real LAN/device commands or hardware acceptance. Streaming agent presence still explicitly transmits `capabilities=NONE`. It cannot print, read attendance records or proxy arbitrary TCP.

## Next
CI first. R2K.2 scoped, vetted opt-in device discovery and authenticated local policy enforcement with manual hardware pilot; R2J.6B actual two-network staging acceptance separately. Main merges/deployments require user permission.
