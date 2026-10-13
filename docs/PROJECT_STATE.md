# Project state

**Date:** 2026-10-13
**Product:** LocalReach — outbound-only, strictly authorized access to narrow LAN device capabilities.
**Branch:** `feat/r2j4-admin-approval-distributed-admission`
**Phase:** R2J.4A — native administrator workflow plus shared PostgreSQL admission.
**Base:** `feat/r2j3-invitation-control-plane` (PR #31). Prior 31 PRs remain open and stacked; main unchanged, no deployment.

## Last verified baseline
R2J.3 latest CI run `38377092425` SUCCESS for all four Linux/PostgreSQL/Windows/macOS jobs: signed admin login, one-time invitation, fingerprint review, separate signed approval, native identity enrollment, OS-secured signing, and loopback TLS tests.

## R2J.4A implementation
- `internal/adminremote` native-only administrator TLS client: preprovisioned key signs login challenge, administrator can issue one-time invitation and read non-secret fingerprint review, and approve only after a provided full fingerprint is checked again against the server and a separately signed short-lived decision is accepted.
- `cmd/localreach-admin`: explicit separately scoped OS-native administrator signing key directory, `init`, `invite`, `review`, `approve`. Approve prompts for an exact out-of-band fingerprint confirmation. No browser private keys, password, or automatic provisioning.
- `migrations/064_shared_admission.sql` and `internal/pairapi.SQLAdmission`: PostgreSQL-backed transactional per-peer/route fixed-window five-per-minute admission across server processes, fail-closed on DB errors. Does not trust forwarded headers.
- `cmd/localreach-control` now configures database-backed admission for **all** native API paths, not just login/invitation. It remains fixed to loopback 127.0.0.1:19443 with TLS and explicit DB configuration.
- Added native CLI tests, shared admission PostgreSQL tests, administrator signed-login/invite/fingerprint approval integration, and three-OS binary compilation.
- `docs/R2J4A_ADMIN_AND_ADMISSION.md` describes manual operation and remaining release blockers.

## Verification
R2J.4A source committed; **new phase CI pending**. Must verify Linux Go/vet/race, disposable PostgreSQL including cross-process admission and admin workflow, Windows DPAPI/full builds, and macOS Keychain/full builds before accepting.

## Security boundaries and blockers
Shared admission is a prototype, NOT an Internet-ready distributed WAF. No trusted reverse proxy/client IP policy, bounded purge/monitoring, authoritative human SSO or admin key provisioning UI, secure key rotation, signed installer or native background agent, actual public gateway, outbound persistent command session, device grants/discovery or hardware usage. Loopback prototype cannot serve a remote agent. No printer, attendance, arbitrary tunnel, shell or TCP-forward features.

## Next
Pass CI and fix findings. Then R2J.4B reviewed human admin identity + secure, externally reachable staging control-plane with comprehensive abuse defenses; R2K separately approved device grants. Do not deploy or merge without explicit user instruction.
