# R2J.4A — OS-protected administrator approvals and shared admission

This branch improves the operator-controlled pairing workflow but **does not** turn the loopback-only control plane into a public gateway. There is still no remote WAN service, persistent cloud command session, device driver, or device capability grant.

## Native administrator approval

`cmd/localreach-admin` supports the following **manual, operator-only** commands:

```sh
# Use an identity directory SEPARATE from LocalReach agent keys.
# Generating a public key does not provision an administrator in the organization.
go run ./cmd/localreach-admin init -identity-dir /SECURE/SEPARATE/ADMIN_DIR

# A trusted operator must provision the printed public key to the correct
# organization and OWNER/ADMIN role in the existing PostgreSQL identity store.
go run ./cmd/localreach-admin invite -identity-dir /SECURE/SEPARATE/ADMIN_DIR \
  -gateway https://TRUSTED_TLS_GATEWAY -organization ORG \
  -admin ADMIN_ID -site SITE

# Transfer the invitation token privately to the intended agent owner.
# The agent uses 'localreach-agent request' (stdin token) to create PENDING.
go run ./cmd/localreach-admin review -identity-dir /SECURE/SEPARATE/ADMIN_DIR \
  -gateway https://TRUSTED_TLS_GATEWAY -organization ORG \
  -admin ADMIN_ID -request REQUEST_ID

# Compare the agent's full SHA-256 public-key fingerprint OUT OF BAND.
# Approval requires the operator to retype the exact 64-character fingerprint.
go run ./cmd/localreach-admin approve -identity-dir /SECURE/SEPARATE/ADMIN_DIR \
  -gateway https://TRUSTED_TLS_GATEWAY -organization ORG \
  -admin ADMIN_ID -request REQUEST_ID
```

The native admin key is stored by existing OS-native secret stores: Windows user DPAPI, macOS Keychain, or Linux desktop Secret Service. The CLI requires an explicitly separate identity directory, refuses the default agent identity directory, does not silently create credentials, and uses TLS certificate verification.

Admin login signs the pre-existing tenant-scoped Ed25519 challenge; the server issues a five-minute session held only in process memory. Issuing an invitation requires a live OWNER/ADMIN role. Review returns only request state, site, expiry and SHA-256 fingerprint. Approval **re-fetches** the request, checks PENDING and unexpired state plus the exact operator-confirmed fingerprint, then signs a fresh nonce-bound, short-lived `pgpairing.AdminDecision`. The backend validates the administrator session/role and signature independently, with transactional replay protection.

**A signed approval still does not give the agent device permissions or create an ONLINE session.** Operator fingerprint comparison is essential; a local CLI cannot independently prove who physically owns a proposed public key. Key provisioning, admin authorization and out-of-band trust remain operator responsibilities, not consumer sign-up.

## Shared admission control

Migration `064_shared_admission.sql` adds `lr_admission_windows` with a per-action/peer unique key. The PostgreSQL `INSERT .. ON CONFLICT DO UPDATE .. WHERE` statement limits each peer and API path to five accepted calls in a rolling *fixed one-minute window* and shares enforcement across multiple server processes with the same database. A rejected attempt does not change the count; an expired window resets on the next request. Malformed direct peer IP or database errors fail closed. All pairing endpoints, including enrollment/resume and admin approvals, are covered when `Handler.Admission` is configured.

The `cmd/localreach-control` process now uses this database-backed admission control by default, with the legacy in-memory limiter retained as a fallback for older isolated handler tests. No client-supplied `X-Forwarded-For` is trusted.

**This is NOT a public Internet abuse-control solution.** All clients behind one reverse proxy may be counted as a single peer, attacker IP changes can bypass per-peer limits, and the table needs bounded retention/cleanup, distributed monitoring, trusted reverse-proxy configuration, connection quotas, request concurrency limits, and account/device-oriented abuse controls. Sharing the limiter requires a reachable PostgreSQL database; any outage denies requests rather than silently bypassing the gate.

## Verification

- Disposable PostgreSQL tests confirm shared admission counts persist across separate DB connections, limits do not reset when another process starts, route/peer isolation, expiry, and invalid peers.
- TLS integration proves administrator key login, invitation issuance, native one-use redemption, fingerprint review, denial on wrong fingerprints, separately signed approval, and agent enrollment.
- CLI tests confirm no implicit key creation and no reuse of the agent default identity directory.
- Linux, Windows and macOS GitHub Actions jobs compile the native admin CLI and retain earlier OS key-vault and pairing checks.

## Remaining milestones

**R2J.4B**: production-facing human administrator identity/SSO provisioning, trusted consent UX, audited key-management lifecycle, hardened externally reachable gateway with certificates, throttling, monitoring, and operator deployment instructions. Real cross-network/CGNAT verification must follow. **R2K**: separately approved device capability grants and *read-only* discovery; printer/attendance writes require independent authorization and hardware acceptance. The current system has no such permissions.

No deployment, merge, proxy exposure, hardware access or device control is authorized by this branch.
