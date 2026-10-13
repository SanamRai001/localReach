# Project state

**Date:** 2026-10-13
**Product:** LocalReach — simple, explicitly authorized outbound access to approved LAN-only devices.
**Active branch:** `feat/r2h3-postgres-transactional-pairing`
**Phase:** R2H.3 — PostgreSQL transactional pairing foundation.
**Base:** `feat/r2h2-durable-pairing-lifecycle` (PR #24). Prior PRs stacked and unmerged; no deployment.

## Verified before this branch

R2H.2 final CI run `38358320876` completed SUCCESS. Earlier Go test/vet/race, local TLS separate-process mock smoke and pairing policy tests passed. No production WAN, installer, device or hardware verification.

## This branch

- Added PostgreSQL migration `migrations/060_pairing_postgres.sql`: organizations/sites, tenant-scoped admin key and role membership, pairing requests, consumed signed nonces, challenge hashes, enrolled agent identities, revocation and audit.
- Implemented `internal/pgpairing` `database/sql` path: authorized, signed, expiring admin decisions and nonce replay guard, pairing state and audit in **one PostgreSQL serializable transaction**. Approval no longer leaves a consumed nonce behind if its pairing/audit write fails.
- Persistent challenge + agent-signed enrollment (same transaction for challenge consumption, agent identity and audit). Revocation updates pairing and agent registry together.
- Real PostgreSQL integration tests cover rollback-injected audit failure, replay, concurrent decisions, scope/RBAC, restarts, enrollment and revocation.
- Added disposable PostgreSQL 16 job to GitHub Actions and pinned PostgreSQL driver dependency.
- `docs/R2H3_POSTGRES_PAIRING.md` documents contracts, test conditions and remaining security work.

## Verification

Code pushed. **R2H.3 GitHub Actions result not yet confirmed** as of this entry. Must verify both regular Go job and PostgreSQL integration job before marking green.

## Scope and blockers

This is an isolated transactional backend, **not yet connected** to a live pairing UI, public server, agent service or device adapter. Bootstrap administrator public keys and role membership are stored in PostgreSQL and validated by signatures; there is **no real login/SSO or continuously synchronized role authority**. Proposals need protected, rate-limited intake. No OS private-key vault, installer signing, real WAN/CGNAT connection, explicit capability grants or hardware acceptance. Production DB TLS/backup/migration/permissions and incident recovery remain outstanding.

## Next

Resolve R2H.3 CI findings. Then develop R2I local OS key storage and safe agent identity recovery; integrate real tenant login, rate-limited pairing UX and capability grants before public/hardware work. Leave all PRs open until explicit merge approval.
