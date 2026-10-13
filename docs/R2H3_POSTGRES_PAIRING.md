# R2H.3 — PostgreSQL transactional pairing foundation

## Why this phase

R2H.1 and R2H.2 store administrator nonce consumption and pairing decisions in **two independent file journals**. If the process stops between them, authorization can be consumed without recording the decision. That fails closed, but it is not a database transaction.

R2H.3 adds a **separate PostgreSQL-backed path**; it does not silently migrate existing installations or activate a public endpoint. Do not share the old file-journal pairing manager with this new backend.

## Database

Apply `migrations/060_pairing_postgres.sql` to a dedicated PostgreSQL database. Schema includes:
- active/blocked organizations and scoped sites;
- trusted administrator **public keys**, role (OWNER, ADMIN, VIEWER), and revocation;
- scoped pairing proposals, approval and rejection, enrolled identities and revocation;
- hashed, single-use decision nonces and agent challenges;
- separate enrolled-agent registry and pairing audit events.

**No private keys, plaintext enrollment invitations, or device capability grants are stored.**

## Transaction boundaries

`internal/pgpairing.Store.Decide` uses a PostgreSQL `SERIALIZABLE` transaction. It checks the organization's active status, administrator's provisioned Ed25519 public key, active OWNER/ADMIN role and valid signed decision, locks the pairing row, checks the scope and pending/enrolled state, writes the nonce hash with a unique constraint, changes the pairing/agent state, and inserts an audit row **before committing**. Any error rolls all of it back, including the consumed nonce. Duplicate and concurrent approvals cannot both succeed.

`Challenge` stores only a hashed 32-byte unpredictable challenge for an approved request, limited to one currently active challenge per request. `Enroll` locks the pairing and challenge records, verifies a domain-separated Ed25519 signature by the original proposed agent key, consumes the challenge, persists the agent identity, and writes the audit entry in a single database transaction.

`AgentActive` checks that the organization and pairing are active and the agent has not been revoked. A paired agent receives **zero device capabilities** by default.

`Propose` and trusted administrator-key provisioning are **not public HTTP APIs**. Proposal admission must be independently authenticated/rate-limited by a real app. Administrator public keys must be provisioned/revoked through a separately trusted operator/admin workflow, not self-enrolled.

## Verification

Go tests are included for:
- signed administrator role enforcement, blocked cross-tenant actions and duplicate public keys;
- transaction rollback when an audit write is forced to fail, including nonce rollback and valid retry;
- concurrent same-nonce approvals (exactly one winner);
- enrolled identity recovery after a fresh DB connection;
- wrong-key enrollment denial, challenge replay denial, revocation, and audit presence.

`.github/workflows/go-verify.yml` includes a new `postgres-pairing` job with an ephemeral PostgreSQL 16 service. It runs `go test -race -count=1 -v ./internal/pgpairing` against the disposable `localreach_test` DB. The test refuses to truncate other database names. CI's localhost `sslmode=disable` is for its isolated disposable runner **only**; a deployed database requires TLS, least-privilege roles, backups, secret management, monitoring and tested disaster recovery.

The Go module pins `github.com/lib/pq` as the PostgreSQL `database/sql` driver. External modules must be reviewed and upgraded as needed.

## Still required for production

- Real user login/SSO and authoritative, continuously enforced tenant-admin role membership. R2H.3 checks *provisioned signed administrator keys and SQL roles*, not an integrated login/session service.
- Authenticated, abuse-resistant proposal/approval transport; native secure OS private-key vault, installer signing, key rotation and session revocation fanout.
- Online cloud relay / WAN security, multi-region scaling, connection/pool capacity, serialization retry policy, full database migration/recovery plan.
- An actual UI using these transactional states, explicit device capability grants, printer/attendance adapters and hardware acceptance.
- Database audit is transactionally consistent but **not independently immutable** against a database superuser.

This phase is a **transactional prototype with real PostgreSQL tests**, not production readiness and not real hardware access. No public port should be opened for it.

## Next

R2I secure desktop agent identity storage and recovery; subsequent phases integrate authenticated admin login, a real pairing API/UI and separately authorized capabilities. Keep R2H.3 isolated until these gates pass.
