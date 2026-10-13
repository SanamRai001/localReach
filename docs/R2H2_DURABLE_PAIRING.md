# R2H.2 — Durable pairing lifecycle (isolated security slice)

## Implemented

`internal/pairledger` is a single-process, bounded (4,096 records / 64 MiB), fsynced append-only journal that persists the complete **non-secret pairing lifecycle**: public-key proposal, approval/rejection, agent enrollment, and revocation. Each event includes its scope and links to the previous event by SHA-256 digest.

Proposed keys are unique within the ledger. Admin approval is accepted only through a caller that has independently established administrator authorization. A short-lived agent enrollment challenge is kept exclusively in memory and requires an Ed25519 signature by the **original proposed key**. A restart invalidates all outstanding challenges but preserves decisions, enrolled agent identity, and revocations. The ledger stores no agent private keys and no invitation tokens.

`internal/pairpolicy.Controller` composes `admintrust.Store` and `pairledger.Store`, using the existing canonical, tenant-scoped signed administrator decision. It validates signed issuance/expiry limits and **consumes and fsyncs the administrator nonce before** writing the pairing decision. This is intentionally fail-closed on interruptions. It is not an atomic transaction spanning two journals.

## Tests

- Request isolation by tenant, authorized approval gate, single proposal per public key.
- Approved pairing state and enrolled ID survive clean restarts.
- Agent signature challenge is one-use, including wrong-key consumption, and challenges are invalid after restart.
- Duplicate enrollment, expired approvals and expired proposals are rejected.
- Revocation survives restart; unauthorized revocation is rejected.
- A second journal writer is denied, corrupted entries or incomplete final records fail closed.
- Concurrent proposals of the same key admit only one winner.
- Persisted administrator decision nonces reject replay after both journals restart; revoked administrator keys fail closed.

The existing `pairing.Manager`, `identity.Registry`, and `pairtransport.NewWithTrust` are **not replaced**. The new ledger and policy compose in-process, with no new HTTP endpoint or background service. The old test pairing transport still exercises in-memory pairing. There is no production-grade cross-process end-to-end integration yet.

## Remaining release blockers

- No authenticated real administrator login, workspace RBAC source, or externally verified tenant membership. `authorized` is trusted input in the isolated ledger API, not an HTTP-supplied decision.
- **Not transactionally atomic across the trust journal and pairing journal.** If a nonce is consumed but the pairing decision fails, manual review or a new signed request is necessary; never undo nonce consumption automatically.
- No OS key vault for agent secrets, resilient distributed database, multi-node replay coordination, complete audit integrity, safe stale lock recovery, journal compaction or audited corruption repair.
- Proposal intake is not protected with production rate limits, persistent admission controls or tenant authorization. Challenge memory capacity is bounded, but denial-of-service protections need review.
- Hash chains are not tamper-proof to someone with filesystem write access.
- No native installer, actual UI pairing, device discovery/capability grants, real WAN/CGNAT testing or public gateway. Never enable real hardware access from this phase.

## Next

R2H.3 should consolidate administrator authentication and pairing/identity state in a single transactional database for real deployment, with dedicated audit and revocation. Then proceed to R2I native agent key storage and R2J real setup flow. Retain the in-process journal only as a bounded prototype/verification baseline.
