# R2H — Durable administrator trust and replay ledger

## Scope delivered

This is the **first R2H security slice**, not complete durable pairing.

- `internal/admintrust.Store` persists tenant-scoped Ed25519 **public** keys, trusted provisioning, revocations, and hashes of consumed administrator decision nonces in an append-only, fsynced JSONL journal.
- Replay validates every event and its SHA-256 hash chain, rejects invalid transitions or partial trailing records, and fails closed. The store uses the existing exclusive ownership sentinel (not a robust crash-recoverable OS lock). Journal growth is capped at 64 MiB; there is no compaction or automatic repair.
- `pairtransport.NewWithTrust` verifies a signature from the provisioned tenant/key ID against a canonical signed decision, with timestamps: issued no more than 120 seconds ago, no more than 30 seconds in the future, and expires within two minutes of issue. On success, the nonce is **durably consumed before** the in-memory pairing manager is asked to approve the request.
- A key can be revoked by a trusted in-process operator, after which new decisions fail closed, including after reopening the journal.
- Tests cover reopening/replay, simultaneous same-nonce use, revocation, corruption, cross-tenant rejection, signature failure, and real httptest HTTPS requests across transport handler restart.

## Strong constraints and remaining risks

**Do not expose this service publicly or use it to authorize hardware yet.** Admin provisioning and revocation are trusted in-process calls, **not protected HTTP admin APIs**. Public-key identity is not the same as verified organization administrator membership or a secure login session.

The legacy `pairtransport.New` still exists for old in-memory tests; use `NewWithTrust` for new durable-admin experiments only. The persistent audit is a hash chain, **not a tamper-proof or signed immutable log**: an attacker with filesystem write access could rewrite the chain; independent signed/off-site checkpoints or database auditing are still needed.

The pairing manager, invitation storage, agent registry, and agent status still live in memory. After a crash, nonce consumption survives but an approved pairing may be lost. That is intentionally **fail closed**, not end-to-end persistence. Audit and scope controls do not replace durable state, authorization checks, rate limits, OS private-key protection, request throttling, operator key rotation, safe ownership recovery, or shared database transactions.

The store writes only public keys, hashed nonces, timestamps and scope identifiers. No private keys or invitation tokens are persisted. A stale ownership sentinel requires manual inspection. An interrupted trailing write fails closed and needs an audited repair process; never silently truncate.

## Verification gate

Run CI on this stacked PR: `go test -count=1 ./...`, `go vet ./...`, `go test -race -count=1 ./...`, and the separate-process mock TLS lab smoke test. A passing CI run still does not establish reliable WAN access, secure local installation, real device authorization, or production readiness.

## Next

R2H.2: persist the pairing request state and associated agent enrollment transaction using a real transactional store and auditable admin identity. Then R2I: platform-specific secure agent private-key storage, rotation, revocation, and identity recovery. Only then connect the real onboarding flow.
