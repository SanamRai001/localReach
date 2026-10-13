# R2I.3 — Native agent signing identity bound to database pairing

## Implemented boundary

This phase introduces a **backend-only agent identity coordinator**, not an installed agent or an Internet-facing pairing API.

`internal/agentlifecycle.Coordinator` accepts a `Signer` implemented by `*agentkeys.Identity` from Windows DPAPI, macOS Keychain, or Linux Secret Service. The native private key stays within the OS-protected Go agent process. The coordinator has three independent operations:

1. **RequestPairing** — submits only the native agent's public key into the server-side `pgpairing.Propose` operation. It is **not approval**. A future authenticated, rate-limited intake service must authorize this operation. Native key creation is a separate explicit user action (`agentkeys.Store.Create`); the coordinator never calls Create.
2. **FinishPairing** — after independent tenant administrator approval has moved the request to APPROVED, obtains a 30-second single-use challenge from the server, signs the domain-separated `pgpairing.EnrollmentMessage` inside the native signer, and submits the signature to transactional PostgreSQL enrollment. Wrong key, expired request, revoked organization, wrong scope and challenge replay fail closed.
3. **VerifySavedIdentity** — **only after an existing native identity is loaded** with `Store.Load`, resolves an enrolled agent ID by its public key (private internal lookup), obtains a fresh challenge, signs `pgpairing.ResumeMessage` (organization + agent ID + nonce), and atomically verifies it against the persisted, unrevoked agent signing key.

Migration `062_agent_resume.sql` adds bounded-time, single-use hashed resume challenges and a transactional resume-verification audit. Resume verification checks organization and pairing status again inside the database transaction. It produces an agent ID upon proof but **does not open an authenticated command session, mark the agent online, or grant device permissions**. Do not expose `ResolveIdentity`, `BeginResume`, or `VerifyResume` directly without authenticated and abuse-controlled transport.

## Lost keys, recovery and rotation policy

- **Restart:** Load the existing OS-protected private key, then prove it via a new server challenge. No new identity is generated.
- **Native credential store unavailable / corrupted:** fail closed. Never auto-generate a new Ed25519 key, swap a marker, or silently substitute an alternate plaintext store.
- **Revoked identity:** cannot resolve or resume even if the same private key is still on the machine. Database organization BLOCKED also prevents identity recovery.
- **Lost key / intentional replacement:** require administrator-authorized revocation of the old pairing, an **explicitly user-consented** new native key lifecycle, and a fresh request/approval for the replacement key. A replacement agent gets a new ID, no inherited capabilities or trust. The UI to perform safe backup/retirement/reset is **not implemented yet**; there is no automatic identity deletion or key rotation in this phase.

Never delete a damaged or lost key store automatically: it may have a recoverable backup, and deleting it before revoking an old pairing can break incident response. Production rotation must also invalidate active sessions, audit old/new identities, and require independent admin approval.

## Verification

- Go unit tests use a test signer to verify coordinator proof messages, approval gating, wrong-key denial and revoked recovery.
- PostgreSQL integration tests apply migrations 060 and 062 to disposable `localreach_test`, verifying enrollment/identity resolution after a new database connection, proof reuse denial, wrong/cross-tenant key denial, expiration, blocked organization and signed revocation.
- Coordinator integration test composes native Signer interface, the actual PostgreSQL backend and signed administrator approval, then proves that a restarted coordinator recovers only the original key and a replacement key remains pending/untrusted.
- CI's real PostgreSQL job includes `internal/pgpairing`, `internal/pgauth`, and `internal/agentlifecycle` with `-p 1`, avoiding simultaneous destructive test setup.

These tests verify the **contract** and database state, not a running desktop agent performing real TLS requests. Windows/macOS/Linux native storage is separately exercised by previous platform-specific tests; optional tests with an unlocked native desktop credential manager remain outstanding. No installed service, actual gateway session, hardware, cloud relay, or WAN/CGNAT verification.

## Next phases

R2I.4 / R2J integration: move the coordinator across an authenticated, encrypted network transport without delivering database credentials to native clients; preserve one-use challenges, replay resistance and organization RBAC, with explicit denial/rate limits. Couple verified identity to scoped **separately authorized** command sessions and local status, then implement the Install → Connect → Approve → Ready UX.

Before public release: service-account rules, secure native installation, consent-driven key reset/rotation, revocation fanout, signed binary packaging, audited capability grants, backend hardening and real hardware acceptance.
