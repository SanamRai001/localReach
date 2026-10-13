# R1B: edge identity enrollment spike

**Scope delivered:** isolated Go package for short-lived one-time invitations, locally generated Ed25519 agent identity proof, scoped tenant/site registration, revocation, and a signature-verification primitive.

**Not delivered:** production enrollment HTTP endpoints, user login/admin authorization, secure persistence, TLS agent transport, replay-safe challenge issuance, revocation push, remote network connectivity, installer or UX. The R1A shared-token mock relay is deliberately unchanged. **Do not expose it to the internet.**

## Trust boundary
1. A separately authenticated and authorized workspace admin requests a one-use tenant/site-bound invitation.
2. The edge installation generates an Ed25519 private key locally and protects it with OS key storage (still a design requirement).
3. The agent signs a domain-separated statement containing the invitation token and submits public key + signature.
4. The registry checks TTL, proof and uniqueness; consumes invitation atomically and assigns opaque agent ID.
5. An authenticated transport later verifies fresh server-issued challenge signatures with anti-replay state. Current VerifyChallenge only checks signature/length and **is insufficient alone** for session authentication.
6. Admin revocation must invalidate existing transport sessions and stop command delivery; currently only modeled in memory.

## Engineering decisions
- Use crypto/rand for invitations; no predictable IDs or permanent installation secrets.
- Store only the SHA-256 digest of invitation tokens.
- Reject reused, expired, malformed or already enrolled public keys.
- Keep private keys completely outside the server's registry.
- Avoid automatically taking a device or LAN online upon discovering it.
- Separate user/app identity from agent identity.
- Treat in-memory state as an experiment, not recoverable infrastructure.

## Later production gates
Add persistent transactional one-time redemption, authenticated admin invitation issue, single-use server challenges, key storage on Windows/Linux, TLS verification, transport session binding, revocation and expiry propagation, tenant authorization and security review.

## Developer check (optional until integration acceptance)
```powershell
go test ./...
go test -race ./... # on supported platforms with a C toolchain
```
Expected: package identity tests pass. This is not a WAN proof.
