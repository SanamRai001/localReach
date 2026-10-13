# R1C.1 — replay-resistant agent session primitives

**Implemented:** single-use, 30-second signed challenge; Ed25519 possession proof; bounded in-memory pending/session maps; opaque 5-minute session tokens stored hashed; agent-scoped authorizations with revocation check on each request; expiry and concurrent replay tests.

**Not implemented:** network session upgrade, authenticated TLS, agent certificate pinning, persistent transactional challenges, key protection, admin account authentication, horizontal scaling, durable job queue, UI, installer. No cross-network agent access is enabled. Do not deploy the R1A relay publicly.

## Threat boundaries
- `Begin` / `Complete` must be called ONLY via an authenticated TLS deployment; plaintext remote transport leaks tokens.
- The current Begin route checks that an agent exists, but callers must also rate-limit requests and prove appropriate authorization before allowing anonymous enrollment or session initiation to be abused.
- A random nonce is consumed regardless of proof success, to avoid brute-force attempts.
- Session tokens are bearer material: bind them to mutually authenticated TLS client identities or channel context before any real deployment, and keep TTL short.
- `Authorize` must be enforced for every message; the in-memory map and challenge store cannot be shared safely between multiple gateway instances.
- Expired records need periodic `Sweep` to bound memory; a persistent store must use transactional single-use redemption and expiry.
- Replay resistance only applies within a single process; a restart loses all sessions, intentionally denying old tokens.

## Review gate for R1C.2
Design secure transport interface and real server-issued identity challenge with authenticated TLS, bootstrapped admin-authorized enrollment, persist revocation and audit, decide connection ownership, and demonstrate cross-network mock command under a separate restricted test deployment. Avoid introducing actual hardware before command recovery semantics are safe.

## Suggested eventual tests
`go test ./...`, `go test -race ./...` (supported C compiler required); failover, session fixation, replay races, revocation during active command, expired token, TLS downgrade, restart and cross-tenant authorization.
