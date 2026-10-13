# R1C.2: TLS transport boundary spike

## What exists
An independent Go HTTP handler with:
- TLS-only endpoint guard.
- Short-lived single-use Ed25519 agent challenge flow using the R1B/R1C.1 primitives.
- A scoped authenticated heartbeat capability.
- Tests demonstrating a TLS loopback round trip, denied plaintext, blocked replay and revoked-session denial, using a self-signed certificate trusted by the test client only.

This handler is **not wired into the R1A mock relay or a production listener**. The relay remains localhost-only with its original development token. There is no public internet gateway or device control in R1C.2.

## Why this is not internet-ready
- In-memory credentials, sessions and challenges; no durable transactional enrollment, login or tenant authorization at issuance boundary.
- A known agent ID can request challenges; no rate limits, abuse control or trusted authorization at Begin.
- Bearer sessions are protected only in transit by TLS, not bound to a TLS client certificate or exporter; active session theft is not fully mitigated.
- No certificate issuance/trust/rotation, deployment config, revocation fanout, metrics or edge key vault integration.
- Challenge replay rejection is process-local; gateway clustering requires shared atomic state.
- No outbound persistent connection, durable delivery or reconnect handling.
- No signed installer or user-facing UI.

## Security gate before remote listener
1. Define authorized user/app pairing initiation and persistent invitation transactions.
2. Select mTLS or channel-bound PoP session authentication and enforce it for every message.
3. Add rate limits, protocol versioning, explicit tenant/device grants and audit.
4. Build crash-recoverable command semantics before enabling printer effects.
5. Validate the end-to-end flow across separate networks under failure and revocation.

## Verification deferred per project workflow
Run `go test ./...`, `go vet ./...` and later `go test -race ./...`. Connector publication is not evidence that tests pass.
