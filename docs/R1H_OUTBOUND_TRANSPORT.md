# R1H — Outbound HTTPS mock transport

## Implemented
New `internal/transport` exposes a mock-only TLS handler and agent poller. The agent initiates HTTPS requests to the gateway and proves its enrolled Ed25519 identity using the R1C single-use challenge/session mechanism. The gateway resolves the agent tenant from its own identity registry; the request cannot choose a different tenant. All control messages are authenticated against the active session and revocation state. `mock.ping` is the only capability.

Sequence: agent HTTPS handshake -> POST claim -> edge durable Submit -> POST receive acknowledgment -> edge durable Begin -> mock result -> durable Finish -> POST broker completion.

Automated test scenarios are authored for successful outbound delivery, cross-tenant isolation, revoked agent denial, rejection of plaintext, and duplicate edge command rejection.

## What is not yet proven
Tests have **not been executed**. The current harness uses httptest.NewTLSServer, not two independently deployed computers/networks. It is HTTPS polling, **not** a persistent WebSocket nor production agent service. There is no internet-facing listener, CGNAT test, automatic reconnect supervisor, certificate provisioning, OS key store, user-admin enrollment, command retry reconciliation or signed installer. The control plane still uses in-memory identity and session stores plus a single-writer file broker.

## Safety and correctness caveats
- This code is mock only: never expose real devices or raw TCP from this gateway.
- Calling the handler with TLS alone does not replace a deployment identity trust model; session bearer tokens are not yet channel-bound.
- If journal Submit succeeds but Receive fails, the broker may re-lease after expiry; the local journal rejects re-execution but the outcome requires reconciliation.
- If the edge executes and Complete fails, broker and edge can diverge. Do not automatically retry physical effects.
- Lease deadlines are capped but there is no heartbeat-based extension or retry scheduling.
- Agent identity is tested with an in-memory generated private key; production requires secure OS storage and revocation propagation.
- No bounded backoff and no recovery after process crash in the agent runtime; this phase is a protocol integration experiment.

## Deferred verification
```powershell
go test ./...
go vet ./...
```
Expected: all Go packages build and all mock unit/integration tests pass. These commands are not asserted to pass until run.

## Next
R1I: reconciliation and agent runner lifecycle: backoff, session renewal, crash-safe reconciliation, reproducible local multi-process harness, and consolidated acceptance. Keep production networking blocked until admin authorization, durable registry, channel-bound credentials, rate limiting and external security review.
