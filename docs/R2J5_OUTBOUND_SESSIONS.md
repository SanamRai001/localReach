# R2J.5 — outbound authenticated agent connection (no device commands)

## Implemented

A manually runnable LocalReach agent now keeps a **genuine, outbound HTTPS response stream** open to the operator-controlled pairing gateway. The stream authenticates with a *fresh, 30-second, single-use Ed25519 resume challenge* signed by the existing OS-protected native agent key. The server consumes that proof in the **same HTTPS request** that attempts to reserve a live connection lease. It does not grant printer, attendance, command, network proxy, or other device access.

On success the gateway emits a bounded newline-delimited JSON `connected` frame and repeated `heartbeat` frames. Each heartbeat renews the 15-second database connection lease **only if the original session owner still matches and the agent, pairing, and organization remain active**. Revoking the pairing or blocking the organization prevents renewal; the gateway terminates the response stream. The client reports connection loss, not success. Server and client keep the same session until interrupted; both have bounded write/read stall guards and a cancellation path.

### Backend and data model

- Migration `065_agent_connections.sql`: single active lease per organization/agent, randomized per-session IDs, 15-second expiry, last heartbeat, scoped OPEN/CLOSE audit.
- `pgpairing.OpenConnection`: claims a live lease for an enrolled, non-revoked agent only. A second live connection cannot take over. An expired lease can be reclaimed by a newer process.
- `pgpairing.RenewConnection`: checks lease ownership and current organization + pairing + agent status on **every renewal**. Revocation closes at the next heartbeat (nominally 4 seconds in the operator server). A crash leaves a stale lease for at most 15 seconds before another instance can reclaim it.
- `pgpairing.CloseConnection`: release only by the matching session ID. Old owners cannot delete newer sessions. `ConnectionOnline` is a read-only lease-based *liveness hint*, **never a capability grant or a substitute for direct transport authorization**.
- `pairapi.Handler` `POST /v1/agent/session`: bounded request body, TLS/native-origin restrictions and existing PostgreSQL admission. Requires one-use Ed25519 identity proof, claims the lease, returns a stream of only `connected`, `heartbeat` and optional `closed` frames. Frames carry agent ID and `capabilities=NONE`; no command payloads, dynamic proxy destinations, shell instructions or LAN requests are supported.
- `agentremote.Client.StreamSession`: client-initiated, certificate-validated HTTPS stream with no redirects, response-frame size limit, inactivity watchdog, strict agent ID/type/capability checks, and immediate local fail-closed notification on EOF/cancel/error.
- `agentservice.LiveMonitor`: instead of pretending periodic `VerifyIdentity` means ONLINE, it reports ONLINE only after an authenticated `connected` or `heartbeat` frame on an active stream, reports OFFLINE when that stream closes, and returns OFFLINE for a heartbeat older than 12 seconds. Failed reconnects use bounded exponential backoff.
- `cmd/localreach-agent serve` now runs the live monitor; use `-retry` to set minimum reconnection delay. Local read-only status at `http://127.0.0.1:18788` and its setup preview can display ONLINE when the actual authenticated outbound stream is active. Both always report `devices=NOT_DISCOVERED`.
- `cmd/localreach-control` configures the streaming handler and leases. Its **localhost default and opt-in restricted source-allowlisted TLS staging controls remain unchanged**. Staging requires separate operator/network approval and appropriate DNS, certs, firewall and PostgreSQL trust. The agent needs no inbound listening port for cloud communication.

## Test acceptance

Disposable PostgreSQL and real TLS integration tests cover an enrolled agent's stream, receipt of genuine heartbeat frames, exclusive ownership against a second connection, lease renewal from another database connection, crash/stale expiry, session reassignment, old-owner release protection, separately signed administrator revocation cutting an active stream, and denial of a revoked reconnect.

Go unit tests cover the local LiveMonitor's accurate ONLINE/OFFLINE transitions, loss of network, stale heartbeat and cancellation. Linux Go unit/vet/race, Windows DPAPI/build, macOS Keychain/build and the existing PostgreSQL pairing/authorization/invitation tests remain CI gates.

## Important limits

This phase implements an **authenticated read-only presence connection**, not a general-purpose tunnel, and not printer/attendance integration. The server does not send or accept *any* device commands. App-layer permissions remain `NONE`. Authenticated session online status must not be used to authorize a printer or attendance action. Browser JavaScript never has private signing keys or cloud database credentials.

The gateway is still a **prototype**: no production cloud deployment, secure human SSO onboarding, broad-network abuse resilience, certificate automation, monitored multi-region high availability, graceful load balancing of streaming connections, signed installers, fully approved key rotation, or actual WAN/CGNAT device acceptance. Failover may require waiting up to 15 seconds for a stale lease to expire. Concurrent streams consume staging concurrency slots (16 total), which is only appropriate for a tiny pilot; this is not a scalable production pool. Presence queries may briefly report a live connection until its lease expires after abrupt process failure.

No user-facing release, physical hardware operations, arbitrary tunneling or deployment has occurred.

## Next steps

1. Validate a deliberate **two-network staging pilot** with valid TLS, firewall allowlisting, an operator-controlled database and administrator identity. Measure dropouts, reclaims, blocked/revoked reconnects and process restart behavior without permitting any device commands.
2. Add more reliable session liveness/revocation fanout, safe proxy/LB semantics, admission retention cleanup, operator diagnostics, and full certificate lifecycle management.
3. Begin **R2K** with individually approved device capability grants and read-only local discovery; do not attach device-write adapters until those grants, tests, and operator acceptance are complete.
