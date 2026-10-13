# R1G — Authenticated mock broker-to-edge integration

## Scope
A test-only orchestrator connects the existing broker, TLS-authenticated identity heartbeat, and local edge journal. A mock command is accepted via the Go broker package; an agent proves its key possession over an httptest TLS server; the orchestrator claims only commands belonging to the registered tenant/agent and executes only `mock.ping`.

Sequence: authenticated handshake -> broker claim -> edge Submit persisted -> broker Receive -> edge Begin persisted -> mock result -> edge Finish -> broker Complete.

## Expected correctness properties
- No raw device or LAN access; mock operation only.
- Tenant/agent scoping comes from the server-side identity registry.
- Authentication failure/revocation prevents broker claim.
- A duplicate edge command is rejected rather than run again.
- Interrupted edge EXECUTING operations are quarantined by the earlier journal code.
- An acknowledged command is not eligible for silent cloud re-lease.

## Important limitations
This is an **in-process mock path**. It does NOT deliver commands from cloud to LAN over the internet; the orchestrator can call both broker and edge objects directly. It does not implement an outbound persistent socket, control-plane API credentials, replay-safe session channel binding, PostgreSQL transactions, signed installers or browser UX.

If edge Submit succeeds but broker Receive fails, the edge record is queued and requires reconciliation. If the edge finishes but broker Complete fails, the broker may become INDETERMINATE and must NOT trigger another physical effect. The current flow has no automated reconciliation. The broker also has no distributed file lock and append-log corruption recovery. No production hardware access is safe.

## Deferred verification
From the branch checkout, run `go test ./...` and `go vet ./...`. Expected: broker, journal, gateway, identity, session and integration test packages pass. These checks have **not** been run in this publishing environment.

## Next milestone
Build a bounded outbound-only agent channel on top of authenticated TLS, with versioned messages, distinct delivery acknowledgements, reconnection and safe reconciliation. Before public exposure, implement authenticated admin enrollment and tenant grants, agent key protection, session/channel binding and rate limiting. Test across separate networks and CGNAT. R2 remains one-click setup.
