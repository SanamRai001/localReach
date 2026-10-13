# R1E — integrated mock agent execution test

**Implemented:** a test-only, TLS-authenticated control handshake followed by a scoped heartbeat, then a local `mock.ping` operation persisted in the agent-side journal. The integration test checks successful result, duplicate suppression, interrupted-effect quarantine after journal restart, revoked identity rejection, plaintext refusal and wrong private key denial.

## Important boundary
This is a **local integration proof**, not the promised cloud-to-LAN bridge. The operation is initiated directly by the test client, not accepted/delivered through an internet command broker. The transport currently supports session control/heartbeat only. Do not claim remotely controlled devices, automatic discovery, one-click install, CGNAT traversal or production-ready security.

## Current safety model
- TLS provided by a test-only httptest server and client trusted specifically for that certificate.
- Agent key generated in memory for testing.
- Uses existing in-memory identity and session registries.
- Local single-writer journal; effects are limited to `mock.ping`.
- Local idempotency ID prevents duplicate execution.
- No publicly listening server is started.

## Acceptance gate deferred
```powershell
go test ./...
go vet ./...
```
Expected: all Go packages build; unit/integration tests pass. Tests have not been executed by the GitHub publishing connector.

## What remains before a secure real-world bridge
1. Production authenticated administrator enrollment and persistent tenant/device policy.
2. TLS-bound agent identity, per-message authorization and replay control, gateway rate limits.
3. Cloud durable dispatch with bounded leases, separate delivery and execution acknowledgments.
4. Agent-held outbound channel, reconnect, actual network failure scenarios.
5. Secure installer, supported device discovery, polished onboarding and error recovery.
6. Independent risk review before exposing any listener to the internet.
