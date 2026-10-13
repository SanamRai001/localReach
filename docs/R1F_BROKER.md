# R1F — Durable mock command broker (isolated spike)

## What exists
- Go standard-library single-process, append-only fsynced command storage.
- Tenant/agent-scoped mock.ping jobs, unique command IDs and bounded disk usage.
- QUEUED -> LEASED -> RECEIVED -> SUCCEEDED / FAILED / INDETERMINATE.
- Cryptographically random lease tokens and short deadlines; stale lease tokens rejected.
- Expired LEASED jobs can be claimed again **only before receipt acknowledgement**.
- RECEIVED jobs that remain unresolved after the deadline become INDETERMINATE on explicit reconciliation. They cannot be automatically re-leased.
- State restores on process restart; corrupted/truncated journal fails closed.
- Tests for scoping, lease expiration and token fencing, duplicate completion and restart reconciliation.

## Execution semantics and open problem
RECEIVED indicates the point after which device execution **may** happen; a crash or lost acknowledgement between cloud and edge can still leave an uncertain outcome. R1D's edge journal provides a local deduplication component, but this new broker is **not yet integrated** with that journal or transport. Physical exactly-once execution is not claimed.

## Significant blockers
The storage layer is single-process / single-writer and has no file lock, schema-versioning, compaction, fault injection, backup/repair workflow, per-tenant quota or multi-node transaction coordination. A partial write can prevent subsequent startup. The current API is a Go package only: NO internet-facing listener or authenticated HTTP endpoints. AuthN/AuthZ must be enforced by a trusted caller; tenant/agent parameters passed to methods are not authentication.

## Proposed next architecture step
Wire the typed mock broker to an outbound agent connection under an authenticated policy boundary, ensuring the edge persists RECEIVED-equivalent intent **before** running any effect. Implement reconciliation, bounded backoff and explicit safety outcomes. Add transactional persistent enrollment and tenant/app grants before remote exposure. Do not turn this into an arbitrary TCP relay.

## Deferred acceptance
```powershell
go test ./...
go vet ./...
```
Extended testing later: crash between claim/receipt, disk full, partial writes, concurrent claims, restart, spoofed tenant, revoked agent and time skew.
